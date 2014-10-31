/*
 * Copyright (C) 2009 Sebastian Krahmer.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Sebastian Krahmer.
 * 4. The name Sebastian Krahmer may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <cstdio>
#include <iostream>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <signal.h>

extern "C" {
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}

#include "net.h"
#include "config.h"
#include "misc.h"
#include "global.h"

using namespace std;

#ifdef USE_CCIPHERS
string ciphers = USE_CCIPHERS;
#else
string ciphers = "!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:!ADH:!3DES:AES256:AESGCM:SHA256:SHA384:@STRENGTH";
#endif


class client_session {

	int sock_fd, peer_fd;
	Socket *sock;

	static const size_t const_message_size;
	string err;
	SSL_CTX *ssl_ctx;
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *ssl_method;
#else
	SSL_METHOD *ssl_method;
#endif
	SSL *ssl;
	EVP_PKEY *pubkey, *privkey;
	struct termios tattr, old_tattr;

	uint16_t my_major, my_minor;

protected:

	int handle_command(const string &, char *, unsigned short);

	int handle_data(const string &, char *, unsigned short);

	int send_window_size();

	int check_server_key();

	int authenticate();

public:

	client_session();

	~client_session();

	int setup();

	int handle();

	const char *why() { return err.c_str(); };

};


const size_t client_session::const_message_size = 1024;


client_session::client_session() :
	sock_fd(-1), peer_fd(-1), sock(NULL), err(""),
	ssl_ctx(NULL), ssl_method(NULL), ssl(NULL),
	pubkey(NULL), privkey(NULL), my_major(1), my_minor(2)
{

}

client_session::~client_session()
{
	if (ssl) {
		SSL_shutdown(ssl);
		SSL_free(ssl);
	}

	/* SSL_free() will also free SSL Ctx
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	*/
	delete sock;
	close(peer_fd);
	tcsetattr(0, TCSANOW, &old_tattr);
}


int client_session::setup()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ssl_method = SSLv23_client_method();

	if (tcgetattr(0, &tattr) < 0) {
		err = "client_session::setup::tcgetattr:";
		err += strerror(errno);
		return -1;
	}
	old_tattr = tattr;

	if (!ssl_method) {
		err = "client_session::setup::SSLv23_client_method:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	ssl_ctx = SSL_CTX_new(ssl_method);
	if (!ssl_ctx) {
		err = "client_session::setup::SSL_CTX_new:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	long op = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_SINGLE_DH_USE|SSL_OP_NO_TICKET;

#ifdef SSL_OP_NO_COMPRESSION
	op |= SSL_OP_NO_COMPRESSION;
#endif

	if ((SSL_CTX_set_options(ssl_ctx, op) & op) != op) {
		err = "client_session::setup::SSL_CTX_set_options():";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if (SSL_CTX_set_cipher_list(ssl_ctx, ciphers.c_str()) != 1) {
		err = "client_sessions::setup::SSL_CTX_set_cipher_list:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if (!(ssl = SSL_new(ssl_ctx))) {
		err = "client_session::setup::SSL_new:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	FILE *fstream = fopen(config::user_keys.c_str(), "r");
	if (!fstream) {
		err = "client_session::authenticate::fopen:";
		err += strerror(errno);
		return -1;
	}

	privkey = PEM_read_PrivateKey(fstream, NULL, NULL, NULL);
	if (!privkey) {
		err = "client_session::setup::PEM_read_PrivateKey:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	fclose(fstream);

	if (config::v6)
		sock = new (nothrow) Socket(PF_INET6);
	else
		sock = new (nothrow) Socket(PF_INET);

	if (!sock) {
		err = "client_session::setup::Socket:";
		return -1;
	}

	if (config::host.length() == 0) {
		if ((sock_fd = sock->blisten(strtoul(config::port.c_str(), NULL, 10))) < 0) {
			err = "client_session::setup::";
			err += sock->why();
			return -1;
		}
		if ((peer_fd = accept(sock_fd, NULL, 0)) < 0) {
			err = "client_session::setup::accept:";
			err += strerror(errno);
			return -1;
		}
		close(sock_fd);
	} else {
		if (config::local_port.length() > 0)
			sock->blisten(strtoul(config::local_port.c_str(), NULL, 10), 0);
		if ((peer_fd = sock->connect(config::host, config::port)) < 0) {
			err = "client_session::setup::connect:";
			err += sock->why();
			return -1;
		}
	}


	//cfmakeraw(&tattr);
	tattr.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
	                 | INLCR | IGNCR | ICRNL | IXON);
	tattr.c_oflag &= ~OPOST;
	tattr.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	tattr.c_cflag &= ~(CSIZE | PARENB);
	tattr.c_cflag |= CS8;

	tattr.c_cc[VMIN] = 1;
	tattr.c_cc[VTIME] = 0;
	tattr.c_oflag |= OPOST;	// needed for \r\n on stdout

	return 0;
}


int client_session::handle_data(const string &tag, char *buf, unsigned short blen)
{
	return write(1, buf, blen);
}

int client_session::handle_command(const string &tag, char *buf, unsigned short blen)
{
	return 0;
}


int client_session::send_window_size()
{
	char wsbuf[64], sbuf[const_message_size];

	global::window_size_changed = 0;
	struct winsize ws;
	if (ioctl(0, TIOCGWINSZ, &ws) < 0) {
		err = "client_session::send_window_size::ioctl:";
		err += strerror(errno);
		return -1;
	}
	snprintf(wsbuf, sizeof(wsbuf), "%hu:%hu:%hu:%hu", ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
	unsigned short l = (unsigned short)strlen(wsbuf);
	snprintf(sbuf, sizeof(sbuf), "C:window-size:%hu:%s", l, wsbuf);
	rewrite: ssize_t n = SSL_write(ssl, sbuf, const_message_size);
	switch (SSL_get_error(ssl, n)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_ZERO_RETURN:
			return -1;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			goto rewrite;
		default:
			err = "client_session::send_windowsize:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
	}
	return 0;
}


// == 1, if everything is OK
int client_session::check_server_key()
{
	if (!ssl)
		return -1;

	FILE *fstream = NULL;
	string keyfile = "";

	// take as directory if ends with "/"
	if (config::server_keys.length() >= 1 &&
	    config::server_keys.find("/", config::server_keys.length() - 1) != string::npos) {
		keyfile = config::server_keys;
		keyfile += "HK_";
		keyfile += config::host;
		keyfile += ":";
		keyfile += config::port;
	} else
		keyfile = config::server_keys;

	X509 *cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		err = "client_session::check_server_key: FAILED! No peer certificate!";
		return -1;
	}
	pubkey = X509_get_pubkey(cert);
	X509_free(cert);
	if (!pubkey) {
		err = "client_session::check_server_key: FAILED! Peer offered invalid pubkey!";
		return -1;
	}

	if (config::verbose) {
		printf("crash:{\n");
		PEM_write_PUBKEY(stdout, pubkey);
		printf("crash:}\n");
	}

	err = "client_session::check_server_key: FAILED! Unable to open/parse known-hosts key-file!";
	if ((fstream = fopen(keyfile.c_str(), "r")) == NULL) {
		EVP_PKEY_free(pubkey);
		return -1;
	}

	EVP_PKEY *pkey_file = NULL;
	if ((pkey_file = PEM_read_PUBKEY(fstream, NULL, NULL, NULL)) == NULL) {
		EVP_PKEY_free(pubkey);
		fclose(fstream);
		return -1;
	}
	fclose(fstream);

	err = "client_session::check_server_key: FAILED! Unknown pubkey!";

	int r = EVP_PKEY_cmp(pubkey, pkey_file);

	// we need pubkey later for authentication
	EVP_PKEY_free(pkey_file);
	return r;
}


int client_session::authenticate()
{
	char rbuf[const_message_size];

	ssize_t r = 0;
	repeek: r = SSL_peek(ssl, rbuf, sizeof(rbuf));
	switch (SSL_get_error(ssl, r)) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		goto repeek;
	default:
		err = "client_session::authenticate::SSL_peek:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if ((size_t)r != const_message_size) {
		usleep(40);
		goto  repeek;
	}
	SSL_read(ssl, rbuf, r);

	err = "client_session::authenticate::message format error";
	char challenge[64];
	unsigned short clen = 0;
	if (sscanf(rbuf, "A:sign:%hu:", &clen) != 1)
		return -1;
	if (clen > sizeof(challenge))
		return -1;
	char *ptr = strchr(rbuf + 7, ':') + 1;
	if (!ptr || r - (ptr - rbuf) < (ssize_t)clen)
		return -1;
	memcpy(challenge, ptr, clen);

	err = "client_session::authenticate::unable to complete authentication";
	if (EVP_PKEY_size(privkey) < 32 || EVP_PKEY_size(privkey) > (int)const_message_size)
		return -1;

	unsigned char resp[const_message_size];
	EVP_MD_CTX md_ctx;
	const EVP_MD *sha512 = EVP_sha512();

	EVP_MD_CTX_init(&md_ctx);
	if (EVP_SignInit_ex(&md_ctx, sha512, NULL) != 1)
		return -1;
	// 'challenge' that was sent by server
	if (EVP_SignUpdate(&md_ctx, challenge, clen) != 1)
		return -1;

	int pubkeylen = i2d_PublicKey(pubkey, NULL);
	if (pubkeylen <= 0 || pubkeylen >= 32000)
		return -1;
	unsigned char *b1 = NULL, *b2 = NULL;
	if ((b1 = (unsigned char *)malloc(pubkeylen)) == NULL)
		return -1;
	b2 = b1;
	if (i2d_PublicKey(pubkey, &b2) != pubkeylen) {
		free(b1);
		return -1;
	}
	// DER encoding of server pubkey
	if (EVP_SignUpdate(&md_ctx, b1, pubkeylen) != 1) {
		free(b1);
		return -1;
	}
	free(b1);

	unsigned int resplen = 0;
	if (EVP_SignFinal(&md_ctx, resp, &resplen, privkey) != 1)
		return -1;

	char sbuf[const_message_size];
	snprintf(sbuf, sizeof(sbuf), "A:crash-%hu.%04hu:%32s:%hu:%s:token:%hu:",
	         my_major, my_minor, config::user.c_str(),
	         (unsigned short)config::cmd.length(), config::cmd.c_str(),
	         (unsigned short)resplen);
	if (resplen > sizeof(sbuf) - strlen(sbuf))
		return -1;
	memcpy(sbuf + strlen(sbuf), resp, resplen);

	rewrite: ssize_t n = SSL_write(ssl, sbuf, const_message_size);
	switch (SSL_get_error(ssl, n)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			goto rewrite;
		default:
			err = "client_session::authenticate:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
	}

	return 0;
}


int client_session::handle()
{
	char rbanner[1024];

	FILE *fstream = fdopen(peer_fd, "r+");
	if (!fstream) {
		err = "client_session::handle::fdopen:";
		err += strerror(errno);
		return -1;
	}

	setbuffer(fstream, NULL, 0);
	SSL_set_fd(ssl, peer_fd);

	memset(rbanner, 0, sizeof(rbanner));
	fgets(rbanner, sizeof(rbanner) - 1, fstream);

	uint16_t major = 0, minor = 0;
	if (sscanf(rbanner, "1000 crashd-%hu.%hu OK\r\n", &major, &minor) != 2) {
		err = "client_session::handle:: Invalid remote banner string.";
		return -1;
	}

	if (config::verbose) {
		if ((major != my_major || minor != my_minor))
			printf("crash: Different versions. Authentication may fail.\n");
		else
			printf("crash: Major/Minor versions match (%hu/%hu)\n", major, minor);
	}

	if (SSL_connect(ssl) <= 0) {
		err = "client_session::handle::SSL_connect:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if (config::verbose) {
		char ssl_desc[256];
		memset(ssl_desc, 0, sizeof(ssl_desc));
		SSL_CIPHER_description(SSL_get_current_cipher(ssl), ssl_desc, sizeof(ssl_desc) - 1);
		printf("crash: Using %s", ssl_desc);
	}

	if (check_server_key() != 1) {
		return -1;
	}

	if (authenticate() < 0)
		return -1;
	if (send_window_size() < 0) {
		return -1;
	}

	// Now, where passphrase has been typed etc;
	// setup terminal into raw mode
	if (tcsetattr(0, TCSANOW, &tattr) < 0) {
		err = "client_session::handle::tcsetattr:";
		err += strerror(errno);
		return -1;
	}
	char buf[const_message_size/2], sbuf[const_message_size],
	     rbuf[const_message_size + 1], tag[64];
	fd_set rset;
	ssize_t r = 0;
	for (;;) {
		FD_ZERO(&rset);
		FD_SET(peer_fd, &rset);
		FD_SET(0, &rset);
		memset(buf, 0, sizeof(buf)); memset(sbuf, 0, sizeof(sbuf));
		memset(rbuf, 0, sizeof(rbuf)); memset(tag, 0, sizeof(tag));
		if (select(peer_fd + 1, &rset, NULL, NULL, NULL) < 0) {
			if (errno == EINTR) {
				if (global::window_size_changed)
					send_window_size();
				continue;
			}
			err = "client_session::handle::";
			err += strerror(errno);
			return -1;
		}
		if (FD_ISSET(0, &rset)) {
			if ((r = read(0, buf, sizeof(buf))) <= 0) {
				if (errno == EINTR)
					continue;
				err = "client_session::handle::";
				err += strerror(errno);
				break;
			}

			sprintf(sbuf, "D:channel0:%hu:", (unsigned short)r);
			size_t slen = strlen(sbuf);
			memcpy(sbuf + slen, buf, r);
			rewrite: ssize_t n = SSL_write(ssl, sbuf, const_message_size);
			switch (SSL_get_error(ssl, n)) {
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_ZERO_RETURN:
					return 0;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
					goto rewrite;
				default:
					err = "client_session::handle::SSL_write:";
					err += ERR_error_string(ERR_get_error(), NULL);
					return -1;
			}
		} else if (FD_ISSET(peer_fd, &rset)) {
			repeek: r = SSL_peek(ssl, rbuf, const_message_size);
			switch (SSL_get_error(ssl, r)) {
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_ZERO_RETURN:
				return 0;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				goto repeek;
			default:
				err = "client_session::handle::SSL_peek:";
				err += ERR_error_string(ERR_get_error(), NULL);
				return -1;
			}

			if ((size_t)r != const_message_size) {
				usleep(40);
				goto  repeek;
			}

			SSL_read(ssl, rbuf, r); // actually, take it off the queue
			// must be either command or data
			if (rbuf[0] != 'C' && rbuf[0] != 'D') {
				break;
			}

			unsigned short len = 0;
			char c = 0;
			if (sscanf(rbuf, "%c:%32[^:]:%hu:", &c, tag, &len) != 3) {
				break;
			}
			if (len >= sizeof(sbuf)) {
				break;
			}
			// find last ':'
			char *ptr = strchr(rbuf + 2, ':') + 1;
			if (!ptr)
				break;
			ptr = strchr(ptr, ':') + 1;
			if (!ptr || r - (ptr - rbuf) < (ssize_t)len) {
				break;
			}
			memcpy(sbuf, ptr, len);
			if (c == 'D')
				handle_data(tag, sbuf, len);
			else if (c == 'C')
				handle_command(tag, sbuf, len);

		}
	}

	return 0;
}


void help(const char *p)
{
	printf("\nUsage:\t%s [-6] [-v] [-H host] [-p port] [-P local port] [-i auth keyfile]\n"
	       "\t\t [-K server key/s] [-c command] <-l user>\n\n"
	       "\t\t -6 -- use IPv6 rather than IPv4\n"
	       "\t\t -v -- be verbose\n"
	       "\t\t -H -- host/IP to connect to; if omitted it uses passive connect (default)\n"
	       "\t\t -p -- port to connect/listen to; default is %s\n"
	       "\t\t -P -- local port used in active connects (default is no bind)\n"
	       "\t\t -i -- private key used for authentication\n"
	       "\t\t -K -- subdir of known host keys relative to \".\" if it ends with '/';\n"
	       "\t\t       absolute path of known-host file otherwise; default is %s\n"
	       "\t\t -c -- command to execute on remote host (default is %s)\n"
	       "\t\t -l -- user to login as (no default!)\n\n",
	       p, config::port.c_str(), config::server_keys.c_str(), config::cmd.c_str());
}


int main(int argc, char **argv)
{

	struct sigaction sa;

	int c = 0;
	while ((c = getopt(argc, argv, "6vhH:K:p:P:l:i:c:")) != -1) {
		switch (c) {
		case '6':
			config::v6 = 1;
			break;
		case 'H':
			config::host = optarg;
			break;
		case 'p':
			config::port = optarg;
			break;
		case 'P':
			config::local_port = optarg;
			break;
		case 'K':
			config::server_keys = optarg;
			break;
		case 'l':
			config::user = optarg;
			break;
		case 'i':
			config::user_keys = optarg;
			break;
		case 'c':
			config::cmd = optarg;
			break;
		case 'v':
			config::verbose = 1;
			break;
		default:
			help(*argv);
			return 0;
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_winch;
	sigaction(SIGWINCH, &sa, NULL);

	if (config::user.length() == 0) {
		help(*argv);
		return 1;
	}

	if (config::verbose)
		printf("crash: starting crypted administration shell\ncrash: connecting to %s:%s ...\n",
		       config::host.c_str(), config::port.c_str());

	client_session csess;
	if (csess.setup() < 0) {
		fprintf(stderr, "crash: %s\n", csess.why());
		return 1;
	}

	if (csess.handle() < 0) {
		fprintf(stderr, "crash: %s\n", csess.why());
		return 1;
	}

	if (config::verbose)
		printf("crash: closing connection.\n");
	return 0;
}

