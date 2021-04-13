/*
 * Copyright (C) 2009-2021 Sebastian Krahmer.
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
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>
#include <errno.h>
#include <poll.h>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <termios.h>
#include <signal.h>

extern "C" {
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}

#include "net.h"
#include "config.h"
#include "csession.h"
#include "misc.h"
#include "global.h"
#include "deleters.h"
#include "missing.h"


using namespace std;

namespace crash {

#ifdef USE_CCIPHERS
string ciphers = USE_CCIPHERS;
#else
string ciphers = "!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:!ADH:!3DES:AES256:AESGCM:SHA256:SHA384:@STRENGTH";
#endif


client_session::~client_session()
{
	if (d_ssl) {
		SSL_shutdown(d_ssl);
		SSL_free(d_ssl);
	}
	if (d_pubkey)
		EVP_PKEY_free(d_pubkey);

	/* SSL_free() will also free SSL Ctx
	if (d_ssl_ctx)
		SSL_CTX_free(d_ssl_ctx);
	*/
	delete d_sock;
	close(d_peer_fd);
	if (d_has_tty)
		tcsetattr(0, TCSANOW, &d_old_tattr);
}


int client_session::setup()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	d_ssl_method = SSLv23_client_method();

	if (tcgetattr(0, &d_tattr) >= 0) {
		d_old_tattr = d_tattr;
		d_has_tty = 1;
	}

	if (!d_ssl_method) {
		d_err = "client_session::setup::TLS_client_method:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}
	d_ssl_ctx = SSL_CTX_new(d_ssl_method);
	if (!d_ssl_ctx) {
		d_err = "client_session::setup::SSL_CTX_new:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	long op = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TLSv1|SSL_OP_NO_TLSv1_1;
	op |= (SSL_OP_SINGLE_DH_USE|SSL_OP_SINGLE_ECDH_USE|SSL_OP_NO_TICKET);

#ifdef SSL_OP_NO_COMPRESSION
	op |= SSL_OP_NO_COMPRESSION;
#endif

	if ((unsigned long)(SSL_CTX_set_options(d_ssl_ctx, op) & op) != (unsigned long)op) {
		d_err = "client_session::setup::SSL_CTX_set_options():";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if (SSL_CTX_set_cipher_list(d_ssl_ctx, ciphers.c_str()) != 1) {
		d_err = "client_sessions::setup::SSL_CTX_set_cipher_list:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if (!(d_ssl = SSL_new(d_ssl_ctx))) {
		d_err = "client_session::setup::SSL_new:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	FILE *fstream = fopen(config::user_keys.c_str(), "r");
	if (!fstream) {
		d_err = "client_session::authenticate::fopen:";
		d_err += strerror(errno);
		return -1;
	}

	d_privkey = PEM_read_PrivateKey(fstream, nullptr, nullptr, nullptr);
	if (!d_privkey) {
		d_err = "client_session::setup::PEM_read_PrivateKey:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}
	fclose(fstream);

	if (config::v6)
		d_sock = new (nothrow) Socket(PF_INET6);
	else
		d_sock = new (nothrow) Socket(PF_INET);

	if (!d_sock) {
		d_err = "client_session::setup::Socket:";
		return -1;
	}

	if (config::host.length() == 0) {
		if ((d_sock_fd = d_sock->blisten(strtoul(config::port.c_str(), nullptr, 10))) < 0) {
			d_err = "client_session::setup::";
			d_err += d_sock->why();
			return -1;
		}
		if ((d_peer_fd = accept(d_sock_fd, nullptr, 0)) < 0) {
			d_err = "client_session::setup::accept:";
			d_err += strerror(errno);
			return -1;
		}
		close(d_sock_fd);
	} else {
		if (config::local_port.length() > 0)
			d_sock->blisten(strtoul(config::local_port.c_str(), nullptr, 10), 0);
		if ((d_peer_fd = d_sock->connect(config::host, config::port)) < 0) {
			d_err = "client_session::setup::connect:";
			d_err += d_sock->why();
			return -1;
		}
	}


	//cfmakeraw(&tattr);
	d_tattr.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
	                 | INLCR | IGNCR | ICRNL | IXON);
	d_tattr.c_oflag &= ~OPOST;
	d_tattr.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	d_tattr.c_cflag &= ~(CSIZE | PARENB);
	d_tattr.c_cflag |= CS8;

	d_tattr.c_cc[VMIN] = 1;
	d_tattr.c_cc[VTIME] = 0;
	d_tattr.c_oflag |= OPOST;	// needed for \r\n on stdout

	return 0;
}


int client_session::send_window_size()
{
	global::window_size_changed = 0;

	if (!d_has_tty)
		return 0;

	char wsbuf[64] = {0};
	struct winsize ws;
	if (ioctl(0, TIOCGWINSZ, &ws) < 0) {
		d_err = "client_session::send_window_size::ioctl:";
		d_err += strerror(errno);
		return -1;
	}
	snprintf(wsbuf, sizeof(wsbuf), "%hu:%hu:%hu:%hu", ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
	string cmd = slen(6 + strlen(wsbuf));
	cmd += ":C:WS:";
	cmd += wsbuf;

	d_fd2state[d_peer_fd].obuf += cmd;
	d_pfds[d_peer_fd].events |= POLLOUT;

	return 0;
}


// == 1, if everything is OK
int client_session::check_server_key()
{
	if (!d_ssl)
		return -1;

	X509 *cert = SSL_get_peer_certificate(d_ssl);
	if (!cert) {
		d_err = "client_session::check_server_key: FAILED! No peer certificate!";
		return -1;
	}
	d_pubkey = X509_get_pubkey(cert);
	X509_free(cert);
	if (!d_pubkey) {
		d_err = "client_session::check_server_key: FAILED! Peer offered invalid pubkey!";
		return -1;
	}

	if (config::no_hk_check) {
		if (config::verbose)
			printf("crashc: Hostkey checking disabled!\n");
		return 1;
	}

	FILE *fstream = nullptr;
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

	if (config::verbose) {
		printf("crashc:{\n");
		PEM_write_PUBKEY(stdout, d_pubkey);
		printf("crashc:}\n");
	}

	d_err = "client_session::check_server_key: FAILED! Unable to open/parse known-hosts key-file!";
	if ((fstream = fopen(keyfile.c_str(), "r")) == nullptr)
		return -1;

	EVP_PKEY *pkey_file = nullptr;
	if ((pkey_file = PEM_read_PUBKEY(fstream, nullptr, nullptr, nullptr)) == nullptr) {
		fclose(fstream);
		return -1;
	}
	fclose(fstream);

	d_err = "client_session::check_server_key: FAILED! Unknown pubkey!";

	int r = EVP_PKEY_cmp(d_pubkey, pkey_file);

	// we need d_pubkey later for authentication
	EVP_PKEY_free(pkey_file);
	return r;
}


int client_session::authenticate()
{
	char rbuf[MSG_BSIZE + 1] = {0};

	reread: ssize_t r = SSL_read(d_ssl, rbuf, sizeof(rbuf));
	switch (SSL_get_error(d_ssl, r)) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		goto reread;
	default:
		d_err = "client_session::authenticate::SSL_read:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	d_err = "client_session::authenticate::message format error";
	char challenge[64] = {0};
	unsigned short clen = 0;
	if (sscanf(rbuf, "A:sign1:%hu:", &clen) != 1)
		return -1;
	if (clen > sizeof(challenge))
		return -1;
	char *ptr = strchr(rbuf + 8, ':');
	if (!ptr++)
		return -1;
	if (r - (ptr - rbuf) < (ssize_t)clen)
		return -1;
	memcpy(challenge, ptr, clen);

	d_err = "client_session::authenticate::unable to complete authentication";
	if (EVP_PKEY_size(d_privkey) < 32 || EVP_PKEY_size(d_privkey) > MSG_BSIZE)
		return -1;

	unsigned char resp[MSG_BSIZE] = {0};
	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
	const EVP_MD *sha512 = EVP_sha512();

	if (!sha512 || !md_ctx.get())
		return -1;

	if (EVP_SignInit_ex(md_ctx.get(), sha512, nullptr) != 1)
		return -1;
	// server banner
	if (EVP_SignUpdate(md_ctx.get(), d_sbanner.c_str(), d_sbanner.size()) != 1)
		return -1;
	// 'challenge' that was sent by server
	if (EVP_SignUpdate(md_ctx.get(), challenge, clen) != 1)
		return -1;

	int pubkeylen = i2d_PublicKey(d_pubkey, nullptr);
	if (pubkeylen <= 0 || pubkeylen >= 32000)
		return -1;
	unique_ptr<unsigned char[]> b1(new (nothrow) unsigned char[pubkeylen]);
	unsigned char *b2 = nullptr;
	if (!b1.get())
		return -1;
	// The b2/b1 foo looks strange but is correct. Check the i2d_X509 man-page on
	// how ppout is treated for i2d_TYPE().
	b2 = b1.get();
	if (i2d_PublicKey(d_pubkey, &b2) != pubkeylen)
		return -1;

	// DER encoding of server d_pubkey
	if (EVP_SignUpdate(md_ctx.get(), b1.get(), pubkeylen) != 1)
		return -1;
	b1.reset(nullptr);

	unsigned int resplen = 0;
	if (EVP_SignFinal(md_ctx.get(), resp, &resplen, d_privkey) != 1)
		return -1;

	char sbuf[MSG_BSIZE] = {0};
	snprintf(sbuf, sizeof(sbuf), "A:sign1:crash-%hu.%04hu:%32s:%hu:%s:token:%hu:",
	         d_major, d_minor, config::user.c_str(),
	         (unsigned short)config::cmd.length(), config::cmd.c_str(),
	         (unsigned short)resplen);
	if (resplen > sizeof(sbuf) - strlen(sbuf))
		return -1;
	memcpy(sbuf + strlen(sbuf), resp, resplen);

	rewrite: ssize_t n = SSL_write(d_ssl, sbuf, MSG_BSIZE);
	switch (SSL_get_error(d_ssl, n)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			goto rewrite;
		default:
			d_err = "client_session::authenticate:";
			d_err += ERR_error_string(ERR_get_error(), nullptr);
			return -1;
	}

	return 0;
}


int client_session::handle()
{
	char rbanner[1024] = {0};

	FILE *fstream = fdopen(d_peer_fd, "r+");
	if (!fstream) {
		d_err = "client_session::handle::fdopen:";
		d_err += strerror(errno);
		return -1;
	}

	setbuffer(fstream, nullptr, 0);
	SSL_set_fd(d_ssl, d_peer_fd);

	fgets(rbanner, sizeof(rbanner) - 1, fstream);

	d_sbanner = rbanner;

	uint16_t major = 0, minor = 0;
	if (sscanf(rbanner, "1000 crashd-%hu.%hu OK\r\n", &major, &minor) != 2) {
		d_err = "client_session::handle:: Invalid remote banner string.";
		return -1;
	}

	if (config::verbose) {
		if ((major != d_major || minor != d_minor))
			printf("crashc: Different versions. Authentication may fail.\n");
		else
			printf("crashc: Major/Minor versions match (%hu/%hu)\n", major, minor);
	}

	if (SSL_connect(d_ssl) <= 0) {
		d_err = "client_session::handle::SSL_connect:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if (config::verbose) {
		char ssl_desc[256] = {0};
		memset(ssl_desc, 0, sizeof(ssl_desc));
		SSL_CIPHER_description(SSL_get_current_cipher(d_ssl), ssl_desc, sizeof(ssl_desc) - 1);
		printf("crashc: Cipher: %s", ssl_desc);
	}

	if (check_server_key() != 1)
		return -1;

	if (authenticate() < 0)
		return -1;

	// Now, where passphrase has been typed etc;
	// setup terminal into raw mode
	if (d_has_tty)
		tcsetattr(0, TCSANOW, &d_tattr);

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		return -1;

	if (!(d_pfds = new (nothrow) pollfd[rl.rlim_cur]))
		return -1;
	if (!(d_fd2state = new (nothrow) state[rl.rlim_cur]))
		return -1;

	d_fd2state[0].fd = 0;
	d_fd2state[0].state = STATE_STDIN;

	d_fd2state[1].fd = 1;
	d_fd2state[1].state = STATE_STDOUT;

	d_fd2state[d_peer_fd].fd = d_peer_fd;
	d_fd2state[d_peer_fd].state = STATE_SSL;

	for (unsigned int i = 0; i < rl.rlim_cur; ++i) {
		d_pfds[i].fd = -1;
		d_pfds[i].events = d_pfds[i].revents = 0;
	}

	ssize_t r = 0;

	d_pfds[0].fd = 0;
	d_pfds[0].events = POLLIN;
	d_pfds[1].fd = 1;
	d_pfds[1].events = POLLOUT;
	d_pfds[d_peer_fd].fd = d_peer_fd;
	d_pfds[d_peer_fd].events = POLLIN;

	// No need to setup window-size on non-pty calls
	if (config::cmd.size() > 0)
		global::window_size_changed = 0;
	else
		global::window_size_changed = 1;

	for (auto it = config::tcp_listens.begin(); it != config::tcp_listens.end(); ++it) {
		if ((r = tcp_listen("127.0.0.1", it->first)) < 0)
			continue;
		d_pfds[r].fd = r;
		d_pfds[r].events = POLLIN;

		d_fd2state[r].fd = r;
		d_fd2state[r].rnode = it->second;
		d_fd2state[r].state = STATE_ACCEPT;
	}

	for (auto it = config::udp_listens.begin(); it != config::udp_listens.end(); ++it) {
		if ((r = udp_listen("127.0.0.1", it->first)) < 0)
			continue;
		d_pfds[r].fd = r;
		d_pfds[r].events = POLLIN;

		d_fd2state[r].fd = r;
		d_fd2state[r].rnode = it->second;
		d_fd2state[r].state = STATE_UDPSERVER;
	}

	if (config::socks5_port != -1) {
		d_pfds[config::socks5_fd].fd = config::socks5_fd;
		d_pfds[config::socks5_fd].events = POLLIN;

		d_fd2state[config::socks5_fd].fd = config::socks5_fd;
		d_fd2state[config::socks5_fd].rnode = "";
		d_fd2state[config::socks5_fd].state = STATE_SOCKS5_ACCEPT;
	}

	if (config::socks4_port != -1) {
		d_pfds[config::socks4_fd].fd = config::socks4_fd;
		d_pfds[config::socks4_fd].events = POLLIN;

		d_fd2state[config::socks4_fd].fd = config::socks4_fd;
		d_fd2state[config::socks4_fd].rnode = "";
		d_fd2state[config::socks4_fd].state = STATE_SOCKS4_ACCEPT;
	}

	// Build a local address for sending reply UDP dgrams. Only the dst port is unknown yet
	// and will be constructed from the ID part of the IP/port/ID header
	struct sockaddr_in lsin;
	lsin.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &lsin.sin_addr);

	// only now set non-blocking mode and moving write buffers
	int flags = fcntl(d_peer_fd, F_GETFL);
	fcntl(d_peer_fd, F_SETFL, flags|O_NONBLOCK);
	SSL_set_mode(d_ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);

	// rbuf a bit larger to contain "1234:C:..." prefix and making it more likely
	// that handle_input() isn't called with incomplete buffer but in a way the first
	// SSL_read() could contain a complete maximum MTU packet
	char buf[MTU] = {0}, rbuf[MTU + 128] = {0}, sbuf[MTU] = {0};

	bool has_stdin = 1, leave = 0;
	int max_fd = d_peer_fd, i = 0, pto = 1000, afd = -1;
	uint16_t u16 = 0;

	if (config::rand_traffic) {
		// should be OK to use re-seeded RAND to obtain timeout values for poll
		// without leaking internal PRNG state via PING-send timings?
		RAND_load_file("/dev/urandom", 16);
		pto = 20;
	}

	for (;!leave;) {

		if (has_stdin)
			d_pfds[0].events = POLLIN;
		else
			d_pfds[0].events = 0;

		errno = 0;

		if (global::window_size_changed)
			send_window_size();

		for (i = rl.rlim_cur - 1; i > 0; --i) {
			if (d_fd2state[i].state != STATE_INVALID && d_fd2state[i].fd != -1) {
				max_fd = i;
				break;
			}
		}

		if ((r = poll(d_pfds, max_fd + 1, pto)) < 0)
			continue;

		// simulate some typing if configured so
		if (config::rand_traffic && r == 0) {
			RAND_bytes(reinterpret_cast<unsigned char *>(&u16), 2);
			pto = u16 % 1000;
			if (d_fd2state[d_peer_fd].obuf.size() == 0) {
				d_fd2state[d_peer_fd].obuf = ping_packet();
				d_pfds[d_peer_fd].revents |= POLLOUT;
			}
		}

		time_t now = time(nullptr);

		for (i = 0; i <= max_fd; ++i) {

			if (d_fd2state[i].state == STATE_INVALID)
				continue;

			if ((d_fd2state[i].state == STATE_CLOSING && (now - d_fd2state[i].time) > CLOSING_TIME) ||
			    (d_fd2state[i].state == STATE_CONNECT && (now - d_fd2state[i].time) > CONNECT_TIME)) {

				if (d_fd2state[i].state == STATE_CONNECT) {
					d_pfds[d_peer_fd].events |= POLLOUT;
					d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size());
					d_fd2state[d_peer_fd].obuf += ":C:T:F:" + d_fd2state[i].rnode;		// signal interrupted connection to remote
					tcp_nodes2sock.erase(d_fd2state[i].rnode);
				}
				close(i);
				d_fd2state[i].fd = -1;
				d_fd2state[i].state = STATE_INVALID;
				d_fd2state[i].obuf.clear();
				d_pfds[i].fd = -1;
				d_pfds[i].events = 0;
				continue;
			}

			if (d_pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				if (d_fd2state[i].state == STATE_SSL) {
					leave = 1;
					break;
				}

				if (d_fd2state[i].state == STATE_CONNECTED || d_fd2state[i].state == STATE_CONNECT) {
					d_pfds[d_peer_fd].events |= POLLOUT;
					d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size());
					d_fd2state[d_peer_fd].obuf += ":C:T:F:" + d_fd2state[i].rnode;	// signal interrupted connection to remote
					tcp_nodes2sock.erase(d_fd2state[i].rnode);
				}

				close(i);
				d_fd2state[i].fd = -1;
				d_fd2state[i].state = STATE_INVALID;
				d_fd2state[i].obuf.clear();
				d_pfds[i].fd = -1;
				d_pfds[i].events = 0;
				continue;
			}

			if ((d_pfds[i].revents & (POLLIN|POLLOUT)) == 0)
				continue;

			unsigned short revents = d_pfds[i].revents;
			d_pfds[i].revents = 0;

			if (d_fd2state[i].state == STATE_STDIN) {
				if ((r = read(i, buf, sizeof(buf))) <= 0) {
					if (errno == EINTR)
						continue;
					has_stdin = 0;
					if (r < 0 || d_has_tty)
						continue;

					r = 1;
					buf[0] = 0x3;	// emulate Ctrl-C for pipes
				}

				d_fd2state[d_peer_fd].obuf += slen(6 + r) + ":D:I0:";	// input from 0
				d_fd2state[d_peer_fd].obuf += string(buf, r);
				d_pfds[d_peer_fd].events |= POLLOUT;

			} else if (d_fd2state[i].state == STATE_STDOUT) {
				r = write(i, d_fd2state[i].obuf.c_str(), d_fd2state[i].obuf.size());
				if (r > 0)
					d_fd2state[i].obuf.erase(0, r);
				if (d_fd2state[i].obuf.size() > 0)
					d_pfds[i].events = POLLOUT;
				else
					d_pfds[i].events = 0;
			} else if (d_fd2state[i].state == STATE_SSL) {

				d_pfds[i].events = POLLIN;

				if (d_fd2state[i].obuf.size() > 0) {

					pad_nops(d_fd2state[i].obuf);

					ssize_t n = SSL_write(d_ssl, d_fd2state[i].obuf.c_str(), d_fd2state[i].obuf.size());
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_ZERO_RETURN:
						return 0;
					case SSL_ERROR_NONE:
					case SSL_ERROR_WANT_WRITE:
					case SSL_ERROR_WANT_READ:
						break;
					default:
						d_err = "client_session::handle::SSL_write:";
						d_err += ERR_error_string(ERR_get_error(), nullptr);
						return -1;
					}
					if (n > 0)
						d_fd2state[i].obuf.erase(0, n);
					if (d_fd2state[i].obuf.size() > 0)
						d_pfds[i].events |= POLLOUT;
				}

				if (revents & (POLLIN|POLLOUT)) {

					ssize_t n = SSL_read(d_ssl, rbuf, sizeof(rbuf));
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_NONE:
						break;
					case SSL_ERROR_ZERO_RETURN:
						return 0;
					case SSL_ERROR_WANT_WRITE:
						d_pfds[i].events |= POLLOUT;
						break;
					case SSL_ERROR_WANT_READ:
						break;
					default:
						d_err = "client_session::handle::SSL_write:";
						d_err += ERR_error_string(ERR_get_error(), nullptr);
						return -1;
					}

					if (n > 0)
						d_fd2state[i].ibuf += string(rbuf, n);

					while (handle_input(d_peer_fd) > 0);

				}
			}

			if (d_fd2state[i].state < STATE_ACCEPT)
				continue;

			// net cmd handler code

			if (revents & POLLIN) {

				if (d_fd2state[i].state == STATE_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					// append ID part of host/port/id/ header. We use the accepted sock fd
					// as ID, as this is unique and identifies the TCP connection
					char id[16] = {0};
					snprintf(id, sizeof(id) - 1, "%d/", afd);

					d_pfds[afd].fd = afd;
					d_pfds[afd].events = 0;	// dont accept data until remote peer established proxy conn

					d_fd2state[afd].fd = afd;
					d_fd2state[afd].rnode = d_fd2state[i].rnode + id;
					d_fd2state[afd].state = STATE_CONNECT;
					d_fd2state[afd].time = now;
					d_fd2state[afd].obuf.clear();

					tcp_nodes2sock[d_fd2state[afd].rnode] = afd;

					d_pfds[d_peer_fd].events |= POLLOUT;
					d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[afd].rnode.size());
					d_fd2state[d_peer_fd].obuf += ":C:T:N:" + d_fd2state[afd].rnode;	// trigger tcp_connect() on remote side

				} else if (d_fd2state[i].state == STATE_SOCKS5_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					d_pfds[afd].fd = afd;
					d_pfds[afd].events = POLLIN;		// wait for SOCKS5 proto requests
					d_fd2state[afd].fd = afd;
					d_fd2state[afd].rnode = "";
					d_fd2state[afd].state = STATE_SOCKS5_AUTH1;
					d_fd2state[afd].time = now;
					d_fd2state[afd].obuf.clear();

				} else if (d_fd2state[i].state == STATE_SOCKS4_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					d_pfds[afd].fd = afd;
					d_pfds[afd].events = POLLIN;		// wait for SOCKS4 proto requests
					d_fd2state[afd].fd = afd;
					d_fd2state[afd].rnode = "";
					d_fd2state[afd].state = STATE_SOCKS4_AUTH;
					d_fd2state[afd].time = now;
					d_fd2state[afd].obuf.clear();

				} else if (d_fd2state[i].state == STATE_CONNECTED) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].state = STATE_INVALID;
						d_fd2state[i].fd = -1;
						d_fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(d_fd2state[i].rnode);

						d_pfds[d_peer_fd].events |= POLLOUT;
						d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size());
						d_fd2state[d_peer_fd].obuf += ":C:T:F:" + d_fd2state[i].rnode;	// signal finished connection via SSL to remote
						continue;
					}
					d_pfds[d_peer_fd].events |= POLLOUT;
					d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size() + r);
					d_fd2state[d_peer_fd].obuf += ":C:T:S:" + d_fd2state[i].rnode + string(sbuf, r);
					d_fd2state[i].time = now;

				} else if (d_fd2state[i].state == STATE_SOCKS4_AUTH) {

					socks4_req *s4r = reinterpret_cast<socks4_req *>(sbuf);

					// expect SOCKS4 request and send positive response
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0 || sbuf[0] != 4) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].state = STATE_INVALID;
						d_fd2state[i].fd = -1;
						d_fd2state[i].obuf.clear();
						continue;
					}

					s4r->ver = 0;
					s4r->cmd = 0x5a;			// request granted
					d_fd2state[i].obuf += string(sbuf, 8);	// orig req w/o ID

					char dst[128] = {0};
					uint16_t rport = 0;

					inet_ntop(AF_INET, &s4r->dst, dst, sizeof(dst) - 1);
					rport = ntohs(s4r->dport);

					// Now that we know where connection is going to, we can build
					// IP/port/ID header
					char hdr[256] = {0};
					snprintf(hdr, sizeof(hdr) - 1, "%s/%d/%d/", dst, rport, i);

					d_fd2state[i].rnode = hdr;
					d_fd2state[i].state = STATE_CONNECT;
					d_fd2state[i].time = now;

					tcp_nodes2sock[d_fd2state[i].rnode] = i;

					d_pfds[d_peer_fd].events |= POLLOUT;
					d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size());
					d_fd2state[d_peer_fd].obuf += ":C:T:N:" + d_fd2state[i].rnode;	// trigger tcp_connect() on remote side

					d_pfds[i].events = POLLOUT;	// don't take data until remote site established connection, so *only* POLLOUT

				} else if (d_fd2state[i].state == STATE_SOCKS5_AUTH1) {

					// expect SOCKS5 auth request (none) and send positive response
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) != 3 || sbuf[0] != 5) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].state = STATE_INVALID;
						d_fd2state[i].fd = -1;
						d_fd2state[i].obuf.clear();
						continue;
					}
					d_pfds[i].events |= POLLOUT;
					d_fd2state[i].state = STATE_SOCKS5_AUTH2;
					d_fd2state[i].obuf += string("\x05\x00", 2);
					d_fd2state[i].time = now;
				} else if (d_fd2state[i].state == STATE_SOCKS5_AUTH2) {

					memset(sbuf, 0, sizeof(sbuf));
					socks5_req *s5r = reinterpret_cast<socks5_req *>(sbuf);

					// expect SOCKS5 connect request
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) < 10 ||
					    s5r->vers != 5 ||				// wrong version?
					    (s5r->atype != 1 && s5r->atype != 4) ||	// IPv4 or IPv6
					    s5r->cmd != 1) {				// not a TCP-connect?
						s5r->cmd = 0x08;			// atype not supported
						d_fd2state[i].obuf += string(sbuf, r);
						d_pfds[i].events |= POLLOUT;		// out and expect next request
						continue;
					}

					char dst[128] = {0};
					uint16_t rport = 0;

					if (s5r->atype == 1) {
						inet_ntop(AF_INET, &s5r->v4.dst, dst, sizeof(dst) - 1);
						rport = ntohs(s5r->v4.dport);
					} else {
						inet_ntop(AF_INET6, &s5r->v6.dst, dst, sizeof(dst) - 1);
						rport = ntohs(s5r->v6.dport);
					}

					// Now that we know where connection is going to, we can build
					// IP/port/ID header
					char hdr[256] = {0};
					snprintf(hdr, sizeof(hdr) - 1, "%s/%d/%d/", dst, rport, i);

					d_fd2state[i].rnode = hdr;
					d_fd2state[i].state = STATE_CONNECT;
					d_fd2state[i].time = now;

					tcp_nodes2sock[d_fd2state[i].rnode] = i;

					d_pfds[d_peer_fd].events |= POLLOUT;
					d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size());
					d_fd2state[d_peer_fd].obuf += ":C:T:N:" + d_fd2state[i].rnode;	// trigger tcp_connect() on remote side

					s5r->cmd = 0;	// response status to socks5 client
					d_fd2state[i].obuf += string(sbuf, r);

					d_pfds[i].events = POLLOUT;	// don't take data until remote site established connection, so *only* POLLOUT

				} else if (d_fd2state[i].state == STATE_UDPSERVER) {

					// Always listens on 127.0.0.1, so this is always AF_INET
					sockaddr_in sin;
					socklen_t sinlen = sizeof(sin);
					if ((r = recvfrom(i, sbuf, sizeof(sbuf), 0, reinterpret_cast<sockaddr *>(&sin), &sinlen)) <= 0)
						continue;

					// in UDP case, we use the local port as ID.
					char id[16] = {0};
					snprintf(id, sizeof(id) - 1, "%d/", sin.sin_port);

					d_pfds[d_peer_fd].events |= POLLOUT;

					// Note here that ID needs to be appended, unlike with TCP. This is since sock fd doesnt
					// distinguish sessions but local ports do this in UDP mode
					d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size() + strlen(id) + r);
					d_fd2state[d_peer_fd].obuf += ":C:U:S:" + d_fd2state[i].rnode + id + string(sbuf, r);
					d_fd2state[i].time = now;

					udp_nodes2sock[d_fd2state[i].rnode + id] = i;
				}
			}
			if (revents & POLLOUT) {

				if (d_fd2state[i].state == STATE_CONNECT ||	// for the SOCKS4/5 case: reply with conn success
				    d_fd2state[i].state == STATE_SOCKS5_AUTH2 ||	// for the SOCKS5 case: reply for auth success
				    d_fd2state[i].state == STATE_CONNECTED) {
					if ((r = write(i, d_fd2state[i].obuf.c_str(), d_fd2state[i].obuf.size())) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].state = STATE_INVALID;
						d_fd2state[i].fd = -1;
						d_fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(d_fd2state[i].rnode);

						d_pfds[d_peer_fd].events |= POLLOUT;
						d_fd2state[d_peer_fd].obuf += slen(7 + d_fd2state[i].rnode.size());
						d_fd2state[d_peer_fd].obuf += ":C:T:F:" + d_fd2state[i].rnode;	// signal finished connection via SSL to remote
						continue;
					}

					d_fd2state[i].time = now;
					d_fd2state[i].obuf.erase(0, r);
				} else if (d_fd2state[i].state == STATE_UDPSERVER) {
					string &dgram = d_fd2state[i].odgrams.front();
					lsin.sin_port = d_fd2state[i].ulports.front();	// ID == dst port of reply datagram already in network order
					if ((r = sendto(i, dgram.c_str(), dgram.size(), 0, reinterpret_cast<const sockaddr *>(&lsin), sizeof(lsin))) <= 0)
						continue;

					d_fd2state[i].odgrams.pop_front();
					d_fd2state[i].ulports.pop_front();
					d_fd2state[i].time = now;
				}

				if (d_fd2state[i].obuf.empty() && d_fd2state[i].odgrams.empty())
					d_pfds[i].events &= ~POLLOUT;
			}
		}
	}

	return 0;
}


int client_session::handle_input(int i)
{

	string &cmd = d_fd2state[i].ibuf;

	if (cmd.size() < 7)
		return 0;

	unsigned short l = 0;
	if (sscanf(cmd.c_str(), "%05hu:", &l) != 1)
		return -1;
	size_t len = l;

	if (len < 6)
		return -1;
	if (cmd.size() < 5 + len)
		return 0;

	if (cmd.find("D:O1:", 6) == 6) {
		d_pfds[1].events |= POLLOUT;
		d_fd2state[1].obuf += cmd.substr(5 + 6, len - 6);
	} else if (cmd.find("D:O2:", 6) == 6) {
		d_pfds[2].events |= POLLOUT;
		d_fd2state[2].obuf += cmd.substr(5 + 6, len - 6);
	} else if (cmd.find("C:PP:", 6) == 6) {
		const string echo = cmd.substr(5 + 6, len - 6);
		d_fd2state[d_peer_fd].obuf += slen(6 + echo.size());
		d_fd2state[d_peer_fd].obuf += ":C:PR:" + echo;
		d_pfds[d_peer_fd].events |= POLLOUT;
	} else if (cmd.find("C:T:", 6) == 6 || cmd.find("C:U:", 6) == 6) {
		net_cmd_handler(cmd, d_fd2state, d_pfds);
	} else if (cmd.find("C:PR:", 6) == 6) {
		;	// ignore ping replies
	} else if (cmd.find("C:NO:", 6) == 6) {
		;	// ignore NOPs
	}

	cmd.erase(0, 5 + len);

	// one command was handled. There may be more in the ibuf
	return 1;
}

}

using namespace crash;

void help(const char *p)
{
	printf("\nUsage:\t%s [-6] [-v] [-H host] [-p port] [-P local port] [-i auth keyfile]\n"
	       "\t [-K server key/s] [-c command] [-U lport:[ip]:rport]\n"
	       "\t [-T lport:[ip]:rport] [-4 lport] [-5 lport] [-R] <-l user>\n\n"
	       "\t -6 -- use IPv6 instead of IPv4\n"
	       "\t -v -- be verbose\n"
	       "\t -H -- host to connect to; if omitted: passive connect (default)\n"
	       "\t -p -- port to connect/listen to; default is %s\n"
	       "\t -P -- local port used in active connects (default is no bind)\n"
	       "\t -i -- private key used for authentication\n"
	       "\t -K -- folder of known host keys if it ends with '/';\n"
	       "\t       absolute path of known-hosts file otherwise;\n"
	       "\t       'none' to disable; default is %s\n"
	       "\t -c -- command to execute on remote host\n"
	       "\t -U -- forward UDP port lport to ip:rport on remote site\n"
	       "\t -T -- forward TCP port lport to ip:rport on remote site\n"
	       "\t -4 -- start SOCKS4 server on lport to forward TCP sessions\n"
	       "\t -5 -- start SOCKS5 server on lport to forward TCP sessions\n"
	       "\t -R -- enable traffic analysis mitigation\n"
	       "\t -l -- user to login as (no default!)\n\n",
	       p, config::port.c_str(), config::server_keys.c_str());
}


void sig_int(int x)
{
	return;
}


int main(int argc, char **argv)
{

	struct sigaction sa;
	string ostr = "";

	int c = 0;
	char lport[16] = {0}, ip[128] = {0}, rport[16] = {0};

	while ((c = getopt(argc, argv, "6vhH:K:p:P:l:i:c:RT:U:5:4:")) != -1) {
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
			if (config::server_keys == "none")
				config::no_hk_check = 1;
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
		case 'R':
			config::rand_traffic = 1;
			break;
		case 'T':
			sscanf(optarg, "%15[0-9]:[%127[^]]]:%15[0-9]", lport, ip, rport);
			config::tcp_listens[lport] = string(ip) + "/" + string(rport) + "/";
			ostr += "crashc: set up local TCP port " + string(lport) + " to proxy to " + string(ip) + ":" + string(rport) + " @ remote.\n";
			break;
		case 'U':
			sscanf(optarg, "%15[0-9]:[%127[^]]]:%15[0-9]", lport, ip, rport);
			config::udp_listens[lport] = string(ip) + "/" + string(rport) + "/";
			ostr += "crashc: set up local UDP port " + string(lport) + " to proxy to " + string(ip) + ":" + string(rport) + " @ remote.\n";
			break;
		case '4':
			if (config::socks4_fd == -1) {
				config::socks4_port = strtoul(optarg, nullptr, 10);
				if ((config::socks4_fd = tcp_listen("127.0.0.1", optarg)) > 0)
					ostr += "crashc: set up SOCKS4 port on " + string(optarg) + "\n";
			}
			break;
		case '5':
			if (config::socks5_fd == -1) {
				config::socks5_port = strtoul(optarg, nullptr, 10);
				if ((config::socks5_fd = tcp_listen("127.0.0.1", optarg)) > 0)
					ostr += "crashc: set up SOCKS5 port on " + string(optarg) + "\n";
			}
			break;
		default:
			help(*argv);
			return 0;
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_winch;
	sigaction(SIGWINCH, &sa, nullptr);
	sa.sa_handler = sig_int;
	sigaction(SIGINT, &sa, nullptr);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, nullptr);

	if (config::user.length() == 0) {
		help(*argv);
		return 1;
	}

	if (config::verbose) {
		printf("\ncrypted admin shell (C) 2021 Sebastian Krahmer https://github.com/stealth/crash\n\n%s\n", ostr.c_str());
		printf("crashc: starting crypted administration shell\ncrashc: connecting to %s:%s ...\n\n",
		       config::host.c_str(), config::port.c_str());
	}
	client_session csess;
	if (csess.setup() < 0) {
		fprintf(stderr, "crashc: %s\n", csess.why());
		return 1;
	}

	if (csess.handle() < 0) {
		fprintf(stderr, "crashc: %s\n", csess.why());
		return 1;
	}

	if (config::verbose)
		printf("crashc: closing connection.\n");
	return 0;
}

