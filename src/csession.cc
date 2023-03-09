/*
 * Copyright (C) 2009-2022 Sebastian Krahmer.
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

#include <cstring>
#include <memory>
#include <errno.h>
#include <poll.h>
#include <string>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <termios.h>

#include "net.h"
#include "config.h"
#include "global.h"
#include "session.h"
#include "misc.h"
#include "missing.h"


#include <cstdint>

extern "C" {
#include <openssl/rand.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}



namespace crash {


#ifdef USE_CCIPHERS
string ciphers = USE_CCIPHERS;
#else
string ciphers = "!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:!ADH:!3DES:AES256:AESGCM:SHA256:SHA384:@STRENGTH";
#endif


client_session::~client_session()
{
	if (d_has_tty)
		tcsetattr(0, TCSANOW, &d_old_tattr);
}


int client_session::setup()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	if (d_type == SOCK_DGRAM)
		d_ssl_method = DTLS_client_method();
	else
		d_ssl_method = TLS_client_method();

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

	long op = SSL_OP_SINGLE_DH_USE|SSL_OP_SINGLE_ECDH_USE|SSL_OP_NO_TICKET|SSL_OP_NO_QUERY_MTU;

#ifdef SSL_OP_NO_COMPRESSION
	op |= SSL_OP_NO_COMPRESSION;
#endif

	if ((unsigned long)(SSL_CTX_set_options(d_ssl_ctx, op) & op) != (unsigned long)op) {
		d_err = "client_session::setup::SSL_CTX_set_options():";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	int min_vers = TLS1_3_VERSION;

	if (d_type == SOCK_DGRAM)
		min_vers = DTLS1_2_VERSION;

	if (SSL_CTX_set_min_proto_version(d_ssl_ctx, min_vers) != 1) {
		d_err = "Server::setup::SSL_CTX_set_min_proto_version():";
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

#ifndef BORINGSSL_API_VERSION
	// DTLS_set_link_mtu(d_ssl, MTU) on openssl
	if (d_type == SOCK_DGRAM)
		SSL_ctrl(d_ssl, SSL_CTRL_SET_MTU, MTU, 0);
#endif

	if (d_sni.size())
		SSL_set_tlsext_host_name(d_ssl, d_sni.c_str());

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

	unique_ptr<Socket> sock(nullptr);
	if (config::v6)
		sock.reset(new (nothrow) Socket(PF_INET6, d_type));
	else
		sock.reset(new (nothrow) Socket(PF_INET, d_type));

	if (!sock.get() || !sock->is_good()) {
		d_err = "client_session::setup::Socket:";
		return -1;
	}

	if (config::host.length() == 0 && d_transport == "tls1") {
		int sock_fd = 0;
		if ((sock_fd = sock->blisten(strtoul(config::port.c_str(), nullptr, 10))) < 0) {
			d_err = "client_session::setup::";
			d_err += sock->why();
			return -1;
		}
		if ((d_peer_fd = accept(sock_fd, nullptr, 0)) < 0) {
			d_err = "client_session::setup::accept:";
			d_err += strerror(errno);
			return -1;
		}
		// not. owned by sock {}
		//close(sock_fd);
	} else if (config::host.length() > 0) {
		if (config::local_port.length() > 0)
			sock->blisten(strtoul(config::local_port.c_str(), nullptr, 10), 0);

		// need to dup, since we are owner of d_peer_fd but connect() returns sock owned fd
		if ((d_peer_fd = dup(sock->connect(config::host, config::port))) < 0) {
			d_err = "client_session::setup::connect:";
			d_err += sock->why();
			return -1;
		}
	} else {
		d_err = "client_session::setup: Not possible to do passive connect in UDP client mode.";
		return -1;
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

	tx_add(d_peer_fd, cmd);
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
			fprintf(stderr, "crashc: Hostkey checking disabled!\n");
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
		fprintf(stderr, "crashc:{\n");
		PEM_write_PUBKEY(stderr, d_pubkey);
		fprintf(stderr, "crashc:}\n");
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
	if (r <= 0 || rbuf[0] != 'A')
		return -1;

	uint16_t major = 0, minor = 0;
	char challenge[64] = {0};
	unsigned short clen = 0;
	if (sscanf(rbuf, "A:crash-%hu.%04hu:sign2:rsa1:%hu:", &major, &minor, &clen) != 3)
		return -1;
	if (clen > sizeof(challenge))
		return -1;

	// find last ':'
	char *ptr = strchr(rbuf + 3, ':');
	for (int colons = 0; colons < 3; ++colons) {
		if (!ptr++)
			return -1;
		ptr = strchr(ptr, ':');
	}
	if (!ptr++)
		return -1;
	if (r - (ptr - rbuf) < (ssize_t)clen)
		return -1;
	memcpy(challenge, ptr, clen);

	d_err = "client_session::authenticate::unable to complete authentication";
	if (EVP_PKEY_size(d_privkey) < 32 || EVP_PKEY_size(d_privkey) > MSG_BSIZE)
		return -1;

	unsigned char resp[MSG_BSIZE] = {0};
	unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_delete)> md_ctx{
		EVP_MD_CTX_create(),
		EVP_MD_CTX_delete
	};
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
	snprintf(sbuf, sizeof(sbuf), "A:crash-%hu.%04hu:sign2:rsa1:%32s:%hu:%s:token:%hu:",
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

	// If a SNI is given, we use the SNI string as banner for Sign()
	if (!d_sni.size()) {
		char rbanner[1024] = {0};

		FILE *fstream = fdopen(d_peer_fd, "r+");
		if (!fstream) {
			d_err = "client_session::handle::fdopen:";
			d_err += strerror(errno);
			return -1;
		}

		setbuffer(fstream, nullptr, 0);

		if (!fgets(rbanner, sizeof(rbanner) - 1, fstream)) {
			d_err = "client_session::handle:: Cannot read remote banner string.";
			return -1;
		}

		// no fclose()

		d_sbanner = rbanner;

		uint16_t major = 0, minor = 0;
		if (sscanf(rbanner, "1000 crashd-%hu.%04hu OK\r\n", &major, &minor) != 2) {
			d_err = "client_session::handle:: Invalid remote banner string.";
			return -1;
		}

		if (config::verbose) {
			if ((major != d_major || minor != d_minor))
				fprintf(stderr, "crashc: Different versions. Some features might not work.\n");
			else
				fprintf(stderr, "crashc: Major/Minor versions match (%hu/%hu)\n", major, minor);
		}
	} else {
		d_sbanner = d_sni;

		if (config::verbose)
			fprintf(stderr, "crashc: Using SNI instead of banner. No major/minor version check.\n");
	}

	SSL_set_fd(d_ssl, d_peer_fd);

	if (SSL_connect(d_ssl) <= 0) {
		d_err = "client_session::handle::SSL_connect:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if (config::verbose) {
		char ssl_desc[256] = {0};
		memset(ssl_desc, 0, sizeof(ssl_desc));
		SSL_CIPHER_description(SSL_get_current_cipher(d_ssl), ssl_desc, sizeof(ssl_desc) - 1);
		fprintf(stderr, "crashc: Cipher: %s", ssl_desc);
	}

	if (check_server_key() != 1)
		return -1;

	if (authenticate() < 0)
		return -1;

	// Now, where passphrase has been typed etc;
	// setup terminal into raw mode
	if (d_has_tty && config::cmd.size() == 0)
		tcsetattr(0, TCSANOW, &d_tattr);

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		return -1;
	if (rl.rlim_cur > FDID_MAX) {
		rl.rlim_cur = rl.rlim_max = FDID_MAX;
		setrlimit(RLIMIT_NOFILE, &rl);
	}

	if (!(d_pfds = new (nothrow) pollfd[rl.rlim_cur]))
		return -1;
	if (!(d_fd2state = new (nothrow) state[rl.rlim_cur]))
		return -1;

	d_fd2state[0].fd = 0;
	d_fd2state[0].state = STATE_STDIN;

	d_fd2state[1].fd = 1;
	d_fd2state[1].state = STATE_STDOUT;

	d_fd2state[2].fd = 2;
	d_fd2state[2].state = STATE_STDERR;

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
	d_pfds[2].fd = 2;
	d_pfds[2].events = POLLOUT;

	d_pfds[d_peer_fd].fd = d_peer_fd;
	d_pfds[d_peer_fd].events = POLLIN;

	// No need to setup window-size on non-pty calls
	if (config::cmd.size() > 0)
		global::window_size_changed = 0;
	else
		global::window_size_changed = 1;

	for (auto it = config::tcp_listens.begin(); it != config::tcp_listens.end(); ++it) {
		if ((r = tcp_listen(config::local_proxy_ip, it->first)) < 0)
			continue;
		d_pfds[r].fd = r;
		d_pfds[r].events = POLLIN;

		d_fd2state[r].fd = r;
		d_fd2state[r].rnode = it->second;
		d_fd2state[r].state = STATE_ACCEPT;
	}

	for (auto it = config::udp_listens.begin(); it != config::udp_listens.end(); ++it) {
		if ((r = udp_listen(config::local_proxy_ip, it->first)) < 0)
			continue;
		d_pfds[r].fd = r;
		d_pfds[r].events = POLLIN;

		d_fd2state[r].fd = r;
		d_fd2state[r].rnode = it->second;
		d_fd2state[r].state = STATE_UDPSERVER;
	}

	if (config::socks5_fd != -1) {
		d_pfds[config::socks5_fd].fd = config::socks5_fd;
		d_pfds[config::socks5_fd].events = POLLIN;

		d_fd2state[config::socks5_fd].fd = config::socks5_fd;
		d_fd2state[config::socks5_fd].rnode = "";
		d_fd2state[config::socks5_fd].state = STATE_SOCKS5_ACCEPT;
	}

	if (config::socks4_fd != -1) {
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
	if (d_type == SOCK_STREAM) {
		int flags = fcntl(d_peer_fd, F_GETFL);
		fcntl(d_peer_fd, F_SETFL, flags|O_NONBLOCK);
		SSL_set_mode(d_ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);
	}

	d_max_fd = d_peer_fd;

	// backing string for tx_string()
	string bk_str;
	bk_str.reserve(2*CHUNK_SIZE);

	// do not touch the buffer sizes, they are well calculated
	char rbuf[RBUF_BSIZE] = {0}, sbuf[SBUF_BSIZE] = {0}, stdin_buf[STDIN_BSIZE] = {0};

	int i = 0, afd = -1, ssl_read_wants_write = 0;
	uint16_t u16 = 0;

	if (config::traffic_flags & TRAFFIC_INJECT) {
		// should be OK to use re-seeded RAND to obtain timeout values for poll
		// without leaking internal PRNG state via PING-send timings?
		RAND_load_file("/dev/urandom", 16);
	}

	// First send a ping packet to check for successfull login and process setup
	tx_add(d_peer_fd, "00010:C:PP:ping");
	d_pfds[d_peer_fd].events |= POLLOUT;

	// signal padding policy to server; the inject policy is handled by client alone
	// via different ping types
	if (config::traffic_flags & TRAFFIC_NOPAD)
		tx_add(d_peer_fd, "00006:C:P0:");
	else if (config::traffic_flags & TRAFFIC_PADMAX)
		tx_add(d_peer_fd, "00006:C:P9:");

	// We loop forever. The one and only exit condition is really when remote peer closed connection,
	// which we detect by SSL_read()/SSL_write() returns
	for (;;) {

		errno = 0;

		if (global::window_size_changed)
			send_window_size();

		for (i = rl.rlim_cur - 1; i > 0; --i) {
			if (d_fd2state[i].state != STATE_INVALID && d_fd2state[i].fd != -1) {
				d_max_fd = i;
				break;
			}
		}

		if ((r = poll(d_pfds, d_max_fd + 1, d_poll_to.next)) < 0)
			continue;

		RAND_bytes(reinterpret_cast<unsigned char *>(&u16), 2);
		d_poll_to.next = d_poll_to.min + u16 % d_poll_to.max;

		if (d_type == SOCK_DGRAM && ((r == 0 && tx_empty(d_peer_fd)) || tx_must_add_sq(d_peer_fd)))
			tx_add_sq(d_peer_fd);

		// simulate some typing if configured so
		if (d_type == SOCK_STREAM && r == 0 && ((config::traffic_flags & TRAFFIC_INJECT) && tx_empty(d_peer_fd))) {
			tx_add(d_peer_fd, ping_packet());
			d_pfds[d_peer_fd].revents |= POLLOUT;
		}

		d_now = time(nullptr);

		for (i = 0; i <= d_max_fd; ++i) {

			if (d_fd2state[i].state == STATE_INVALID)
				continue;

			if ((d_fd2state[i].state == STATE_CLOSING && (d_now - d_fd2state[i].time) > CLOSING_TIME) ||
			    (d_fd2state[i].state == STATE_CONNECT && (d_now - d_fd2state[i].time) > CONNECT_TIME)) {

				if (d_fd2state[i].state == STATE_CONNECT) {
					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);	// signal interrupted connection to remote
					d_pfds[d_peer_fd].events |= POLLOUT;
					tcp_nodes2sock.erase(d_fd2state[i].rnode);
				}
				close(i);
				d_fd2state[i].fd = -1;
				d_fd2state[i].state = STATE_INVALID;
				tx_clear(i);
				d_pfds[i].fd = -1;
				d_pfds[i].events = 0;
				d_pfds[i].revents = 0;
				continue;
			}

			if (d_pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
				if (d_fd2state[i].state == STATE_SSL) {
					flush_fd(1, tx_string_and_clear(1));
					flush_fd(2, tx_string_and_clear(2));
					return -1;
				}

				if (!(d_pfds[i].revents & POLLIN)) {

					if (d_fd2state[i].state == STATE_CONNECTED || d_fd2state[i].state == STATE_CONNECT) {
						tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);	// signal interrupted connection to remote
						d_pfds[d_peer_fd].events |= POLLOUT;
						tcp_nodes2sock.erase(d_fd2state[i].rnode);
					}

					// (potentially redirected) stdin was closed and no data pending. signal stdin-close to peer
					if (d_fd2state[i].state == STATE_STDIN) {
						tx_add(d_peer_fd, slen(7) + ":C:CL:0");
						d_pfds[d_peer_fd].events |= POLLOUT;
					}

					close(i);
					d_fd2state[i].fd = -1;
					d_fd2state[i].state = STATE_INVALID;
					tx_clear(i);
					d_pfds[i].fd = -1;
					d_pfds[i].events = 0;
					d_pfds[i].revents = 0;
					continue;
				}
			}

			if ((d_pfds[i].revents & (POLLIN|POLLOUT)) == 0)
				continue;

			unsigned short revents = d_pfds[i].revents;
			d_pfds[i].revents = 0;

			if (d_fd2state[i].state == STATE_STDIN && tx_can_add(d_peer_fd)) {
				if ((r = read(i, stdin_buf, sizeof(stdin_buf))) <= 0) {
					if (errno == EINTR)
						continue;
					close(i);
					d_fd2state[i].fd = -1;
					d_fd2state[i].state = STATE_INVALID;
					tx_clear(i);
					d_pfds[i].fd = -1;
					d_pfds[i].events = 0;

					// signal end-of-stdin to peer
					tx_add(d_peer_fd, slen(7) + ":C:CL:0");
					d_pfds[d_peer_fd].events |= POLLOUT;
					continue;
				}

				tx_add(d_peer_fd, slen(6 + r) + ":D:I0:" + string(stdin_buf, r));	// input from 0
				d_pfds[d_peer_fd].events |= POLLOUT;

			} else if (d_fd2state[i].state == STATE_STDOUT || d_fd2state[i].state == STATE_STDERR) {
				sequence_t seq = 0;
				auto sv = tx_string(i, seq, bk_str, STDOUT_CHUNK_SIZE);
				r = write(i, sv.c_str(), sv.size());
				if (r > 0)
					tx_remove(i, r);
				if (!tx_empty(i))
					d_pfds[i].events = POLLOUT;
				else
					d_pfds[i].events = 0;
			} else if (d_fd2state[i].state == STATE_SSL) {

				d_pfds[i].events = POLLIN;

				if (!tx_empty(i)) {

					// obtains properly padded, sized and sequenced string for the STATE_SSL case
					// so that the chunks also fit in UDP dgrams
					sequence_t seq = 0;
					auto sv = tx_string(i, seq, bk_str, d_chunk_size);

					// keep sequenced packets for possible resend requests
					if (d_type == SOCK_DGRAM && seq != 0)
						d_tx_map[d_flow.tx_sequence++] = bk_str;

					ssize_t n = SSL_write(d_ssl, sv.c_str(), sv.size());
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_ZERO_RETURN:
						flush_fd(1, tx_string_and_clear(1));
						flush_fd(2, tx_string_and_clear(2));
						return 0;
					case SSL_ERROR_NONE:
					case SSL_ERROR_WANT_WRITE:
					case SSL_ERROR_WANT_READ:
						break;
					default:
						d_err = "client_session::handle::SSL_write:";
						d_err += ERR_error_string(ERR_get_error(), nullptr);
						flush_fd(1, tx_string_and_clear(1));
						flush_fd(2, tx_string_and_clear(2));
						return -1;
					}
					// dgram data was already removed by tx_string() before
					if (n > 0 && d_type == SOCK_STREAM)
						tx_remove(i, n);

					d_last_ssl_qlen = tx_size(i);
					if (ssl_read_wants_write || d_last_ssl_qlen > 0)
						d_pfds[i].events |= POLLOUT;

					if (!(revents & POLLIN) && !ssl_read_wants_write)
						continue;
				}

				if (revents & (POLLIN|POLLOUT)) {

					ssl_read_wants_write = 0;

					ssize_t n = SSL_read(d_ssl, rbuf, sizeof(rbuf));
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_NONE:
						break;
					case SSL_ERROR_ZERO_RETURN:
						flush_fd(1, tx_string_and_clear(1));
						flush_fd(2, tx_string_and_clear(2));
						return 0;
					case SSL_ERROR_WANT_WRITE:
						d_pfds[i].events |= POLLOUT;
						ssl_read_wants_write = 1;
						break;
					case SSL_ERROR_WANT_READ:
						break;
					default:
						d_err = "client_session::handle::SSL_read:";
						d_err += ERR_error_string(ERR_get_error(), nullptr);
						flush_fd(1, tx_string_and_clear(1));
						flush_fd(2, tx_string_and_clear(2));
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
					snprintf(id, sizeof(id) - 1, "%04hx/", (unsigned short)afd);	// FDID_MAX guarantees type short

					d_pfds[afd].fd = afd;
					d_pfds[afd].events = 0;	// dont accept data until remote peer established proxy conn

					d_fd2state[afd].fd = afd;
					d_fd2state[afd].rnode = d_fd2state[i].rnode + id;
					d_fd2state[afd].state = STATE_CONNECT;
					d_fd2state[afd].time = d_now;
					tx_clear(afd);

					tcp_nodes2sock[d_fd2state[afd].rnode] = afd;

					tx_add(d_peer_fd, slen(7 + d_fd2state[afd].rnode.size()) + ":C:T:N:" + d_fd2state[afd].rnode);	// trigger tcp_connect() on remote side
					d_pfds[d_peer_fd].events |= POLLOUT;

				} else if (d_fd2state[i].state == STATE_SOCKS5_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					d_pfds[afd].fd = afd;
					d_pfds[afd].events = POLLIN;		// wait for SOCKS5 proto requests
					d_fd2state[afd].fd = afd;
					d_fd2state[afd].rnode = "";
					d_fd2state[afd].state = STATE_SOCKS5_AUTH1;
					d_fd2state[afd].time = d_now;
					tx_clear(afd);

				} else if (d_fd2state[i].state == STATE_SOCKS4_ACCEPT) {
					if ((afd = accept(i, nullptr, nullptr)) < 0)
						continue;

					d_pfds[afd].fd = afd;
					d_pfds[afd].events = POLLIN;		// wait for SOCKS4 proto requests
					d_fd2state[afd].fd = afd;
					d_fd2state[afd].rnode = "";
					d_fd2state[afd].state = STATE_SOCKS4_AUTH;
					d_fd2state[afd].time = d_now;
					tx_clear(afd);

				} else if (d_fd2state[i].state == STATE_CONNECTED && tx_can_add(d_peer_fd)) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
						tcp_nodes2sock.erase(d_fd2state[i].rnode);
						tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);	// signal finished connection via SSL to remote
						d_pfds[d_peer_fd].events |= POLLOUT;
						continue;
					}
					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size() + r) + ":C:T:S:" + d_fd2state[i].rnode + string(sbuf, r));
					d_pfds[d_peer_fd].events |= POLLOUT;
					d_fd2state[i].time = d_now;

				} else if (d_fd2state[i].state == STATE_SOCKS4_AUTH) {

					socks4_req *s4r = reinterpret_cast<socks4_req *>(sbuf);

					// expect SOCKS4 request and send positive response
					memset(sbuf, 0, sizeof(sbuf));
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) < 3 || sbuf[0] != 4) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
						continue;
					}

					s4r->ver = 0;
					s4r->cmd = 0x5a;		// request granted
					tx_add(i, string(sbuf, 8));	// orig req w/o ID

					char dst[128] = {0};
					uint16_t rport = 0;

					inet_ntop(AF_INET, &s4r->dst, dst, sizeof(dst) - 1);
					rport = ntohs(s4r->dport);

					// Now that we know where connection is going to, we can build
					// IP/port/ID header
					char hdr[256] = {0};
					snprintf(hdr, sizeof(hdr) - 1, "%s/%04hx/%04hx/", dst, rport, (unsigned short)i);

					d_fd2state[i].rnode = hdr;
					d_fd2state[i].state = STATE_CONNECT;
					d_fd2state[i].time = d_now;

					tcp_nodes2sock[d_fd2state[i].rnode] = i;

					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:N:" + d_fd2state[i].rnode);	// trigger tcp_connect() on remote side
					d_pfds[d_peer_fd].events |= POLLOUT;

					d_pfds[i].events = POLLOUT;	// don't take data until remote site established connection, so *only* POLLOUT

				} else if (d_fd2state[i].state == STATE_SOCKS5_AUTH1) {

					// expect SOCKS5 auth request (none) and send positive response
					memset(sbuf, 0, sizeof(sbuf));
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0 || sbuf[0] != 5) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
						continue;
					}
					d_fd2state[i].state = STATE_SOCKS5_AUTH2;
					tx_add(i, string("\x05\x00", 2));
					d_pfds[i].events |= POLLOUT;
					d_fd2state[i].time = d_now;
				} else if (d_fd2state[i].state == STATE_SOCKS5_AUTH2) {

					memset(sbuf, 0, sizeof(sbuf));
					socks5_req *s5r = reinterpret_cast<socks5_req *>(sbuf);

					// expect SOCKS5 connect request
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) < 10 ||
					    s5r->vers != 5 ||				// wrong version?
					    (s5r->atype != 1 && s5r->atype != 4) ||	// IPv4 or IPv6
					    s5r->cmd != 1) {				// not a TCP-connect?
						s5r->cmd = 0x08;			// atype not supported
						flush_fd(i, string(sbuf, 2));
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
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
					snprintf(hdr, sizeof(hdr) - 1, "%s/%04hx/%04hx/", dst, rport, (unsigned short)i);

					d_fd2state[i].rnode = hdr;
					d_fd2state[i].state = STATE_CONNECT;
					d_fd2state[i].time = d_now;

					tcp_nodes2sock[d_fd2state[i].rnode] = i;

					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:N:" + d_fd2state[i].rnode);	// trigger tcp_connect() on remote side
					d_pfds[d_peer_fd].events |= POLLOUT;

					s5r->cmd = 0;	// response status to socks5 client
					tx_add(i, string(sbuf, r));
					d_pfds[i].events = POLLOUT;	// don't take data until remote site established connection, so *only* POLLOUT

				} else if (d_fd2state[i].state == STATE_UDPSERVER) {

					// Always listens on 127.0.0.1, so this is always AF_INET
					sockaddr_in sin;
					socklen_t sinlen = sizeof(sin);
					if ((r = recvfrom(i, sbuf, sizeof(sbuf), 0, reinterpret_cast<sockaddr *>(&sin), &sinlen)) <= 0)
						continue;

					// in UDP case, we use the local port as ID.
					char id[16] = {0};
					snprintf(id, sizeof(id) - 1, "%04hx/", sin.sin_port);

					// Note here that ID needs to be appended, unlike with TCP. This is since sock fd doesnt
					// distinguish sessions but local ports do this in UDP mode
					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size() + 5 + r) + ":C:U:S:" + d_fd2state[i].rnode + id + string(sbuf, r));
					d_pfds[d_peer_fd].events |= POLLOUT;

					d_fd2state[i].time = d_now;

					udp_nodes2sock[d_fd2state[i].rnode + id] = i;
				}
			}
			if (revents & POLLOUT) {

				if (d_fd2state[i].state == STATE_CONNECT ||		// for the SOCKS4/5 case: reply with conn success
				    d_fd2state[i].state == STATE_SOCKS5_AUTH2 ||	// for the SOCKS5 case: reply for auth success
				    d_fd2state[i].state == STATE_CONNECTED) {
					auto sv = tx_string(i, bk_str);
					if ((r = write(i, sv.c_str(), sv.size())) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
						tcp_nodes2sock.erase(d_fd2state[i].rnode);
						tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);	// signal finished connection via SSL to remote
						d_pfds[d_peer_fd].events |= POLLOUT;
						continue;
					}

					d_fd2state[i].time = d_now;
					tx_remove(i, r);
				} else if (d_fd2state[i].state == STATE_UDPSERVER) {
					string &dgram = d_fd2state[i].odgrams.front();
					lsin.sin_port = d_fd2state[i].ulports.front();	// ID == dst port of reply datagram already in network order
					if ((r = sendto(i, dgram.c_str(), dgram.size(), 0, reinterpret_cast<const sockaddr *>(&lsin), sizeof(lsin))) <= 0)
						continue;

					d_fd2state[i].odgrams.pop_front();
					d_fd2state[i].ulports.pop_front();
					d_fd2state[i].time = d_now;
				}

				if (tx_empty(i) && d_fd2state[i].odgrams.empty())
					d_pfds[i].events &= ~POLLOUT;
			}
		}
	}

	return 0;
}


int client_session::handle_input(int i)
{
	int r = 0;

	if ((r = this->session::handle_input(i)) != 1)
		return r;

	string &cmd = d_fd2state[i].ibuf;

	if (cmd.size() < 7)
		return 0;

	unsigned short l = 0;
	if (sscanf(cmd.c_str(), "%05hu:", &l) != 1)
		return 0;
	size_t len = l;

	if (len < 6)
		return -1;
	if (cmd.size() < 5 + len)
		return 0;

	if (cmd.find("D:O1:", 6) == 6) {
		tx_add(1, cmd.substr(5 + 6, len - 6));
		d_pfds[1].events |= POLLOUT;
	} else if (cmd.find("D:O2:", 6) == 6) {
		tx_add(2, cmd.substr(5 + 6, len - 6));
		d_pfds[2].events |= POLLOUT;
	} else {

		// valid len/packet format, but unrecognized cmd. Maybe a chained command for
		// this->session::handle_input(), so keep it where it is and let next iteration handle it
		return 1;
	}

	cmd.erase(0, 5 + len);

	global::input_received = 1;

	// one command was handled. There may be more in the ibuf
	return 1;
}

}


