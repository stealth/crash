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
#include <map>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include "session.h"
#include "server.h"
#include "config.h"
#include "log.h"
#include "net.h"
#include "misc.h"

// needed for HAVE_DTLS_LISTEN
#include "missing.h"


using namespace std;
using namespace crash;


extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
}

namespace crash {

unsigned short Server::d_min_time_between_reconnect = 1;


#ifdef USE_SCIPHERS
string ciphers = USE_SCIPHERS;
#else
string ciphers = "!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:!3DES:!ADH:kDHE:RSA:AES256:AESGCM:SHA256:SHA384:@STRENGTH";
#endif

extern int enable_dh(SSL_CTX *);


map<int, string> dtls_cookies;

int cookie_generate_cb(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	int fd = 0;

	if ((fd = SSL_get_fd(ssl)) < 0)
		return 1;

	unsigned char ck[16] = {0};
	RAND_bytes(ck, sizeof(ck));
	dtls_cookies.emplace(fd, string(reinterpret_cast<char *>(ck), sizeof(ck)));
	memcpy(cookie, ck, sizeof(ck));
	*cookie_len = sizeof(ck);
	return 1;
}


int cookie_verify_cb(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	int fd = SSL_get_fd(ssl);

	if (fd < 0 || cookie_len > 16)
		return 0;
	if (cookie_len == 0)
		return 1;
	auto it = dtls_cookies.find(fd);

	if (it == dtls_cookies.end() || string(reinterpret_cast<const char *>(cookie), cookie_len) != it->second)
		return 0;
	return 1;
}


Server::Server(const std::string &t, const std::string &sni)
	: d_transport(t), d_sni(sni)
{
}


Server::~Server()
{
	// OpenSSL bug workaround
	//if (d_ssl_ctx)
	//	SSL_CTX_free(d_ssl_ctx);
	delete d_sock;
}


int Server::setup()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	if (d_transport == "dtls1")
		d_ssl_method = DTLS_server_method();
	else
		d_ssl_method = TLS_server_method();

	if (!d_ssl_method) {
		d_err = "Server::setup::D/TLS_server_method:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if ((d_ssl_ctx = SSL_CTX_new(d_ssl_method)) == nullptr) {
		d_err = "Server::setup::SSL_CTX_new:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}
	if (SSL_CTX_use_certificate_file(d_ssl_ctx, config::certfile.c_str(),
	    SSL_FILETYPE_PEM) != 1) {
		d_err = "Server::setup::SSL_CTX_use_certificate():";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(d_ssl_ctx, config::keyfile.c_str(),
	    SSL_FILETYPE_PEM) != 1) {
		d_err = "Server::setup::SSL_CTX_use_PrivateKey_file():";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	long op = SSL_OP_SINGLE_DH_USE|SSL_OP_SINGLE_ECDH_USE|SSL_OP_NO_TICKET|SSL_OP_NO_QUERY_MTU;

#ifdef SSL_OP_NO_COMPRESSION
	op |= SSL_OP_NO_COMPRESSION;
#endif

	if ((unsigned long)(SSL_CTX_set_options(d_ssl_ctx, op) & op) != (unsigned long)op) {
		d_err = "Server::setup::SSL_CTX_set_options():";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	int min_vers = TLS1_3_VERSION;

	if (d_transport == "dtls1") {
		min_vers = DTLS1_2_VERSION;
#ifdef HAVE_DTLS_LISTEN
		SSL_CTX_set_cookie_generate_cb(d_ssl_ctx, cookie_generate_cb);
		SSL_CTX_set_cookie_verify_cb(d_ssl_ctx, cookie_verify_cb);
#endif
	}

	if (SSL_CTX_set_min_proto_version(d_ssl_ctx, min_vers) != 1) {
		d_err = "Server::setup::SSL_CTX_set_min_proto_version():";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	// check for DHE and enable it if there are parameters
	string::size_type dhe = ciphers.find("kDHE");
	if (dhe != string::npos) {
		if (enable_dh(d_ssl_ctx) != 1)
			ciphers.erase(dhe, 4);
	}

	if (SSL_CTX_set_cipher_list(d_ssl_ctx, ciphers.c_str()) != 1) {
		d_err = "Server::setup::SSL_CTX_set_cipher_list:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if (config::v6)
		d_sock = new (nothrow) Socket(PF_INET6, d_transport == "tls1" ? SOCK_STREAM : SOCK_DGRAM);
	else
		d_sock = new (nothrow) Socket(PF_INET, d_transport == "tls1" ? SOCK_STREAM : SOCK_DGRAM);

	if (!d_sock || !d_sock->is_good()) {
		d_err = "Server::setup::new:";
		return -1;
	}

	return 0;
}


int Server::loop()
{
	pid_t pid = 0;
	int peer_fd = -1;
	struct sockaddr *from = nullptr;
	struct sockaddr_in from4;
	struct sockaddr_in6 from6;
	socklen_t flen = 0;
	string msg = "";
	char dst[128] = {0};
	time_t now = time(nullptr) - 42, last_accept = 0;
	unsigned short port = 0;
	int type = d_transport == "tls1" ? SOCK_STREAM : SOCK_DGRAM;

	if (config::v6) {
		from = reinterpret_cast<struct sockaddr *>(&from6);
		flen = sizeof(from6);
	} else {
		from = reinterpret_cast<struct sockaddr *>(&from4);
		flen = sizeof(from4);
	}

	if (!d_sock || !d_sock->is_good()) {
		d_err = "Server::loop: Server not initialized!";
		return -1;
	}

	// No host -> passive
	if (config::host.empty()) {
		if ((d_sock_fd = d_sock->blisten(config::laddr, config::lport)) < 0) {
			d_err = "Server::loop::";
			d_err += d_sock->why();
			return -1;
		}

		for (;;) {

			if (type == SOCK_DGRAM) {
				char c = 0;
				last_accept = now;
				if (recvfrom(d_sock_fd, &c, 1, MSG_PEEK, from, &flen) <= 0)
					continue;

				now = time(nullptr);

				// TLS Record Layer: ContentType == handshake (22)
				if (now - last_accept <= d_min_time_between_reconnect || c != 22) {
					char buf[4096] = {0};
					recv(d_sock_fd, buf, sizeof(buf), 0);
					continue;
				}

				// dup() it, to emulate kind of accept() and we do not need to handle DGRAM differently in child
				peer_fd = dup(d_sock_fd);

				// in UDP mode, set the address where data is sent from and received from
				// via read/write and all other datagrams are ignored on receipt
				if (connect(peer_fd, from, flen) != 0) {
					msg = "Failed to set default dst of new UDP connection.";
					syslog().log(msg);
					close(peer_fd);
					continue;
				}
			} else {
				last_accept = now;
				peer_fd = accept(d_sock_fd, from, &flen);
				if (peer_fd < 0)
					continue;

				// brand new D/DoS protection :-)
				now = time(nullptr);
				if (now - last_accept <= d_min_time_between_reconnect) {
					if (config::v6) {
						if (!is_good_ip(from6.sin6_addr)) {
							close(peer_fd);
							continue;
						}
					} else {
						if (!is_good_ip(from4.sin_addr)) {
							close(peer_fd);
							continue;
						}
					}
				}
			}

			if ((pid = fork()) == 0) {
				close(d_sock_fd);

				if (config::v6) {
					inet_ntop(AF_INET6, &from6.sin6_addr, dst, sizeof(dst));
					port = ntohs(from6.sin6_port);
				} else {
					inet_ntop(AF_INET, &from4.sin_addr, dst, sizeof(dst));
					port = ntohs(from4.sin_port);
				}
				msg = "New connection from [";
				msg += dst;
				snprintf(dst, sizeof(dst), "]:%hu", port);
				msg += dst;
				syslog().log(msg);

				server_session *s = new (nothrow) server_session(peer_fd, d_transport, d_sni);
				if (!s) {
					syslog().log("out of memory");
					close(peer_fd);
					exit(1);
				}
				if (s->handle(d_ssl_ctx) < 0) {
					string l = "FAIL: ";
					l += s->why();
					syslog().log(l);
				}
				syslog().log("closing connection");
				delete s;
				exit(0);
			}

			close(peer_fd);
			if (type == SOCK_STREAM)
				continue;

			// DGRAM sockets must be closed and re-bound, as the connect() on dup-ed peer_fd also changed state
			// of d_sock_fd. recycle() handles that.
			if (d_sock->recycle() < 0 || (d_sock_fd = d_sock->blisten(config::laddr, config::lport)) < 0) {
				d_err = "Server::loop::";
				d_err += d_sock->why();
				return -1;
			}
		}

	// target host was given -> active connect
	} else if (d_transport == "tls1") {
		if (d_sock->blisten(config::laddr, config::lport, 0) < 0) {
			d_err = "Server::loop::";
			d_err += d_sock->why();
			return -1;
		}
		if (!config::socks5_connect_proxy.empty())
			d_sock->socks5(config::socks5_connect_proxy, config::socks5_connect_proxy_port);
		if ((d_sock_fd = d_sock->connect(config::host, config::port)) < 0) {
			d_err = "Server::loop::";
			d_err += d_sock->why();
			return -1;
		}
		server_session *s = new (nothrow) server_session(d_sock_fd, d_transport, d_sni);
		if (s)
			s->handle(d_ssl_ctx);
		delete s;
	} else {
		d_err = "Server::loop: Not possible to use active connect as server in UDP mode.";
		return -1;
	}
	return 0;
}

}

