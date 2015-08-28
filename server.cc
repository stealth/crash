/*
 * Copyright (C) 2009-2014 Sebastian Krahmer.
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
#include <string>
#include <stdlib.h>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <iostream>
#include <sys/time.h>
#include "session.h"
#include "server.h"
#include "config.h"
#include "log.h"
#include "net.h"
#include "misc.h"


using namespace std;

extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}

using namespace std;

unsigned short Server::min_time_between_reconnect = 3;


#ifdef USE_SCIPHERS
string ciphers = USE_SCIPHERS;
#else
string ciphers = "!LOW:!EXP:!MD5:!CAMELLIA:!RC4:!MEDIUM:!DES:!3DES:!ADH:kDHE:RSA:AES256:AESGCM:SHA256:SHA384:@STRENGTH";
#endif

extern int enable_dh(SSL_CTX *);


Server::Server()
	: sock_fd(-1), sock(NULL), ssl_method(NULL), ssl_ctx(NULL)
{
}


Server::~Server()
{
	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);
	delete sock;
}


int Server::setup()
{
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_digests();
	ssl_method = SSLv23_server_method();

	if (!ssl_method) {
		err = "Server::setup::SSLv23_server_method:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if ((ssl_ctx = SSL_CTX_new(ssl_method)) == NULL) {
		err = "Server::setup::SSL_CTX_new:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	if (SSL_CTX_use_certificate_file(ssl_ctx, config::certfile.c_str(),
	    SSL_FILETYPE_PEM) != 1) {
		err = "Server::setup::SSL_CTX_use_certificate():";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, config::keyfile.c_str(),
	    SSL_FILETYPE_PEM) != 1) {
		err = "Server::setup::SSL_CTX_use_PrivateKey_file():";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	long op = SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_SINGLE_DH_USE|SSL_OP_NO_TICKET;

#ifdef SSL_OP_NO_COMPRESSION
	op |= SSL_OP_NO_COMPRESSION;
#endif

	if ((SSL_CTX_set_options(ssl_ctx, op) & op) != op) {
		err = "Server::setup::SSL_CTX_set_options():";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	// check for DHE and enable it if there are parameters
	string::size_type dhe = ciphers.find("kDHE");
	if (dhe != string::npos) {
		if (enable_dh(ssl_ctx) != 1)
			ciphers.erase(dhe, 4);
	}

	if (SSL_CTX_set_cipher_list(ssl_ctx, ciphers.c_str()) != 1) {
		err = "Server::setup::SSL_CTX_set_cipher_list:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if (config::v6)
		sock = new (nothrow) Socket(PF_INET6);
	else
		sock = new (nothrow) Socket(PF_INET);

	if (!sock) {
		err = "Server::setup::new:";
		return -1;
	}

	return 0;
}


int Server::loop()
{
	int peer_fd;
	struct sockaddr *from = NULL;
	struct sockaddr_in from4;
	struct sockaddr_in6 from6;
	socklen_t flen = 0;
	string msg = "";
	char dst[128];
	time_t now = time(NULL) - 42, last_accept = 0;
	unsigned short port = 0;

	if (config::v6) {
		from = (struct sockaddr *)&from6;
		flen = sizeof(from6);
	} else {
		from = (struct sockaddr *)&from4;
		flen = sizeof(from4);
	}

	if (!sock) {
		err = "Server::loop: Server not initialized!";
		return -1;
	}

	// No host -> passive
	if (config::host.length() == 0) {
		sock_fd = sock->blisten(strtoul(config::port.c_str(), NULL, 10));
		if (sock_fd < 0) {
			err = "Server::loop::";
			err += sock->why();
			return -1;
		}
		for (;;) {
			last_accept = now;
			peer_fd = accept(sock_fd, from, &flen);
			if (peer_fd < 0)
				continue;

			// brand new D/DoS protection :-)
			now = time(NULL);
			if (now - last_accept <= 1) {
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

			if (fork() == 0) {
				close(sock_fd);
				if (config::v6) {
					inet_ntop(AF_INET6, &from6.sin6_addr, dst, sizeof(dst));
					port = ntohs(from6.sin6_port);
				} else {
					inet_ntop(AF_INET, &from4.sin_addr, dst, sizeof(dst));
					port = ntohs(from4.sin_port);
				}
				msg = "New connection from ";
				msg += dst;
				snprintf(dst, sizeof(dst), "p%hu", port);
				msg += dst;
				syslog().log(msg);

				server_session *s = new (nothrow) server_session(peer_fd, ssl_ctx);
				if (!s) {
					syslog().log("out of memory");
					exit(1);
				}
				if (s->handle() < 0) {
					string l = "FAIL: ";
					l += s->why();
					syslog().log(l);
				}
				syslog().log("closing connection");
				sleep(1);
				delete s;
				exit(0);
			}
			close(peer_fd);
		}
	} else {
		if (config::local_port.length() > 0)
			sock->blisten(strtoul(config::local_port.c_str(), NULL, 10), 0);
		sock_fd = sock->connect(config::host, config::port);
		if (sock_fd < 0) {
			err = "Server::loop::";
			err += sock->why();
			return -1;
		}
		server_session *s = new (nothrow) server_session(sock_fd, ssl_ctx);
		if (s)
			s->handle();
		sleep(1);
		delete s;
	}
	return 0;
}


