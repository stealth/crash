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

#include <string>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include "net.h"

using namespace std;


Socket::Socket(int pf)
{
	// PF_ and AF_ constants *might* be equal
	if (pf == PF_INET)
		family = AF_INET;
	else if (pf == PF_INET6)
		family = AF_INET6;
	else
		family = 0;

	if ((sock_fd = socket(pf, SOCK_STREAM, 0)) < 0) {
		error = "Socket::socket:";
		error += strerror(errno);
		throw;
	}
}


Socket::~Socket()
{
	close(sock_fd);
}


int Socket::blisten(unsigned short port, bool do_listen)
{
	int one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr *sin = NULL;
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
	socklen_t slen = 0;
	if (family == AF_INET) {
		memset(&sin4, 0, sizeof(sin4));
		sin4.sin_port = htons(port);
		sin4.sin_family = AF_INET;
		sin4.sin_addr.s_addr = INADDR_ANY;
		sin = (struct sockaddr *)&sin4;
		slen = sizeof(sin4);
	} else if (family == AF_INET6) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_port = htons(port);
		sin6.sin6_family = AF_INET6;
		//sin6.sin6_addr = in6addr_any;
		sin = (struct sockaddr *)&sin6;
		slen = sizeof(sin6);
	} else {
		error = "Socket::bind:unknown family type!";
		return -1;
	}

	if (bind(sock_fd, sin, slen) < 0) {
		error = "Socket::bind:";
		error += strerror(errno);
		return -1;
	}

	if (do_listen) {
		if (listen(sock_fd, 12) < 0) {
			error = "Socket::listen:";
			error += strerror(errno);
			return -1;
		}
	}

	return sock_fd;
}


int Socket::connect(const string &host, const string &port)
{
	int r = 0;
	struct addrinfo hint, *ai = NULL;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = family;
	hint.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo(host.c_str(), port.c_str(), &hint, &ai)) < 0) {
		error = "Socket::getaddrinfo:";
		error += gai_strerror(r);
		return -1;
	}

	if (::connect(sock_fd, ai->ai_addr, ai->ai_addrlen) < 0) {
		error = "Socket::connect:";
		error += strerror(errno);
		return -1;
	}

	return sock_fd;
}


