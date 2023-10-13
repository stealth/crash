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
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <memory>
#include <netdb.h>
#include <poll.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "net.h"
#include "misc.h"


using namespace std;

namespace crash {


Socket::Socket(int pf, int type = SOCK_STREAM)
{
	create(pf, type);
}


void Socket::create(int pf, int type)
{
	// PF_ and AF_ constants *might* be equal
	if (pf == PF_INET || pf == AF_INET)
		d_family = AF_INET;
	else if (pf == PF_INET6 || pf == AF_INET6)
		d_family = AF_INET6;
	else
		d_family = 0;

	d_type = type;

	if ((d_sock_fd = socket(d_family, d_type, 0)) < 0) {
		d_error = "Socket::socket:";
		d_error += strerror(errno);
		return;
	}

	if (d_type == SOCK_STREAM) {
		int one = 1;
		socklen_t len = sizeof(one);
		setsockopt(d_sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, len);
	} else {
		int r = 2*1024*1024, s = r/4;
		setsockopt(d_sock_fd, SOL_SOCKET, SO_RCVBUF, &r, sizeof(r));
		setsockopt(d_sock_fd, SOL_SOCKET, SO_SNDBUF, &s, sizeof(s));
	}
}


int Socket::recycle()
{
	close(d_sock_fd);
	create(d_family, d_type);
	return is_good() ? 0 : -1;
}


Socket::~Socket()
{
	close(d_sock_fd);
}


int Socket::blisten(const string &laddr, const string &lport, bool do_listen, bool do_reuse)
{
	int r = 0;

	if (do_reuse) {
		int one = 1;
		setsockopt(d_sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}

	struct addrinfo hint = {0}, *tai = nullptr;

	hint.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	hint.ai_socktype = d_type;
	hint.ai_family = d_family;

	if ((r = getaddrinfo(laddr.c_str(), lport.c_str(), &hint, &tai)) != 0) {
		d_error = "Socket::blisten::getaddrinfo:";
		d_error += gai_strerror(r);
		return -1;
	}

	unique_ptr<addrinfo, decltype(&freeaddrinfo)> ai(tai, freeaddrinfo);

	if (::bind(d_sock_fd, ai->ai_addr, ai->ai_addrlen) < 0) {
		d_error = "Socket::bind:";
		d_error += strerror(errno);
		return -1;
	}

	if (d_type == SOCK_STREAM && do_listen) {
		if (listen(d_sock_fd, 12) < 0) {
			d_error = "Socket::listen:";
			d_error += strerror(errno);
			return -1;
		}
	}

	return d_sock_fd;
}


int Socket::socks5(const string &proxy, const string &port)
{

	if (d_type != SOCK_STREAM)
		return -1;

	d_socks5_proxy = proxy;
	d_socks5_port = port;

	if (port.empty())
		d_socks5_port = "5555";

	return 0;
}


int Socket::connect(const string &host, const string &port)
{
	int r = 0;
	struct addrinfo hint = {0}, *tai = nullptr;

	hint.ai_flags = AI_NUMERICSERV;
	hint.ai_socktype = d_type;
	hint.ai_family = d_family;

	string next_host = host, next_port = port;

	if (!d_socks5_proxy.empty()) {

		if (host.size() > 255) {
			d_error = "Socket::connect::host name size too large for SOCKS5 request";
			return -1;
		}
		hint.ai_socktype = SOCK_STREAM;
		next_host = d_socks5_proxy;
		next_port = d_socks5_port;
	}

	if ((r = getaddrinfo(next_host.c_str(), next_port.c_str(), &hint, &tai)) != 0) {
		d_error = "Socket::connect::getaddrinfo:";
		d_error += gai_strerror(r);
		return -1;
	}

	unique_ptr<addrinfo, decltype(&freeaddrinfo)> ai(tai, freeaddrinfo);

	if (::connect(d_sock_fd, ai->ai_addr, ai->ai_addrlen) < 0) {
		d_error = "Socket::connect:";
		d_error += strerror(errno);
		return -1;
	}

	if (!d_socks5_proxy.empty()) {

		// SOCKS5 greeting
		struct alignas(1) {
			uint8_t vers, nauth, auth;
		} s5_g = {5, 1, 0}, s5_g_resp = {0, 0, 0};

		if (writen(d_sock_fd, &s5_g, sizeof(s5_g)) != sizeof(s5_g)) {
			d_error = "Socket::connect::write (SOCKS5):";
			d_error += strerror(errno);
			return -1;
		}

		// auth not supported
		if (read(d_sock_fd, &s5_g_resp, 2) != 2 || s5_g_resp.nauth != 0) {
			d_error = "Socket::connect::read (SOCKS5):";
			d_error += strerror(errno);
			return -1;
		}

		struct socks5_req s5_c = {0}, s5_c_resp = {0};

		s5_c.vers = 0x5;
		s5_c.cmd = 1;
		s5_c.atype = 3;		// DNS name, may also be IP string

		s5_c.name.nlen = (uint8_t)host.size();
		memcpy(s5_c.name.name, host.c_str(), s5_c.name.nlen);
		uint16_t p = htons((uint16_t)stoul(port));
		memcpy(s5_c.name.name + s5_c.name.nlen, &p, sizeof(p));

		ssize_t req_len = 5*sizeof(uint8_t) + s5_c.name.nlen + sizeof(uint16_t);
		if (writen(d_sock_fd, &s5_c, req_len) != req_len) {
			d_error = "Socket::connect::write (SOCKS5):";
			d_error += strerror(errno);
			return -1;
		}

		// len for IPv4 bound SOCKS servers (see below)
		ssize_t resp_len = 4*sizeof(uint8_t);	// + sizeof(s5_c_resp.v4);

		// Workaround for buggy OpenSSH SOCKS5 server: Even if bound to IPv6 address,
		// it will answer with a bound address of type IPv4. So we can't pre-compute the
		// required response len :(
		//if (d_family == AF_INET6)
		//	resp_len = 4*sizeof(uint8_t) + sizeof(s5_c_resp.v6);

		if (read(d_sock_fd, &s5_c_resp, resp_len) != resp_len || s5_c_resp.cmd != 0) {
			d_error = "Socket::connect::read (SOCKS5):";
			d_error += strerror(errno);
			return -1;
		}

		ssize_t remain = 0;
		if (s5_c_resp.atype == 1)	// IPv4
			remain = sizeof(s5_c_resp.v4);
		else
			remain = sizeof(s5_c_resp.v6);

		char dummy[sizeof(s5_c_resp.v4) + sizeof(s5_c_resp.v6)] = {0};
		if (read(d_sock_fd, dummy, remain) != remain) {
			d_error = "Socket::connect::read (SOCKS5):";
			d_error += strerror(errno);
			return -1;
		}
	}

	return d_sock_fd;
}


// maps "IP/port/ID/" string to actual socket, so that we know
// which socket the tagged cmd data belongs to, which carries IP/port pair in front
map<string, int> tcp_nodes2sock, udp_nodes2sock;


static int listen(int type, const string &ip, const string &port)
{
	int r = 0, sock_fd = -1;

	addrinfo hint = {0}, *tai = nullptr;
	hint.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;
	hint.ai_socktype = type;

	if ((r = getaddrinfo(ip.c_str(), port.c_str(), &hint, &tai)) < 0)
		return -1;

	unique_ptr<addrinfo, decltype(&freeaddrinfo)> ai(tai, freeaddrinfo);

	if ((sock_fd = socket(ai->ai_family, type, 0)) < 0)
		return -1;

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	int one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if (::bind(sock_fd, ai->ai_addr, ai->ai_addrlen) < 0)
		return -1;
	if (type == SOCK_STREAM) {
		if (::listen(sock_fd, 12) < 0)
			return -1;
	}

	return sock_fd;
}


int udp_listen(const string &ip, const string &port)
{
	return listen(SOCK_DGRAM, ip, port);
}


int tcp_listen(const string &ip, const string &port)
{
	return listen(SOCK_STREAM, ip, port);
}


static map<string, struct addrinfo *> resolv_cache;


static int connect(int type, const string &name, const string &port)
{

	// if cache has grown largely, drop it and make new
	if (resolv_cache.size() > 1024) {
		for (const auto &it : resolv_cache)
			freeaddrinfo(it.second);
		resolv_cache.clear();
	}

	int r = 0, sock_fd = -1, one = 1;
	socklen_t len = sizeof(one);

	addrinfo hint = {0}, *tai = nullptr;
	hint.ai_socktype = type;
	hint.ai_flags = AI_NUMERICHOST|AI_NUMERICSERV;

	bool can_free = 1;

	if ((r = getaddrinfo(name.c_str(), port.c_str(), &hint, &tai)) != 0) {

		can_free = 0;

		string key = name + ":" + port;

		auto it = resolv_cache.find(key);

		if (it == resolv_cache.end()) {

			hint.ai_flags = AI_NUMERICSERV;
			if ((r = getaddrinfo(name.c_str(), port.c_str(), &hint, &tai)) != 0)
				return -1;

			resolv_cache[key] = tai;

		} else
			tai = it->second;
	}

	if ((sock_fd = socket(tai->ai_family, type, 0)) < 0) {
		if (can_free)
			freeaddrinfo(tai);
		return -1;
	}

	if (type == SOCK_STREAM)
		setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, len);

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	if (::connect(sock_fd, tai->ai_addr, tai->ai_addrlen) < 0 && errno != EINPROGRESS) {
		close(sock_fd);
		if (can_free)
			freeaddrinfo(tai);
		return -1;
	}

	return sock_fd;
}


int udp_connect(const string &ip, const string &port)
{
	return connect(SOCK_DGRAM, ip, port);
}


int tcp_connect(const string &ip, const string &port)
{
	return connect(SOCK_STREAM, ip, port);
}


}

