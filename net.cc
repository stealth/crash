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

#include <string>
#include <cerrno>
#include <cstring>
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

	int one = 1;
	socklen_t len = sizeof(one);
	setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, len);

}


Socket::~Socket()
{
	close(sock_fd);
}


int Socket::blisten(unsigned short port, bool do_listen)
{
	int one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr *sin = nullptr;
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

	if (::bind(sock_fd, sin, slen) < 0) {
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
	struct addrinfo hint, *ai = nullptr;

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


// maps "IP/port/ID/" string to actual socket, so that we know
// which socket the tagged cmd data belongs to, which carries IP/port pair in front
map<string, int> tcp_nodes2sock, udp_nodes2sock;


static int listen(int type, const string &ip, const string &port)
{
	int r = 0, sock_fd = -1;
	addrinfo hint, *tai = nullptr;
	memset(&hint, 0, sizeof(hint));
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


static int connect(int type, const string &ip, const string &port)
{
	int r = 0, sock_fd = -1, one = 1;
	socklen_t len = sizeof(one);

	addrinfo hint, *tai = nullptr;
	memset(&hint, 0, sizeof(hint));
	hint.ai_socktype = type;

	if ((r = getaddrinfo(ip.c_str(), port.c_str(), &hint, &tai)) < 0)
		return -1;

	unique_ptr<addrinfo, decltype(&freeaddrinfo)> ai(tai, freeaddrinfo);

	if ((sock_fd = socket(ai->ai_family, type, 0)) < 0)
		return -1;

	setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &one, len);

	int flags = fcntl(sock_fd, F_GETFL);
	fcntl(sock_fd, F_SETFL, flags|O_NONBLOCK);

	if (::connect(sock_fd, ai->ai_addr, ai->ai_addrlen) < 0 && errno != EINPROGRESS) {
		close(sock_fd);
		return -1;
	}

	return sock_fd;
}


static int udp_connect(const string &ip, const string &port)
{
	return connect(SOCK_DGRAM, ip, port);
}


static int tcp_connect(const string &ip, const string &port)
{
	return connect(SOCK_STREAM, ip, port);
}


/*
 * C:T:N:IP/port/ID/		-> open new TCP connection to IP:port
 * C:T:C:IP/port/ID/	  	-> connection to IP:port is estabished on remote side
 * C:T:S:IP/port/ID/data	-> send data to IP:port
 * C:T:R:IP/port/ID/data	-> data received from IP:port on remote side
 * C:T:F:IP/port/ID/		-> close connection belonging to IP:port
 *
 * C:U:S:IP/port/ID/		-> send UDP datagram to IP:port
 * C:U:R:IP/port/ID/		-> received UDP datagram from IP:port on remote side
 *
 */

int net_cmd_handler(const string &cmd, state *fd2state, pollfd *pfds, uint32_t flags)
{
	char C[16] = {0}, proto[16] = {0}, op[16] = {0}, host[128] = {0}, port[16] = {0}, id[16] = {0};
	unsigned short len = 0;
	int sock = -1;

	// ID is the logical channel to distinguish between multiple same host:port connections.
	// The accepted socket fd of the local psc part is unique and good for it.
	if (sscanf(cmd.c_str(), "%hu:%15[^:]:%15[^:]:%15[^:]:%127[^/]/%15[^/]/%15[^/]/", &len, C, proto, op, host, port, id) != 7)
		return -1;

	const string node = string(host) + "/" + string(port) + "/" + id + "/";

	if (len < 7 + node.size() || len > cmd.size() - 5)
		return -1;

	if (C[0] != 'C' || (proto[0] != 'T' && proto[0] != 'U'))
		return -1;

	// open new non-blocking connection
	if (cmd.find("C:T:N:", 6) == 6 && (flags & NETCMD_SEND_ALLOW)) {
		if ((sock = tcp_connect(host, port)) < 0)
			return -1;

		pfds[sock].revents = 0;
		pfds[sock].events = POLLOUT;
		pfds[sock].fd = sock;

		fd2state[sock].fd = sock;
		fd2state[sock].state = STATE_CONNECT;
		fd2state[sock].obuf.clear();
		fd2state[sock].odgrams.clear();
		fd2state[sock].ulports.clear();
		fd2state[sock].rnode = node;
		fd2state[sock].time = time(nullptr);

		tcp_nodes2sock[node] = sock;

	// non-blocking connect() got ready
	} else if (cmd.find("C:T:C:", 6) == 6) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;

		pfds[sock].events = POLLIN;

		fd2state[sock].fd = sock;
		fd2state[sock].state = STATE_CONNECTED;
		fd2state[sock].obuf.clear();
		fd2state[sock].odgrams.clear();
		fd2state[sock].ulports.clear();
		fd2state[sock].time = time(nullptr);

	// finish connection
	} else if (cmd.find("C:T:F:", 6) == 6) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;
		tcp_nodes2sock.erase(it);

		// flush remaining data
		if (fd2state[sock].obuf.size() > 0)
			writen(sock, fd2state[sock].obuf.c_str(), fd2state[sock].obuf.size());

		// sock will be closed in main poll() loop via timeout
		shutdown(sock, SHUT_RDWR);
		pfds[sock].fd = -1;
		pfds[sock].events = 0;

		fd2state[sock].state = STATE_CLOSING;
		fd2state[sock].obuf.clear();
		fd2state[sock].odgrams.clear();
		fd2state[sock].ulports.clear();
		fd2state[sock].time = time(nullptr);

	// Send or receive data. No NETCMD_SEND_ALLOW check, since the node will not be in
	// the tcp_nodes2sock map in the first place, as there was no tcp_connect() and no map
	// insertion.
	} else if (cmd.find("C:T:S:", 6) == 6 || cmd.find("C:T:R:", 6) == 6) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;
		pfds[sock].events |= POLLOUT;

		fd2state[sock].obuf += cmd.substr(5 + 7 + node.size(), len - 7 - node.size());	// strip off data part
		fd2state[sock].time = time(nullptr);

	} else if (cmd.find("C:U:S:", 6) == 6 || cmd.find("C:U:R:", 6) == 6) {
		auto it = udp_nodes2sock.find(node);
		if (it == udp_nodes2sock.end()) {
			if (!(flags & NETCMD_SEND_ALLOW))
				return 0;
			if ((sock = udp_connect(host, port)) < 0)
				return -1;
			udp_nodes2sock[node] = sock;

			// Just fill rnode part in server side. client main loop expects ID/ part not to be
			// appended
			fd2state[sock].rnode = node;
			fd2state[sock].state = STATE_UDPCLIENT;
			fd2state[sock].fd = sock;
		} else
			sock = it->second;

		pfds[sock].revents = 0;
		pfds[sock].fd = sock;
		pfds[sock].events = POLLIN;

		if (cmd.size() > 5 + 7 + node.size()) {
			fd2state[sock].odgrams.push_back(cmd.substr(5 + 7 + node.size(), len - 7 - node.size()));	// strip off data part (startes after "%05hu:C:U:S")
			fd2state[sock].ulports.push_back((uint16_t)strtoul(id, nullptr, 10));

			pfds[sock].events |= POLLOUT;
		}
		fd2state[sock].time = time(nullptr);
	}

	return 0;
}

}

