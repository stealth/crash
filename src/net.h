/*
 * Copyright (C) 2006-2021 Sebastian Krahmer.
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
#ifndef crash_net_h
#define crash_net_h

#include <map>
#include <string>
#include <cstdint>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "misc.h"


namespace crash {

class Socket {
protected:
	int sock_fd, family;
	std::string error;

public:

	Socket(int);

	virtual ~Socket();

	int connect(const std::string &, const std::string &);

	int blisten(unsigned short port, bool do_listen = 1);

	const char *why() { return error.c_str(); };

};



extern std::map<std::string, int> tcp_nodes2sock, udp_nodes2sock;

int tcp_listen(const std::string &, const std::string &);

int udp_listen(const std::string &, const std::string &);

int net_cmd_handler(const std::string &, state *, pollfd *, uint32_t flags = 0);

struct alignas(4) v4_tuple {
	in_addr dst;
	uint16_t dport;
};

struct alignas(4) v6_tuple {
	in6_addr dst;
	uint16_t dport;
};

struct socks5_req {
	uint8_t vers, cmd, mbz, atype;
	union alignas(4) {
		v4_tuple v4;
		v6_tuple v6;
	};
};	// no __attribute__((packed)) needed, as its properly aligned


struct socks4_req {
	uint8_t ver, cmd;
	uint16_t dport;
	uint32_t dst;
	uint8_t id;
};


}

#endif

