/*
 * Copyright (C) 2006-2023 Sebastian Krahmer.
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
	int d_sock_fd{-1}, d_family{PF_INET}, d_type{SOCK_STREAM};

	std::string d_socks5_proxy{""}, d_socks5_port{""};
	std::string d_error{""};

	void create(int, int);

public:

	Socket(int, int);

	virtual ~Socket();

	int recycle();

	int socks5(const std::string &, const std::string &);

	int connect(const std::string &, const std::string &);

	int blisten(const std::string &, const std::string &, bool do_listen = 1);

	bool is_good() { return d_sock_fd >= 0; };

	const char *why() { return d_error.c_str(); };
};


// TCP connections can use the socket fd as id, as it uniquely identifies the connection.
// UDP sockets receive all datagrams on the same fd, so we cannot use the fd as an connection-id and therefore
// need to map the dgram's originating struct sockaddr {} (implemented as string blob) to an unqiue id,
// so that we know where to send replies to when we receive data for that id.
class udp_node2id {

	std::map<uint16_t, std::string> d_id2node;
	std::map<std::string, uint16_t> d_node2id;

	enum { max_id = 0xffff };

	uint16_t d_next_id{0};

public:

	uint16_t put(const std::string &addr)
	{
		// if origin already exists, take this ID
		auto it = d_node2id.find(addr);
		if (it != d_node2id.end())
			return it->second;

		// if there are free IDs, pick a new one
		if (d_node2id.size() <= max_id) {
			d_node2id[addr] = d_next_id;
			d_id2node[d_next_id] = addr;
			return d_next_id++;
		}

		// otherwise flush all mappings (possibly corrupt outstanding UDP sessions)
		d_node2id.clear();
		d_id2node.clear();
		d_next_id = 0;

		d_node2id[addr] = d_next_id;
		d_id2node[d_next_id] = addr;
		return d_next_id++;
	}

	std::string get(uint16_t id)
	{
		std::string ret = "";
		auto it = d_id2node.find(id);
		if (it != d_id2node.end())
			ret = it->second;

		return ret;
	}

	void del(uint16_t id)
	{
		auto it = d_id2node.find(id);
		if (it != d_id2node.end()) {
			auto it2 = d_node2id.find(it->second);	// must exist
			d_node2id.erase(it2);
			d_id2node.erase(it);
		}
	}
};


extern std::map<std::string, int> tcp_nodes2sock, udp_nodes2sock;

int tcp_listen(const std::string &, const std::string &);

int udp_listen(const std::string &, const std::string &);

int tcp_connect(const std::string &, const std::string &);

int udp_connect(const std::string &, const std::string &);


struct alignas(1) v4_tuple {
	in_addr dst;
	uint16_t dport;
} __attribute__((packed));


struct alignas(1) v6_tuple {
	in6_addr dst;
	uint16_t dport;
} __attribute__((packed));


struct alignas(1) name_tuple {
	uint8_t nlen;
	char name[255 + 2];	// +2 for dst port
} __attribute__((packed));


struct alignas(1) socks5_req {
	uint8_t vers, cmd, mbz, atype;
	union {
		v4_tuple v4;
		v6_tuple v6;
		name_tuple name;
	};
} __attribute__((packed));


struct alignas(1) socks4_req {
	uint8_t ver, cmd;
	uint16_t dport;
	uint32_t dst;
	uint8_t id;
} __attribute__((packed));


}

#endif

