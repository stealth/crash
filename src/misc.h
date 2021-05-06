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

#ifndef crash_misc_h
#define crash_misc_h

#include <string>
#include <cstdint>
#include <deque>
#include <time.h>
#include <netinet/in.h>

namespace crash {


enum {
	STATE_INVALID		=	0,
	STATE_PTY		=	1,
	STATE_STDIN		=	2,
	STATE_STDOUT		=	3,
	STATE_STDERR		=	4,
	STATE_SSL		=	5,

	STATE_ACCEPT		=	6,
	STATE_CONNECT		=	7,
	STATE_CONNECTED		=	8,
	STATE_CLOSING		=	9,
	STATE_UDPCLIENT		=	10,
	STATE_UDPSERVER		=	11,
	STATE_SOCKS5_ACCEPT	=	12,
	STATE_SOCKS5_AUTH1	=	13,
	STATE_SOCKS5_AUTH2	=	14,
	STATE_SOCKS4_ACCEPT	=	15,
	STATE_SOCKS4_AUTH	=	16,

	CLOSING_TIME		=	10,
	CONNECT_TIME		=	30,
	UDP_CLOSING_TIME	=	120,

	MTU			=	1500,
	MSG_BSIZE		=	1024,
	CHUNK_SIZE		=	MTU,

	NETCMD_SEND_ALLOW	=	1,

	TRAFFIC_NOPAD		=	0x00001,
	TRAFFIC_PAD1		=	0x00002,
	TRAFFIC_PADMAX		=	0x00004,
	TRAFFIC_PING_IGN	=	0x01000,
	TRAFFIC_INJECT		=	0x10000

};

struct state {
	time_t time{0};
	int fd{-1};
	int state{STATE_INVALID};
	std::string obuf{""}, ibuf{""}, rnode{""};

	// must only be pushed/popped in pairs. Each reply datagram needs a port on 127.0.0.1
	// where it is sent to
	std::deque<std::string> odgrams;
	std::deque<uint16_t> ulports;
};


std::string slen(unsigned short);

int writen(int fd, const void *buf, size_t len);

int readn(int fd, void *buf, size_t len);

int flush_fd(int, std::string &);

void pad_nops(std::string &);

std::string ping_packet();

void sig_winch(int);

int read_keys_from_file(const std::string &);

void read_until(const char *, const char *);

std::string extract_keys(const char *);

void read_good_ips(const std::string &);

bool is_good_ip(const struct in_addr &);

bool is_good_ip(const struct in6_addr &);

bool is_nologin(const std::string &);

}

#endif

