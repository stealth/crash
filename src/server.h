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
#ifndef crash_server_h
#define crash_server_h

#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <utility>
#include <string>
#include <atomic>
#include <map>
#include "net.h"
#include "log.h"

extern "C" {
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
}

namespace crash {

class Server {

	int d_sock_fd{-1};
	Socket *d_sock{nullptr};
	std::string d_transport{"tls1"}, d_sni{""}, d_err{""};

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *d_ssl_method{nullptr};
#else
	SSL_METHOD *d_ssl_method{nullptr};
#endif
	SSL_CTX *d_ssl_ctx{nullptr};

	std::map<std::string, time_t> d_connects;
	static unsigned short d_min_time_between_reconnect;

	static std::atomic<int> sigchld_mtx;
	static int sigchld_idx;
	enum { MAX_CHLDS = 32 };
	static std::pair<pid_t, struct timeval> sigchld_pids[MAX_CHLDS];

public:

	Server(const std::string &, const std::string &);

	~Server();

	// These need to be in Server{} because its running privileged, so
	// the release cann ::logout() the PIDs from the utmx files
	static void add_chld(pid_t);

	static void release_chlds();

	const char *why() { return d_err.c_str(); };

	int setup();

	int loop();
};

}

#endif

