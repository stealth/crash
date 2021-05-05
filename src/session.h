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

#ifndef crash_session_h
#define crash_session_h

#include <poll.h>
#include <unistd.h>
#include <string>
#include <sys/types.h>

#include "misc.h"
#include "iobox.h"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/evp.h>
}


namespace crash {


class server_session {

	static std::string d_banner;

	std::string d_err{""};

	int d_sock{-1}, d_max_fd{0}, d_stdin_closed{0};
	SSL *d_ssl{nullptr};
	SSL_CTX *d_ssl_ctx{nullptr};
	EVP_PKEY *d_pubkey{nullptr};

	std::string d_user{""}, d_cmd{""}, d_home{""}, d_shell{""};

	iobox d_iob;

	state *d_fd2state{nullptr};

	pollfd *d_pfds{nullptr};


	uid_t d_final_uid{0xffff};
	char d_peer_ip[64]{0};

protected:

	int handle_input(int);

	int authenticate();

public:

	server_session(int, SSL_CTX *);

	~server_session();

	int handle();

	const char *why()
	{
		return d_err.c_str();
	}
};

}

#endif

