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
#include <termios.h>

extern "C" {
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>
}


#include "net.h"
#include "misc.h"

#ifndef crash_csession_h
#define crash_csession_h


namespace crash {


class client_session {

	int d_sock_fd{-1}, d_peer_fd{-1}, d_max_fd{0};
	Socket *d_sock{nullptr};

	std::string d_err{""};
	std::string d_sni{""}, d_sbanner{""};
	SSL_CTX *d_ssl_ctx{nullptr};

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *d_ssl_method{nullptr};
#else
	SSL_METHOD *d_ssl_method{nullptr};
#endif

	SSL *d_ssl{nullptr};
	EVP_PKEY *d_pubkey{nullptr}, *d_privkey{nullptr};

	state *d_fd2state{nullptr};

	pollfd *d_pfds{nullptr};

	struct termios d_tattr, d_old_tattr;

	uint16_t d_major{2}, d_minor{2};

	bool d_has_tty{0};

protected:

	int handle_input(int);

	int send_window_size();

	int check_server_key();

	int authenticate();

public:

	client_session(const std::string &sni)
	 : d_sni(sni)
	{
	}

	~client_session();

	int setup();

	int handle();

	const char *why()
	{
		return d_err.c_str();
	}

};


}

#endif

