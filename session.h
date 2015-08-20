/*
 * Copyright (C) 2009-2015 Sebastian Krahmer.
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

#ifndef __session_h__
#define __session_h__

#include <sys/types.h>
#include <unistd.h>
#include <string>
#include "iobox.h"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/evp.h>
}


class server_session {
	std::string err;
	static std::string banner;
	int sock;
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	EVP_PKEY *pubkey;

	string user, cmd, home, shell;

	iobox iob;

	uid_t final_uid;
	char peer_ip[64];

protected:
	int handle_command(const std::string &, char *, unsigned short);

	int handle_data(const std::string &, char *, unsigned short);

	int authenticate();

public:

	server_session(int, SSL_CTX *);

	~server_session();

	int handle();

	int send_const_chunks(const std::string &, const char *, size_t);

	const char *why() { return err.c_str(); };

};

#endif

