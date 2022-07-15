/*
 * Copyright (C) 2014-2021 Sebastian Krahmer.
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

#include <memory>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/bn.h>

#include "dh2048.cc"

namespace crash {

#if OPENSSL_VERSION_NUMBER < 0x30000000

static DH *dh2048 = nullptr;


DH *dh_callback(SSL *ssl, int is_exported, int keylen)
{
	return dh2048;
}

#endif

int enable_dh(SSL_CTX *ctx)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000

	EVP_PKEY *evp_dh = nullptr;
	std::unique_ptr<BIO, decltype(&BIO_free)> bio{
		BIO_new_mem_buf(pem_dh.c_str(), pem_dh.size()),
		BIO_free
	};
	if (!bio.get() || PEM_read_bio_Parameters(bio.get(), &evp_dh) == nullptr)
		return 0;
	SSL_CTX_set0_tmp_dh_pkey(ctx, evp_dh);
	return 1;
#else
	if ((dh2048 = get_dh2048()) != nullptr) {
		SSL_CTX_set_tmp_dh_callback(ctx, dh_callback);
		return 1;
	}
	return 0;
#endif
}

}

