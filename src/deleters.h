/*
 * Copyright (C) 2016 Sebastian Krahmer.
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


#ifndef crash_deleters_h
#define crash_deleters_h

extern "C" {
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
}

#include <cstdio>

extern "C" typedef void (*EVP_PKEY_del)(EVP_PKEY *);

extern "C" typedef void (*EVP_PKEY_CTX_del)(EVP_PKEY_CTX *);

extern "C" typedef void (*EVP_MD_CTX_del)(EVP_MD_CTX *);

extern "C" typedef void (*EVP_CIPHER_CTX_del)(EVP_CIPHER_CTX *);

extern "C" typedef void (*DH_del)(DH *);

extern "C" typedef void (*RSA_del)(RSA *);

extern "C" typedef int (*BIO_del)(BIO *);

extern "C" typedef void (*BIGNUM_del)(BIGNUM *);

extern "C" typedef void (*BN_CTX_del)(BN_CTX *);

extern "C" typedef void (*BN_GENCB_del)(BN_GENCB *);

extern "C" typedef void (*EC_GROUP_del)(EC_GROUP *);

extern "C" typedef void (*EC_KEY_del)(EC_KEY *);

extern "C" typedef int (*FILE_del)(FILE *);

extern "C" typedef void (*free_del)(void *);


#endif
