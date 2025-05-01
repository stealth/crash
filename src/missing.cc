#include <memory>
#include <cstring>
#include <sys/time.h>
#include "missing.h"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>
}


namespace crash {


int EVP_PKEY_cmp(const EVP_PKEY *a, const EVP_PKEY *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	return ::EVP_PKEY_eq(a, b);
#else
	return ::EVP_PKEY_cmp(a, b);
#endif
}


int BIO_ADDR_rawmake(BIO_ADDR *ap, int family, const void *where, size_t wherelen, unsigned short port)
{
#ifdef LIBRESSL_VERSION_NUMBER
	if (family == AF_INET) {
		memset(&ap->sa_in, 0, sizeof(ap->sa_in));
		ap->sa_in.sin_family = family;
		ap->sa_in.sin_port = port;
		memcpy(&ap->sa_in.sin_addr, where, sizeof(ap->sa_in.sin_addr));
		return 0;
	} else if (family == AF_INET6) {
		memset(&ap->sa_in6, 0, sizeof(ap->sa_in));
		ap->sa_in6.sin6_family = family;
		ap->sa_in6.sin6_port = port;
		memcpy(&ap->sa_in6.sin6_addr, where, sizeof(ap->sa_in6.sin6_addr));
		return 0;
	}
	return -1;
#else
	return ::BIO_ADDR_rawmake(ap, family, where, wherelen, port);
#endif
}

BIO_ADDR *BIO_ADDR_new()
{
#ifdef LIBRESSL_VERSION_NUMBER
	return new (std::nothrow) BIO_ADDR;
#else
	return ::BIO_ADDR_new();
#endif
}


void BIO_ADDR_free(BIO_ADDR *a)
{
#ifdef LIBRESSL_VERSION_NUMBER
	delete a;
#else
	return ::BIO_ADDR_free(a);
#endif
}


const SSL_METHOD *OSSL_QUIC_client_method()
{
#ifdef HAVE_QUIC
	return ::OSSL_QUIC_client_method();
#else
	return nullptr;
#endif
}


const SSL_METHOD *OSSL_QUIC_server_method()
{
#ifdef HAVE_QUIC
	return ::OSSL_QUIC_server_method();
#else
	return nullptr;
#endif
}


int SSL_set_blocking_mode(SSL *ssl, int b)
{
#ifdef HAVE_QUIC
	return ::SSL_set_blocking_mode(ssl, b);
#else
	return 1;	// success
#endif
}


int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos, unsigned int plen)
{
#ifdef HAVE_QUIC
	return ::SSL_set_alpn_protos(ssl, protos, plen);
#else
	return 0;	// success
#endif
}


int SSL_set1_initial_peer_addr(SSL *ssl, const BIO_ADDR *addr)
{
#ifdef HAVE_QUIC
	return ::SSL_set1_initial_peer_addr(ssl, addr);
#else
	return 1;	// success
#endif
}


int SSL_handle_events(SSL *ssl)
{
#ifdef HAVE_QUIC
	return ::SSL_handle_events(ssl);
#else
	return 1;	// success
#endif
}

int SSL_net_read_desired(SSL *ssl)
{
#ifdef HAVE_QUIC
	return ::SSL_net_read_desired(ssl);
#else
	return 0;
#endif
}


int SSL_net_write_desired(SSL *ssl)
{
#ifdef HAVE_QUIC
	return ::SSL_net_write_desired(ssl);
#else
	return 0;
#endif
}


SSL *SSL_new_listener(SSL_CTX *ctx, uint64_t flags)
{
#ifdef HAVE_QUIC
	return ::SSL_new_listener(ctx, flags);
#else
	return nullptr;
#endif
}


int SSL_listen(SSL *ssl)
{
#ifdef HAVE_QUIC
	return ::SSL_listen(ssl);
#else
	return 1;	// success
#endif
}


void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                int (*cb) (SSL *ssl,
                                           const unsigned char **out,
                                           unsigned char *outlen,
                                           const unsigned char *in,
                                           unsigned int inlen,
                                           void *arg),
                                void *arg)
{
#ifdef HAVE_QUIC
	return ::SSL_CTX_set_alpn_select_cb(ctx, cb, arg);
#else
	return;
#endif
}


SSL *SSL_accept_connection(SSL *ssl, uint64_t flags)
{
#ifdef HAVE_QUIC
	return ::SSL_accept_connection(ssl, flags);
#else
	return nullptr;
#endif
}


int SSL_stream_conclude(SSL *ssl, uint64_t flags)
{
#ifdef HAVE_QUIC
	return ::SSL_stream_conclude(ssl, flags);
#else
	return 1;	// success
#endif
}


int SSL_get_event_timeout(SSL *ssl, struct timeval *tv, int *is_infinite)
{
#ifdef HAVE_QUIC
	return ::SSL_get_event_timeout(ssl, tv, is_infinite);
#else
	return 1;	// success
#endif
}

}

