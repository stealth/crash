#include <memory>
#include <cstring>
#include "missing.h"

extern "C" {
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

}


