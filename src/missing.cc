extern "C" {
#include <openssl/opensslv.h>
}

#ifdef LIBRESSL_VERSION_NUMBER

#include <memory>
#include <cstring>
#include "missing.h"

int BIO_ADDR_rawmake(BIO_ADDR *ap, int family, const void *where, size_t wherelen, unsigned short port)
{
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
}

BIO_ADDR *BIO_ADDR_new()
{
	return new (std::nothrow) BIO_ADDR;
}


void BIO_ADDR_free(BIO_ADDR *a)
{
	delete a;
}

#endif

