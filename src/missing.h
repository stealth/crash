#ifndef crash_missing_h
#define crash_missing_h

extern "C" {
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
}

#if OPENSSL_VERSION_NUMBER > 0x10100000L && !(defined LIBRESSL_VERSION_NUMBER) && !(defined BORINGSSL_API_VERSION)
#define EVP_MD_CTX_delete EVP_MD_CTX_free
#else
#define EVP_MD_CTX_delete EVP_MD_CTX_destroy
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define EVP_PKEY_cmp EVP_PKEY_eq
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L || LIBRESSL_VERSION_NUMBER >= 0x30000000L
#ifndef NO_DTLS_LISTEN
#define HAVE_DTLS_LISTEN
#endif
#endif

#ifdef LIBRESSL_VERSION_NUMBER

// dirty, but libressl is behind with their API
#include <netinet/in.h>
#include <arpa/inet.h>

union BIO_ADDR {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;
};

int BIO_ADDR_rawmake(BIO_ADDR *, int, const void *, size_t, unsigned short);

BIO_ADDR *BIO_ADDR_new();

void BIO_ADDR_free(BIO_ADDR *);

#endif


#endif

