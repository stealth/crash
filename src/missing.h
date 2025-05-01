#ifndef crash_missing_h
#define crash_missing_h

#include <cstdint>
#include <sys/time.h>

extern "C" {
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#ifdef HAVE_QUIC
#include <openssl/quic.h>
#endif

}

namespace crash {

#if OPENSSL_VERSION_NUMBER > 0x10100000L && !(defined LIBRESSL_VERSION_NUMBER) && !(defined BORINGSSL_API_VERSION)
#define EVP_MD_CTX_delete EVP_MD_CTX_free
#else
#define EVP_MD_CTX_delete EVP_MD_CTX_destroy
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L || LIBRESSL_VERSION_NUMBER >= 0x30000000L
#ifndef NO_DTLS_LISTEN
#define HAVE_DTLS_LISTEN
#endif
#endif

#ifdef LIBRESSL_VERSION_NUMBER

// dirty, but libressl is behind with their API
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

union BIO_ADDR {
	struct sockaddr sa;
	struct sockaddr_in sa_in;
	struct sockaddr_in6 sa_in6;
};

#endif

int BIO_ADDR_rawmake(BIO_ADDR *, int, const void *, size_t, unsigned short);

BIO_ADDR *BIO_ADDR_new();

void BIO_ADDR_free(BIO_ADDR *);

int EVP_PKEY_cmp(const EVP_PKEY *, const EVP_PKEY *);

const SSL_METHOD *OSSL_QUIC_client_method();

const SSL_METHOD *OSSL_QUIC_server_method();

int SSL_set_blocking_mode(SSL *, int);

int SSL_set_alpn_protos(SSL *, const unsigned char *, unsigned int);

int SSL_set1_initial_peer_addr(SSL *, const BIO_ADDR *);

int SSL_handle_events(SSL *);

int SSL_net_read_desired(SSL *);

int SSL_net_write_desired(SSL *);

SSL *SSL_new_listener(SSL_CTX *, uint64_t);

int SSL_listen(SSL *);

void SSL_CTX_set_alpn_select_cb(SSL_CTX *, int (*) (SSL *ssl, const unsigned char **, unsigned char *, const unsigned char *, unsigned int, void *), void *);

SSL *SSL_accept_connection(SSL *, uint64_t);

int SSL_stream_conclude(SSL *, uint64_t);

int SSL_get_event_timeout(SSL *, struct timeval *, int *);

enum {
#ifdef HAVE_QUIC
	LISTENER_FLAG_NO_VALIDATE	=	SSL_LISTENER_FLAG_NO_VALIDATE
#else
	LISTENER_FLAG_NO_VALIDATE	=	0
#endif
};

}

#endif

