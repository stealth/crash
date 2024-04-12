/*
 * Copyright (C) 2009-2023 Sebastian Krahmer.
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

// for initgroups() etc
#ifdef __CYGWIN__
#define _BSD_SOURCE
#endif

#include <cstdio>
#include <string>
#include <cstring>
#include <ctype.h>
#include <memory>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
extern "C" {
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
}
#include <iostream>
#include "config.h"
#include "global.h"
#include "disguise.h"
#include "session.h"
#include "misc.h"
#include "pty.h"
#include "log.h"
#include "net.h"
#include "missing.h"


using namespace std;

namespace crash {


// in non-pty case, get notified about childs exit to close
// DGRAM sockets which dont return "ready for read" on select()
volatile pid_t pipe_child = 1;
volatile bool pipe_child_exited = 0;

static void sess_sig_chld(int x)
{
	pid_t pid;
	while ((pid = waitpid(-1, nullptr, WNOHANG)) > 0) {
		// pipe_child PID is local to the session process and refers to the child attatched to the PTY
		if (pid == pipe_child)
			pipe_child_exited = 1;
	}
}


server_session::server_session(int fd, const string &transport, const string &sni, const string &from)
	: session(transport, sni)
{

	d_peer_fd = fd;

	if (config::v6)
		d_family = AF_INET6;

	// in active connect case, 'from' is empty, as there was no accept/recv and the peer is config::host
	if (from.empty()) {
		d_peer_ip = config::host;
	} else {

		char dst[128] = {0};

		if (getnameinfo(reinterpret_cast<const sockaddr *>(from.c_str()), from.size(), dst, sizeof(dst) - 1, nullptr, 0, NI_NUMERICHOST|NI_NUMERICSERV) != 0)
			d_peer_ip = "?.?.?.?";
		else
			d_peer_ip = dst;
	}

	if (d_type == SOCK_DGRAM)
		d_chunk_size = UDP_CHUNK_SIZE;

	if (sni.size()) {
		d_sni = sni;
		d_banner = sni;
	}

	if (!config::no_net)
		d_net_cmd_flags = NETCMD_SEND_ALLOW;

#if !defined LIBRESSL_VERSION_NUMBER && !defined BORINGSSL_API_VERSION
	// only happens in passive case for DTLS, so no distinguish for 'from' needs to be done
	d_dlisten_param = BIO_ADDR_new();
	uint16_t fport = 0;
	const void *where = nullptr;
	size_t wlen = 0;
	if (d_family == AF_INET) {
		fport = reinterpret_cast<const sockaddr_in *>(from.c_str())->sin_port;
		where = &(reinterpret_cast<const sockaddr_in *>(from.c_str()))->sin_addr;
		wlen = sizeof(in_addr);
	} else {
		fport = reinterpret_cast<const sockaddr_in6 *>(from.c_str())->sin6_port;
		where = &(reinterpret_cast<const sockaddr_in6 *>(from.c_str()))->sin6_addr;
		wlen = sizeof(in6_addr);
	}
	crash::BIO_ADDR_rawmake(d_dlisten_param, d_family, where, wlen, fport);
#endif
}


server_session::~server_session()
{
#if !defined LIBRESSL_VERSION_NUMBER && !defined BORINGSSL_API_VERSION
	crash::BIO_ADDR_free(d_dlisten_param);
#endif

}


// == 1 if OK
int server_session::authenticate()
{
	unsigned char rand[256] = {0}, md[EVP_MAX_MD_SIZE] = {0};

	d_err = "server_session::authenticate::rand init failed";

	// Also add some entropy in the child-session, as the PRNG-state
	// is inherited from parent across fork()
	if (RAND_load_file("/dev/urandom", 16) != 16)
		return -1;
	if (RAND_bytes(rand, sizeof(rand)) != 1)
		return -1;
	unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_delete)> md_ctx{
		EVP_MD_CTX_create(),
		EVP_MD_CTX_delete
	};
	const EVP_MD *sha512 = EVP_sha512();
	if (!sha512 || !md_ctx.get())
		return -1;
	if (EVP_DigestInit_ex(md_ctx.get(), sha512, nullptr) != 1)
		return -1;
	if (EVP_DigestUpdate(md_ctx.get(), rand, sizeof(rand)) != 1)
		return -1;
	if (EVP_DigestFinal_ex(md_ctx.get(), md, nullptr) != 1)
		return -1;

	char sbuf[MSG_BSIZE] = {0};

	sprintf(sbuf, "A:crash-%hu.%04hu:sign2:rsa1:%hu:", d_major, d_minor, (unsigned short)EVP_MD_size(sha512));
	memcpy(sbuf + strlen(sbuf), md, EVP_MD_size(sha512));

	d_err = "server_session::authenticate:: auth exchange";

	// write singing-request to client
	rewrite: ssize_t n = SSL_write(d_ssl, sbuf, MSG_BSIZE);
	switch (SSL_get_error(d_ssl, n)) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		return -1;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		goto rewrite;
	default:
		d_err = "server_session::authenticate::SSL_write:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	char rbuf[MSG_BSIZE + 1] = {0}, cmdbuf[256] = {0}, ubuf[64] = {0}, token[1024] = {0};

	reread: ssize_t r = SSL_read(d_ssl, rbuf, MSG_BSIZE);
	switch (SSL_get_error(d_ssl, r)) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		return -1;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		goto reread;
	default:
		d_err = "server_session::authenticate::SSL_read:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	// start message parsing
	d_err = "server_session::authenticate::message format error";
	if (r <= 0 || rbuf[0] != 'A')
		return -1;

	unsigned short major = 0, minor = 0, cmdlen = 0;
	if (sscanf(rbuf, "A:crash-%hu.%04hu:sign2:rsa1:%32[^:]:%hu:", &major, &minor, ubuf, &cmdlen) != 4)
		return -1;

	if (cmdlen >= sizeof(cmdbuf))
		return -1;

	// find last ':'
	char *ptr = strchr(rbuf + 3, ':');
	for (int colons = 0; colons < 4; ++colons) {
		if (!ptr++)
			return -1;
		ptr = strchr(ptr, ':');
	}
	if (!ptr++)
		return -1;
	if (r - (ptr - rbuf) < (ssize_t)cmdlen)
		return -1;

	memcpy(cmdbuf, ptr, cmdlen);
	if (cmdlen)
		d_cmd = cmdbuf;

	ptr += cmdlen;
	unsigned short tlen = 0;
	if (sscanf(ptr, ":token:%hu:", &tlen) != 1)
		return -1;
	if (tlen >= sizeof(token) || tlen < 8)
		return -1;
	ptr = strchr(ptr + 7, ':');
	if (!ptr++)
		return -1;
	if (r - (ptr - rbuf) < (ssize_t)tlen)
		return -1;

	memcpy(token, ptr, tlen);
	// end message parsing

	unsigned int i = 0;
	for (; i < sizeof(ubuf); ++i) {
		// just in case isspace() doesnt like \0 :)
		if (!isspace(ubuf[i]) || ubuf[i] == 0)
			break;
	}
	d_user = &ubuf[i];
	// some basic checks
	if (d_user.length() <= 1 || d_user.find("/", 0) != string::npos ||
	    d_user.find(":", 0) != string::npos)
		d_user = "[crashd]";

	char falsch[] = "/bin/false";
	struct passwd pw, *pwp = nullptr;
	memset(&pw, 0, sizeof(pw));
	pw.pw_shell = falsch;

#ifndef ANDROID
	char pwstr[4096] = {0};
	getpwnam_r(d_user.c_str(), &pw, pwstr, sizeof(pwstr), &pwp);
#else
	pwp = getpwnam(d_user.c_str());
#endif

	// invalid user, or
	// someone without a shell, except if always_login switch is given to crashd, or
	// -U was given and someone else than current user wants to authenticate
	if (!pwp || (!config::always_login && is_nologin(pwp->pw_shell)) ||
	    (!config::uid_change && (pwp->pw_uid != geteuid()))) {
		d_user = "[crashd]";
		d_err = "server_session::authenticate: Invalid username.";
	} else {
		d_shell = pwp->pw_shell;
		if (chdir(pwp->pw_dir) < 0)
			;	// avoid gcc warning
		d_home = pwp->pw_dir;

		if (config::uid_change && setgid(pwp->pw_gid) < 0) {
			d_err = "server_session::authenticate::setgid:";
			d_err += strerror(errno);
			return -1;
		}
		if (config::uid_change && initgroups(d_user.c_str(), pwp->pw_gid) < 0) {
			d_err = "server_session::authenticate::initgroups:";
			d_err += strerror(errno);
			return -1;
		}

		// Attention! we only set EUID to user, for accessing the keyfile.
		// Later on, before the command is actually executed (shell session)
		// the whole EUID/UID needs to be dropped. We need to keep root privs
		// in order to log utmp/wtmp entries later. And we cannot do that now since
		// we did not allocate a PTY yet. Otherwise we'd need to allocate a PTY
		// before user is authenticated which looks wrong to me.
		d_final_uid = pwp->pw_uid;
		if (config::uid_change && setreuid((uid_t)-1, pwp->pw_uid) < 0) {
			d_err = "server_session::authenticate::setreuid:";
			d_err += strerror(errno);
			return -1;
		}
		d_err = "auth failure for user '";
		d_err += d_user;
		d_err += "'";
		string file = "";
		if (config::user_keys.c_str()[0] == '/') {
			file = config::user_keys;
		} else {
			file = pwp->pw_dir;
			file += "/";
			file += config::user_keys;
			file += "/authorized_keys";
		}
		FILE *fstream = fopen(file.c_str(), "r");
		if (!fstream)
			return -1;

		// verify signature over the sha hash of the
		// rand-bytes array
		unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey{
			PEM_read_PUBKEY(fstream, nullptr, nullptr, nullptr),
			EVP_PKEY_free
		};
		fclose(fstream);
		if (!pkey.get()) {
			syslog().log("no userkey");
			return -1;
		}

		// Ok? see above comment. Will drop that later completely to "final_uid".
		if (config::uid_change) {
			if (setreuid(0, 0) < 0)
				;	// avoid gcc warning
		}

		if (EVP_VerifyInit_ex(md_ctx.get(), sha512, nullptr) != 1)
			return -1;
		if (EVP_VerifyUpdate(md_ctx.get(), d_banner.c_str(), d_banner.size()) != 1)
			return -1;
		if (EVP_VerifyUpdate(md_ctx.get(), md, EVP_MD_size(sha512)) != 1) // 'challenge' that was sent to client
			return -1;
		int pubkeylen = i2d_PublicKey(d_pubkey, nullptr);
		if (pubkeylen <= 0 || pubkeylen >= 32000)
			return -1;
		unique_ptr<unsigned char[]> b1(new (nothrow) unsigned char[pubkeylen]);
		unsigned char *b2 = nullptr;
		if (!b1.get())
			return -1;
		b2 = b1.get();
		// The b2/b1 foo looks strange but is correct. Check the i2d_X509 man-page on
		// how ppout is treated for i2d_TYPE().
		if (i2d_PublicKey(d_pubkey, &b2) != pubkeylen)
			return -1;
		// DER encoding of server pubkey
		if (EVP_VerifyUpdate(md_ctx.get(), b1.get(), pubkeylen) != 1)
			return -1;
		int v = EVP_VerifyFinal(md_ctx.get(), reinterpret_cast<unsigned char*>(token), tlen, pkey.get());
		return v;
	}
	return 0;
}


int server_session::handle(SSL_CTX *ssl_ctx)
{

	// not owning
	d_ssl_ctx0 = ssl_ctx;

	struct itimerval iti;

	memset(&iti, 0, sizeof(iti));
	iti.it_value.tv_sec = 12;
	setitimer(ITIMER_REAL, &iti, nullptr);

	// If a SNI is set, we immediately accept TLS traffic w/o banner and the d_banner
	// is set to the SNI for Verify()
	if (!d_sni.size()) {
		if (writen(d_peer_fd, d_banner.c_str(), d_banner.length()) != (int)(d_banner.length())) {
			d_err = "server_session::handle::writen:";
			d_err += strerror(errno);
			return -1;
		}
	}

	if ((d_ssl = SSL_new(ssl_ctx)) == nullptr) {
		d_err = "server_session::handle::SSL_new:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if (config::allow_roam && d_type == SOCK_DGRAM)
		d_bio = BIO_new_dgram(d_peer_fd, BIO_NOCLOSE);
	else
		d_bio = BIO_new_socket(d_peer_fd, BIO_NOCLOSE);

	// +1 for ourself to always have a valid d_bio in case of suspend/resume
	// where we call SSL_free()
	BIO_up_ref(d_bio);

	// +1 for set0 (as told by manpage)
	BIO_up_ref(d_bio);

#ifdef LIBRESSL_VERSION_NUMBER
	SSL_set_bio(d_ssl, d_bio, d_bio);
#else
	SSL_set0_rbio(d_ssl, d_bio);
	SSL_set0_wbio(d_ssl, d_bio);
#endif

	if (d_type == SOCK_DGRAM) {

#ifndef BORINGSSL_API_VERSION
		// DTLS_set_link_mtu(d_ssl, MTU) for openssl
		SSL_ctrl(d_ssl, SSL_CTRL_SET_MTU, MTU, 0);
#endif
		// DTLSv1_listen() seems to be buggy in older openssl and just hangs
		// w/o sending the required cookie request. I also question the requirement
		// of this "DoS protection" (as per RFC), since crashd only accepts one new UDP session
		// per second.
#ifdef HAVE_DTLS_LISTEN
		if (DTLSv1_listen(d_ssl, d_dlisten_param) <= 0) {
			d_err = "server_session::handle::DTLSv1_listen:";
			d_err += ERR_error_string(ERR_get_error(), nullptr);
			return -1;
		}
#endif
	}

	if (SSL_accept(d_ssl) <= 0) {
		d_err = "server_session::handle::SSL_accept:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	if (d_sni.size()) {
		string peer_sni = SSL_get_servername(d_ssl, TLSEXT_NAMETYPE_host_name);
		if (d_sni != peer_sni) {
			d_err = "server_session: Wrong SNI by client. Rejecting.";
			return -1;
		}
	}

	if (config::allow_roam && d_type == SOCK_DGRAM)
		BIO_ctrl(d_bio, BIO_CTRL_DGRAM_GET_PEER, 0, d_bio_peer);

	if (disguise_filter(d_ssl) != 1) {
		d_err = "server_session: Disguise filter triggered.";
		return -1;
	}

	// Get our own X509 for authentication input. This has moved below
	// SSL_accept() since OSX ships with buggy OpenSSL that segfaults
	// with nullptr ptr access if the SSL object is not connected: search for
	// 'nullptr ptr deref when calling SSL_get_certificate'
	X509 *cert = SSL_get_certificate(d_ssl);
	if (!cert) {
		d_err = "server_session::handle::SSL_get_certificate:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}
	// as per manpage, `cert` must not be freed
	d_pubkey = X509_get_pubkey(cert);

	if (!d_pubkey) {
		d_err = "server_session::handle::X509_get_pubkey:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}


	// authenticate, this already sets EGID/GID and groups
	// but NOT EUID/UID!
	if (authenticate() != 1)
		return -1;

	memset(&iti, 0, sizeof(iti));
	setitimer(ITIMER_REAL, &iti, nullptr);

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sess_sig_chld;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGCHLD, &sa, nullptr);

	if (d_cmd.size() > 0) {
		if (d_iob.init_pipe() < 0) {
			d_err = "server_session::handle:: I/O channel setup:";
			d_err += d_iob.why();
			return -1;
		}
	} else {
		if (d_iob.init_pty(d_final_uid, -1, 0600) < 0) {
			d_err = "server_session::handle:: PTY setup:";
			d_err += d_iob.why();
			return -1;
		}
	}

	string l = "SUCCESS: opening session for user '";
	l += d_user;
	l += "'";
	syslog().log(l);

	// only on a pipe in non-pty mode, unused for other cases. Assignment is not compound
	// with if() check since in C++20 you will get deprecate warning for compound volatile statements
	pipe_child = fork();
	if (pipe_child == 0) {
		long mfd = sysconf(_SC_OPEN_MAX);
		for (long i = 0; i <= mfd; ++i) {
			if (i != d_iob.slave0() && i != d_iob.slave1() && i != d_iob.slave2())
				close(i);
		}
		setsid();
#if (defined __FreeBSD__) || (defined __NetBSD__) || (defined __OpenBSD__) || (defined __APPLE__)
		if (config::uid_change && !config::silent && setlogin(d_user.c_str()) < 0) {
			d_err = "FAIL: server_session::handle::setlogin:";
			d_err += strerror(errno);
			syslog().log(d_err);

			// No "return"s here, since we are in a child, and we want the
			// parent which is handling out crypto stream do the cleanup
			// and not return the ->handle() caller directly
			exit(1);
		}
#endif
		if (config::uid_change && setuid(d_final_uid) < 0) {
			d_err = "FAIL: server_session::handle::setuid:";
			d_err += strerror(errno);
			syslog().log(d_err);
			exit(1);
		}

		char *a[] = {nullptr, nullptr, nullptr, nullptr};

		// dont honor pw shell entry in case of always-login
		if (config::always_login) {
#ifdef ANDROID
			a[0] = strdup("/system/bin/sh");
#else
			a[0] = strdup("/bin/sh");
#endif
		} else
			a[0] = strdup(d_shell.c_str());

		if (d_cmd.size() > 0) {
			a[1] = strdup("-c");
			a[2] = strdup(d_cmd.c_str());
		}

		dup2(d_iob.slave0(), 0);
		dup2(d_iob.slave1(), 1);
		dup2(d_iob.slave2(), 2);

		d_iob.close_master();
		d_iob.close_slave();

		ioctl(0, TIOCSCTTY, 0);

		string h = "HOME=";
		h += d_home;
		char *const env[] = {strdup(h.c_str()), nullptr};
		execve(*a, a, env);
		exit(0);
	} else if (pipe_child < 0) {
		d_err = "server_session::handle::";
		d_err += strerror(errno);
		return -1;
	}

	if (d_iob.is_pty())
		logger::login(d_iob.pts_name(), d_user, d_peer_ip);

	if (config::uid_change && setuid(d_final_uid) < 0) {
		d_err = "server_session::handle::setuid:";
		d_err += strerror(errno);
		return -1;
	}

	d_iob.close_slave();

	struct rlimit rl;
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
		return -1;
	if (rl.rlim_cur > FDID_MAX) {
		rl.rlim_cur = rl.rlim_max = FDID_MAX;
		setrlimit(RLIMIT_NOFILE, &rl);
	}

	if (!(d_pfds = new (nothrow) pollfd[rl.rlim_cur]))
		return -1;
	if (!(d_fd2state = new (nothrow) state[rl.rlim_cur]))
		return -1;

	d_fd2state[d_iob.master0()].fd = d_iob.master0();
	d_fd2state[d_iob.master0()].state = STATE_PTY;
	d_fd2state[d_iob.master1()].fd = d_iob.master1();
	d_fd2state[d_iob.master1()].state = STATE_PTY;
	d_fd2state[d_iob.master2()].fd = d_iob.master2();
	d_fd2state[d_iob.master2()].state = STATE_PTY;

	d_fd2state[d_peer_fd].fd = d_peer_fd;
	d_fd2state[d_peer_fd].state = STATE_SSL;

	for (unsigned int i = 0; i < rl.rlim_cur; ++i) {
		d_pfds[i].fd = -1;
		d_pfds[i].events = d_pfds[i].revents = 0;
	}

	d_pfds[d_iob.master0()].fd = d_iob.master0();
	d_pfds[d_iob.master0()].events |= POLLOUT;
	d_pfds[d_iob.master1()].fd = d_iob.master1();
	d_pfds[d_iob.master1()].events |= POLLIN;
	d_pfds[d_iob.master2()].fd = d_iob.master2();
	d_pfds[d_iob.master2()].events |= POLLIN;

	d_pfds[d_peer_fd].fd = d_peer_fd;
	d_pfds[d_peer_fd].events = POLLIN;

	// only now set non-blocking mode and moving write buffers
	if (d_type == SOCK_STREAM) {
		int flags = fcntl(d_peer_fd, F_GETFL);
		fcntl(d_peer_fd, F_SETFL, flags|O_NONBLOCK);
		SSL_set_mode(d_ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);
	}

	d_max_fd = d_peer_fd;

	// backing string to avoid numerous re/allocs for growing strings
	string bk_str;
	bk_str.reserve(2*CHUNK_SIZE);

	// do not touch the buffer sizes, they are well calculated
	char pty_buf[PTY_BSIZE] = {0}, rbuf[RBUF_BSIZE] = {0}, sbuf[SBUF_BSIZE] = {0};

	ssize_t r = 0;
	int i = 0, stdin_can_close = 1, ssl_read_wants_write = 0;

	// exit condition checked around poll()
	for (;;) {

		// if peer has signalled closed stdin, check if we can do so if no data is left to be written to input
		if (stdin_can_close && d_stdin_closed && tx_empty(d_iob.master0())) {
			d_iob.close_master0();
			d_fd2state[i].fd = -1;
			d_fd2state[i].state = STATE_INVALID;
			tx_clear(i);
			d_pfds[i].fd = -1;
			d_pfds[i].events = 0;
			stdin_can_close = 0;
		}

		for (i = rl.rlim_cur - 1; i > 0; --i) {
			if (d_fd2state[i].state != STATE_INVALID && d_fd2state[i].fd != -1) {
				d_max_fd = i;
				break;
			}
		}

		errno = 0;

		// faster polls if child already exited and we are just about to flush remaining data
		if (pipe_child_exited && tx_empty(d_peer_fd) && d_tx_map.empty())
			d_poll_to.next = d_poll_to.min;

		if ((r = poll(d_pfds, d_max_fd + 1, d_poll_to.next)) <= 0) {

			// signal caught
			if (errno == EINTR)
				continue;

			// child exited and no data left to flush? Thats a clean exit!
			if (r == 0 && pipe_child_exited && tx_empty(d_peer_fd) && d_tx_map.empty())
				return 0;

			// real error
			if (r < 0)
				return -1;
		}

		if (d_type == SOCK_DGRAM && ((r == 0 && tx_empty(d_peer_fd)) || tx_must_add_sq(d_peer_fd)))
			tx_add_sq(d_peer_fd);

		d_now = time(nullptr);

		for (i = 0; i <= d_max_fd; ++i) {

			if (d_fd2state[i].state == STATE_INVALID)
				continue;

			if ((d_fd2state[i].state == STATE_CLOSING && (d_now - d_fd2state[i].time) > CLOSING_TIME) ||
			    (d_fd2state[i].state == STATE_UDPCLIENT && (d_now - d_fd2state[i].time) > UDP_CLOSING_TIME && d_fd2state[i].odgrams.empty())) {
				close(i);
				d_fd2state[i].fd = -1;
				d_fd2state[i].state = STATE_INVALID;
				tx_clear(i);
				d_pfds[i].fd = -1;
				d_pfds[i].events = 0;
				d_pfds[i].revents = 0;
				continue;
			}

			if (d_pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {

				if (d_fd2state[i].state == STATE_SSL) {
					flush_fd(d_iob.master0(), tx_string_and_clear(d_iob.master0()));
				}

				if (!(d_pfds[i].revents & POLLIN)) {

					if ((d_fd2state[i].state == STATE_CONNECTED || d_fd2state[i].state == STATE_CONNECT)) {
						tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);	// signal finished connection to remote
						d_pfds[d_peer_fd].events |= POLLOUT;
						tcp_nodes2sock.erase(d_fd2state[i].rnode);
					}

					close(i);
					d_fd2state[i].fd = -1;
					d_fd2state[i].state = STATE_INVALID;
					tx_clear(i);
					d_pfds[i].fd = -1;
					d_pfds[i].events = 0;
					d_pfds[i].revents = 0;
					continue;
				}
			}

			if ((d_pfds[i].revents & (POLLIN|POLLOUT)) == 0)
				continue;

			unsigned short revents = d_pfds[i].revents;
			d_pfds[i].revents = 0;

			if (d_fd2state[i].state == STATE_PTY) {
				d_pfds[i].events = POLLIN;

				if ((revents & POLLIN) && tx_can_add(d_peer_fd)) {
					if ((r = read(i, pty_buf, sizeof(pty_buf))) <= 0) {
						if (errno != EINTR) {
							close(i);
							d_fd2state[i].fd = -1;
							d_fd2state[i].state = STATE_INVALID;
							tx_clear(i);
							d_pfds[i].fd = -1;
							d_pfds[i].events = 0;
							continue;
						}
					} else {
						tx_add(d_peer_fd, slen(6 + r) + (i == d_iob.master1() ? ":D:O1:" : ":D:O2:") + string(pty_buf, r));
						d_pfds[d_peer_fd].events |= POLLOUT;
					}
				}
				if ((revents & POLLOUT) && !tx_empty(i)) {
					sequence_t seq = 0;
					auto sv = tx_string(i, seq, bk_str, STDOUT_CHUNK_SIZE);
					if ((r = write(i, sv.c_str(), sv.size())) <= 0) {
						if (errno != EINTR) {
							close(i);
							d_fd2state[i].fd = -1;
							d_fd2state[i].state = STATE_INVALID;
							tx_clear(i);
							d_pfds[i].fd = -1;
							d_pfds[i].events = 0;
							continue;
						}
						r = 0;
					}
					if (r > 0)
						tx_remove(i, r);
				}

				if (!tx_empty(i))
					d_pfds[i].events |= POLLOUT;

			} else if (d_fd2state[i].state == STATE_SSL) {

				d_pfds[i].events = POLLIN;

				if ((revents & POLLOUT) && !tx_empty(i)) {

					// obtains properly padded and max chunk-sized string
					sequence_t seq = 0;
					auto sv = tx_string(i, seq, bk_str, d_chunk_size);

					// keep sequenced packets for possible resend requests. 'seq' equals d_flow.tx_sequence
					if (d_type == SOCK_DGRAM && seq != 0)
						d_tx_map[d_flow.tx_sequence++] = bk_str;

					// in DTLS case, set peer to that we known were the last good recv from
					if (config::allow_roam && d_type == SOCK_DGRAM)
						BIO_ctrl(d_bio, BIO_CTRL_DGRAM_SET_PEER, 0, d_bio_peer);

					ssize_t n = SSL_write(d_ssl, sv.c_str(), sv.size());
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_ZERO_RETURN:
						flush_fd(d_iob.master0(), tx_string_and_clear(d_iob.master0()));
						return 0;
					case SSL_ERROR_NONE:
					case SSL_ERROR_WANT_WRITE:
					case SSL_ERROR_WANT_READ:
						break;
					default:
						d_err = "server_session::handle::SSL_write:";
						d_err += ERR_error_string(ERR_get_error(), nullptr);
						flush_fd(d_iob.master0(), tx_string_and_clear(d_iob.master0()));
						return -1;
					}

					// dgram data was already removed from queue by tx_string()
					if (n > 0 && d_type == SOCK_STREAM)
						tx_remove(i, n);

					d_last_ssl_qlen = tx_size(i);
					if (ssl_read_wants_write || d_last_ssl_qlen > 0)
						d_pfds[i].events |= POLLOUT;
				}

				if ((revents & POLLIN) || (ssl_read_wants_write && (revents & POLLOUT))) {

					ssl_read_wants_write = 0;

					ssize_t n = SSL_read(d_ssl, rbuf, sizeof(rbuf));
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_NONE:
						break;
					case SSL_ERROR_ZERO_RETURN:
						flush_fd(d_iob.master0(), tx_string_and_clear(d_iob.master0()));
						return 0;
					case SSL_ERROR_WANT_WRITE:
						d_pfds[i].events |= POLLOUT;
						ssl_read_wants_write = 1;
						break;
					case SSL_ERROR_WANT_READ:
						break;
					default:
						d_err = "server_session::handle::SSL_read:";
						d_err += ERR_error_string(ERR_get_error(), nullptr);
						flush_fd(d_iob.master0(), tx_string_and_clear(d_iob.master0()));
						return -1;
					}

					if (n > 0)
						d_fd2state[i].ibuf += string(rbuf, n);

					// on successfull DTLS read, obtain last known address of peer sender
					if (config::allow_roam && d_type == SOCK_DGRAM)
						BIO_ctrl(d_bio, BIO_CTRL_DGRAM_GET_PEER, 0, d_bio_peer);

					while (handle_input(i) > 0);
				}
			}

			if (d_fd2state[i].state < STATE_ACCEPT)
				continue;

			// net cmd handler

			if (revents & POLLIN) {

				if (d_fd2state[i].state == STATE_CONNECTED && tx_can_add(d_peer_fd)) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
						tcp_nodes2sock.erase(d_fd2state[i].rnode);
						tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);  // signal finished connection to remote
						d_pfds[d_peer_fd].events |= POLLOUT;
						continue;
					}
					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size() + r) + ":C:T:R:" + d_fd2state[i].rnode + string(sbuf, r));        // received TCP data
					d_pfds[d_peer_fd].events |= POLLOUT;
				} else if (d_fd2state[i].state == STATE_UDPCLIENT) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0)
						continue;

					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size() + r) + ":C:U:R:" + d_fd2state[i].rnode + string(sbuf, r));        // received UDP data
					d_pfds[d_peer_fd].events |= POLLOUT;
				}
			}
			if (revents & POLLOUT) {

				if (d_fd2state[i].state == STATE_CONNECT) {
					int e = 0;
					socklen_t elen = sizeof(e);
					if (getsockopt(i, SOL_SOCKET, SO_ERROR, &e, &elen) < 0 || e != 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
						tcp_nodes2sock.erase(d_fd2state[i].rnode);

						tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);	// signal finished connection to remote
						d_pfds[d_peer_fd].events |= POLLOUT;
						continue;
					}

					d_pfds[i].events = POLLIN;
					d_fd2state[i].state = STATE_CONNECTED;
					d_fd2state[i].time = d_now;

					tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:C:" + d_fd2state[i].rnode);		// TCP connect() finished, connection is set up
					d_pfds[d_peer_fd].events |= POLLOUT;

				} else if (d_fd2state[i].state == STATE_CONNECTED) {
					auto sv = tx_string(i, bk_str);
					if ((r = send(i, sv.c_str(), sv.size(), 0)) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].fd = -1;
						d_fd2state[i].state = STATE_INVALID;
						tx_clear(i);
						tcp_nodes2sock.erase(d_fd2state[i].rnode);
						tx_add(d_peer_fd, slen(7 + d_fd2state[i].rnode.size()) + ":C:T:F:" + d_fd2state[i].rnode);	// signal finished connection via SSL to remote
						d_pfds[d_peer_fd].events |= POLLOUT;
						continue;
					}

					tx_remove(i, r);
				} else if (d_fd2state[i].state == STATE_UDPCLIENT) {
					const string &dgram = d_fd2state[i].odgrams.front().second;
					// No need to sendto(), each socket with ID is connect()'ed since -U binding already knows
					// the remote IP:port to send to
					if ((r = send(i, dgram.c_str(), dgram.size(), 0)) <= 0)
						continue;

					d_fd2state[i].odgrams.pop_front();
				}

				if (tx_empty(i) && d_fd2state[i].odgrams.empty())
					d_pfds[i].events &= ~POLLOUT;
			}
		}
	}

	return 0;
}


int server_session::suspend(const string &cmd)
{

	unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> old_sess{
		SSL_get1_session(d_ssl),
		SSL_SESSION_free
	};
	if (!old_sess.get())
		return -1;

	unsigned int old_idlen = 0;
	auto old_id = SSL_SESSION_get_id(old_sess.get(), &old_idlen);

	// smells fishy?
	if (old_idlen < 32 || old_idlen > 4096)
		return -1;

	string old_id_s = string(reinterpret_cast<const char *>(old_id), old_idlen);

	// loop until SSL_accept() returns the correctly resumed session (kidz might
	// try invalid tickets).
	// NEVER return or break from this loop, unless the new session is verified OK.
	for (;;) {

		SSL_set_quiet_shutdown(d_ssl, 1);
		SSL_shutdown(d_ssl);

		// This will also free the bio, but we have +1 ref for ourself,
		// so we can re-set them just below
		SSL_free(d_ssl);
		if (!(d_ssl = SSL_new(d_ssl_ctx0))) {
			syslog().log("Failed to obtain new SSL object upon suspend.");
			_exit(1);
		}

		// Preferably we want to use SSL_shutdown(); SSL_clear(); so a new
		// SSL_accept() could be made on the same `d_ssl`, but see man-page
		// on the side-effects and it breaks depending on library version. So
		// we have to go the whole SSL_free(); SSL_new(); ... path :/
		SSL_set_session(d_ssl, old_sess.get());

		BIO_up_ref(d_bio);
		BIO_up_ref(d_bio);
#ifdef LIBRESSL_VERSION_NUMBER
		SSL_set_bio(d_ssl, d_bio, d_bio);
#else
		SSL_set0_rbio(d_ssl, d_bio);
		SSL_set0_wbio(d_ssl, d_bio);
#endif

#ifndef BORINGSSL_API_VERSION
		// DTLS_set_link_mtu(d_ssl, MTU) for openssl
		SSL_ctrl(d_ssl, SSL_CTRL_SET_MTU, MTU, 0);
#endif
		syslog().log("DTLS session suspended.");
		sleep(1);
		if (SSL_accept(d_ssl) <= 0)
			continue;

		auto new_sess = SSL_get1_session(d_ssl);

		if (!new_sess || SSL_session_reused(d_ssl) != 1) {
			if (new_sess)
				SSL_SESSION_free(new_sess);
			syslog().log("No reuse. Failed to resume DTLS session.");
			continue;
		}

		if (SSL_CTX_sess_number(d_ssl_ctx0) != 1) {
			SSL_CTX_remove_session(d_ssl_ctx0, new_sess);	// also calls SSL_SESSION_free()
			syslog().log("More than one session. Failed to resume DTLS session.");
			continue;
		}

		unsigned int new_idlen = 0;
		auto new_id = SSL_SESSION_get_id(new_sess, &new_idlen);

		if (old_idlen != new_idlen) {
			SSL_SESSION_free(new_sess);
			continue;
		}

		string new_id_s = string(reinterpret_cast<const char *>(new_id), new_idlen);

		SSL_SESSION_free(new_sess);

		if (CRYPTO_memcmp(old_id_s.c_str(), new_id_s.c_str(), old_id_s.size()) == 0)
			break;	// success

		syslog().log("SessionID mismatch. Failed to resume DTLS session.");
	}

	syslog().log("DTLS session resumed.");

	// reset RX/TX seq counters
	d_flow.reset();
	return 0;
}


int server_session::handle_input(int i)
{
	int r = 0;

	if ((r = this->session::handle_input(i)) != 1)
		return r;

	string &cmd = d_fd2state[i].ibuf;

	if (cmd.size() < 7)
		return 0;

	unsigned short l = 0;
	if (sscanf(cmd.c_str(), "%05hu:", &l) != 1)
		return 0;
	size_t len = l;

	if (len < 6)
		return -1;
	if (cmd.size() < 5 + len)	// 5bytes %05hu + :C:...
		return 0;

	if (cmd.find("D:I0:", 6) == 6) {
		tx_add(d_iob.master0(), cmd.substr(5 + 6, len - 6));
		d_pfds[d_iob.master0()].events |= POLLOUT;
	} else if (cmd.find("C:WS:", 6) == 6) {
		struct winsize ws;
		if (sscanf(cmd.c_str() + 5 + 6, "%hu:%hu:%hu:%hu", &ws.ws_row, &ws.ws_col, &ws.ws_xpixel, &ws.ws_ypixel) == 4) {
			if (d_iob.is_pty())
				ioctl(d_iob.master1(), TIOCSWINSZ, &ws);
		}

	// remote peer has closed stdin
	} else if (cmd.find("C:CL:0", 6) == 6) {
		d_stdin_closed = 1;

	// peer suspended session
	} else if (cmd.find("C:SPND:0", 6) == 6) {
		if (d_type == SOCK_DGRAM && config::allow_roam) {
			if (suspend(cmd) < 0)
				syslog().log("Suspend request received but failed to do so.");
			cmd.clear();
			return 0;
		}
	} else {
		// valid len/packet format, but unrecognized cmd. Maybe a chained command for
		// this->session::handle_input(), so keep it where it is and let next iteration handle it
		return 1;
	}

	cmd.erase(0, 5 + len);

	// one command was handled. There may be more in the ibuf
	return 1;
}

}

