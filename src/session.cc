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
#include <termios.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
extern "C" {
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
}
#include <iostream>
#include "config.h"
#include "global.h"
#include "session.h"
#include "misc.h"
#include "pty.h"
#include "log.h"
#include "net.h"
#include "deleters.h"
#include "missing.h"


using namespace std;

namespace crash {


// change in client d_major, d_minor accordingly
string server_session::d_banner = "1000 crashd-2.002 OK\r\n";

string server_session::d_sni = "";

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


server_session::server_session(int fd, SSL_CTX *ctx, const string &sni)
	: d_sock(fd), d_ssl_ctx(ctx)
{
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
	socklen_t slen = sizeof(struct sockaddr_in);
	struct sockaddr *sin = reinterpret_cast<struct sockaddr *>(&sin4);

	if (config::v6) {
		slen = sizeof(struct sockaddr_in6);
		sin = reinterpret_cast<struct sockaddr *>(&sin6);
	}

	if (getpeername(fd, sin, &slen) < 0)
		return;

	if (config::v6) {
		inet_ntop(AF_INET6, &sin6.sin6_addr, d_peer_ip, sizeof(d_peer_ip));
	} else {
		inet_ntop(AF_INET, &sin4.sin_addr, d_peer_ip, sizeof(d_peer_ip));
	}

	if (sni.size()) {
		d_sni = sni;
		d_banner = sni;
	}
}


server_session::~server_session()
{
	if (d_ssl) {
		SSL_shutdown(d_ssl);
		//SSL_free(ssl);
	}

	if (d_pubkey)
		EVP_PKEY_free(d_pubkey);
	// Do not mess with SSL_CTX, its not owned by us, but by server {}

	shutdown(d_sock, SHUT_RDWR);

	if (d_fd2state) {
		for (int i = 3; i <= d_max_fd; ++i) {
			if (d_fd2state[i].state != STATE_INVALID)
				close(i);
		}
		delete [] d_fd2state;
	}

	delete [] d_pfds;
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
	unique_ptr<EVP_MD_CTX, EVP_MD_CTX_del> md_ctx(EVP_MD_CTX_create(), EVP_MD_CTX_delete);
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

	sprintf(sbuf, "A:sign1:%hu:", (unsigned short)EVP_MD_size(sha512));
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
	if (rbuf[0] != 'A')
		return -1;

	unsigned short major = 0, minor = 0, cmdlen = 0;
	if (sscanf(rbuf, "A:sign1:crash-%hu.%hu:%32[^:]:%hu:", &major, &minor, ubuf, &cmdlen) != 4)
		return -1;

	if (cmdlen >= sizeof(cmdbuf))
		return -1;

	// find last ':'
	char *ptr = strchr(rbuf + 8, ':');
	if (!ptr++)
		return -1;
	ptr = strchr(ptr, ':');
	if (!ptr++)
		return -1;
	ptr = strchr(ptr, ':');
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
		unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(PEM_read_PUBKEY(fstream, nullptr, nullptr, nullptr), EVP_PKEY_free);
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


int server_session::handle()
{
	struct itimerval iti;

	memset(&iti, 0, sizeof(iti));
	iti.it_value.tv_sec = 12;
	setitimer(ITIMER_REAL, &iti, nullptr);

	// If a SNI is set, we immediately accept TLS traffic w/o banner and the d_banner
	// is set to the SNI for Verify()
	if (!d_sni.size()) {
		if (writen(d_sock, d_banner.c_str(), d_banner.length()) != (int)(d_banner.length())) {
			d_err = "server_session::handle::writen:";
			d_err += strerror(errno);
			return -1;
		}
	}

	if ((d_ssl = SSL_new(d_ssl_ctx)) == nullptr) {
		d_err = "server_session::handle::SSL_new:";
		d_err += ERR_error_string(ERR_get_error(), nullptr);
		return -1;
	}

	SSL_set_fd(d_ssl, d_sock);

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
	d_pubkey = X509_get_pubkey(cert);
	X509_free(cert);
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

	// only on a pipe in non-pty mode, unused for other cases
	if ((pipe_child = fork()) == 0) {
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

	d_fd2state[d_sock].fd = d_sock;
	d_fd2state[d_sock].state = STATE_SSL;

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

	d_pfds[d_sock].fd = d_sock;
	d_pfds[d_sock].events = POLLIN;

	// only now set non-blocking mode and moving write buffers
	int flags = fcntl(d_sock, F_GETFL);
	fcntl(d_sock, F_SETFL, flags|O_NONBLOCK);
	SSL_set_mode(d_ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_ENABLE_PARTIAL_WRITE);

	d_max_fd = d_sock;

	char pty_buf[PTY_BSIZE] = {0}, rbuf[RBUF_BSIZE] = {0}, sbuf[MTU] = {0};

	ssize_t r = 0;
	int i = 0, poll_to = 1000, stdin_can_close = 1, ssl_read_wants_write = 0;

	string::size_type last_ssl_qlen = 0;

	// exit condition checked around poll()
	for (;;) {

		// if peer has signalled closed stdin, check if we can do so if no data is left to be written to input
		if (stdin_can_close && d_stdin_closed && d_fd2state[d_iob.master0()].obuf.size() == 0) {
			d_iob.close_master0();
			d_fd2state[i].state = STATE_INVALID;
			d_fd2state[i].obuf.clear();
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
		if (pipe_child_exited && d_fd2state[d_sock].obuf.size() == 0)
			poll_to = 0;

		if ((r = poll(d_pfds, d_max_fd + 1, poll_to)) <= 0) {

			// signal caught
			if (errno == EINTR)
				continue;

			// child exited and no data left to flush? Thats a clean exit!
			if (r == 0 && pipe_child_exited && d_fd2state[d_sock].obuf.size() == 0)
				return 0;

			// real error
			if (r < 0)
				return -1;

			// no fd ready to write, but still data pending. continue
			continue;
		}

		time_t now = time(nullptr);

		for (i = 0; i <= d_max_fd; ++i) {

			if (d_fd2state[i].state == STATE_INVALID)
				continue;

			if ((d_fd2state[i].state == STATE_CLOSING && (now - d_fd2state[i].time) > CLOSING_TIME) ||
			    (d_fd2state[i].state == STATE_UDPCLIENT && (now - d_fd2state[i].time) > UDP_CLOSING_TIME && d_fd2state[i].odgrams.empty())) {
				close(i);
				d_fd2state[i].fd = -1;
				d_fd2state[i].state = STATE_INVALID;
				d_fd2state[i].obuf.clear();
				d_pfds[i].fd = -1;
				d_pfds[i].events = 0;
				continue;
			}

			if (d_pfds[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {

				if (d_fd2state[i].state == STATE_SSL) {
					flush_fd(d_iob.master0(), d_fd2state[d_iob.master0()].obuf);
				}

				if (d_fd2state[i].state == STATE_CONNECTED || d_fd2state[i].state == STATE_CONNECT) {
					d_pfds[d_sock].events |= POLLOUT;
					d_fd2state[d_sock].obuf += slen(7 + d_fd2state[i].rnode.size());
					d_fd2state[d_sock].obuf += ":C:T:F:" + d_fd2state[i].rnode;	// signal finished connection to remote
					tcp_nodes2sock.erase(d_fd2state[i].rnode);
				}

				// poll() can report hangup on PTY whilst still delivering data from that fd.
				// do not close in this case but continue the revent treatment
				if (!(d_fd2state[i].state == STATE_PTY && (d_pfds[i].revents & POLLIN))) {
					close(i);
					d_fd2state[i].fd = -1;
					d_fd2state[i].state = STATE_INVALID;
					d_fd2state[i].obuf.clear();
					d_pfds[i].fd = -1;
					d_pfds[i].events = 0;
					continue;
				}
			}

			if ((d_pfds[i].revents & (POLLIN|POLLOUT)) == 0)
				continue;

			unsigned short revents = d_pfds[i].revents;
			d_pfds[i].revents = 0;

			if (d_fd2state[i].state == STATE_PTY) {
				d_pfds[i].events = POLLIN;

				if (revents & POLLIN) {
					if ((r = read(i, pty_buf, sizeof(pty_buf))) <= 0) {
						if (errno != EINTR) {
							close(i);
							d_fd2state[i].fd = -1;
							d_fd2state[i].state = STATE_INVALID;
							d_fd2state[i].obuf.clear();
							d_pfds[i].fd = -1;
							d_pfds[i].events = 0;
							continue;
						}
					} else {

						d_fd2state[d_sock].obuf += slen(6 + r);
						if (i == d_iob.master1())
							d_fd2state[d_sock].obuf += ":D:O1:";	// output from stdout
						else
							d_fd2state[d_sock].obuf += ":D:O2:";	// stderr
						d_fd2state[d_sock].obuf += string(pty_buf, r);
						d_pfds[d_sock].events |= POLLOUT;
					}
				}
				if ((revents & POLLOUT) && d_fd2state[i].obuf.size() > 0) {
					size_t nw = d_fd2state[i].obuf.size() > CHUNK_SIZE ? CHUNK_SIZE : d_fd2state[i].obuf.size();
					if ((r = write(i, d_fd2state[i].obuf.c_str(), nw)) <= 0) {
						if (errno != EINTR) {
							close(i);
							d_fd2state[i].fd = -1;
							d_fd2state[i].state = STATE_INVALID;
							d_fd2state[i].obuf.clear();
							d_pfds[i].fd = -1;
							d_pfds[i].events = 0;
							continue;
						}
						r = 0;
					}
					if (r > 0)
						d_fd2state[i].obuf.erase(0, r);
				}

				if (d_fd2state[i].obuf.size() > 0)
					d_pfds[i].events |= POLLOUT;

			} else if (d_fd2state[i].state == STATE_SSL) {

				d_pfds[i].events = POLLIN;

				if (d_fd2state[i].obuf.size() > 0) {

					// Only pad if since last padding new payload data was added to queue.
					// As there is only one socket (d_sock) where we pad outgoing data,
					// one variable (last_ssl_qlen) is sufficient and we don't need to have
					// a variable inside d_fd2state.
					if (last_ssl_qlen < d_fd2state[i].obuf.size())
						pad_nops(d_fd2state[i].obuf);

					size_t nw = d_fd2state[i].obuf.size() > CHUNK_SIZE ? CHUNK_SIZE : d_fd2state[i].obuf.size();
					ssize_t n = SSL_write(d_ssl, d_fd2state[i].obuf.c_str(), nw);
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_ZERO_RETURN:
						flush_fd(d_iob.master0(), d_fd2state[d_iob.master0()].obuf);
						return 0;
					case SSL_ERROR_NONE:
					case SSL_ERROR_WANT_WRITE:
					case SSL_ERROR_WANT_READ:
						break;
					default:
						d_err = "server_session::handle::SSL_write:";
						d_err += ERR_error_string(ERR_get_error(), nullptr);
						flush_fd(d_iob.master0(), d_fd2state[d_iob.master0()].obuf);
						return -1;
					}
					if (n > 0)
						d_fd2state[i].obuf.erase(0, n);
					last_ssl_qlen = d_fd2state[i].obuf.size();
					if (ssl_read_wants_write || last_ssl_qlen > 0)
						d_pfds[i].events |= POLLOUT;

					if (!(revents & POLLIN) && !ssl_read_wants_write)
						continue;
				}

				if (revents & (POLLIN|POLLOUT)) {

					ssl_read_wants_write = 0;

					ssize_t n = SSL_read(d_ssl, rbuf, sizeof(rbuf));
					switch (SSL_get_error(d_ssl, n)) {
					case SSL_ERROR_NONE:
						break;
					case SSL_ERROR_ZERO_RETURN:
						flush_fd(d_iob.master0(), d_fd2state[d_iob.master0()].obuf);
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
						flush_fd(d_iob.master0(), d_fd2state[d_iob.master0()].obuf);
						return -1;
					}

					if (n > 0)
						d_fd2state[i].ibuf += string(rbuf, n);

					while (handle_input(i) > 0);
				}
			}

			if (d_fd2state[i].state < STATE_ACCEPT)
				continue;

			// net cmd handler

			if (revents & POLLIN) {

				if (d_fd2state[i].state == STATE_CONNECTED) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].state = STATE_INVALID;
						d_fd2state[i].fd = -1;
						d_fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(d_fd2state[i].rnode);

						d_pfds[d_sock].events |= POLLOUT;
						d_fd2state[d_sock].obuf += slen(7 + d_fd2state[i].rnode.size());
						d_fd2state[d_sock].obuf += ":C:T:F:" + d_fd2state[i].rnode;	// signal finished connection to remote
						continue;
					}

					d_pfds[d_sock].events |= POLLOUT;
					d_fd2state[d_sock].obuf += slen(7 + d_fd2state[i].rnode.size() + r);
					d_fd2state[d_sock].obuf += ":C:T:R:" + d_fd2state[i].rnode + string(sbuf, r);	// received TCP data
				} else if (d_fd2state[i].state == STATE_UDPCLIENT) {
					if ((r = recv(i, sbuf, sizeof(sbuf), 0)) <= 0)
						continue;

					d_pfds[d_sock].events |= POLLOUT;
					d_fd2state[d_sock].obuf += slen(7 + d_fd2state[i].rnode.size() + r);
					d_fd2state[d_sock].obuf += ":C:U:R:" + d_fd2state[i].rnode + string(sbuf, r);	// received UDP data
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
						d_fd2state[i].state = STATE_INVALID;
						d_fd2state[i].fd = -1;
						d_fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(d_fd2state[i].rnode);

						d_pfds[d_sock].events |= POLLOUT;
						d_fd2state[d_sock].obuf += slen(7 + d_fd2state[i].rnode.size());
						d_fd2state[d_sock].obuf += ":C:T:F:" + d_fd2state[i].rnode;	// signal finished connection to remote
						continue;
					}

					d_pfds[i].events = POLLIN;
					d_fd2state[i].state = STATE_CONNECTED;
					d_fd2state[i].time = now;

					d_pfds[d_sock].events |= POLLOUT;
					d_fd2state[d_sock].obuf += slen(7 + d_fd2state[i].rnode.size());
					d_fd2state[d_sock].obuf += ":C:T:C:" + d_fd2state[i].rnode;	// TCP connect() finished, connection is set up

				} else if (d_fd2state[i].state == STATE_CONNECTED) {
					if ((r = send(i, d_fd2state[i].obuf.c_str(), d_fd2state[i].obuf.size(), 0)) <= 0) {
						close(i);
						d_pfds[i].fd = -1;
						d_pfds[i].events = 0;
						d_fd2state[i].state = STATE_INVALID;
						d_fd2state[i].fd = -1;
						d_fd2state[i].obuf.clear();
						tcp_nodes2sock.erase(d_fd2state[i].rnode);

						d_pfds[d_sock].events |= POLLOUT;
						d_fd2state[d_sock].obuf += slen(7 + d_fd2state[i].rnode.size());
						d_fd2state[d_sock].obuf += ":C:T:F:" + d_fd2state[i].rnode;	// signal finished connection to remote
						continue;
					}

					d_fd2state[i].obuf.erase(0, r);
				} else if (d_fd2state[i].state == STATE_UDPCLIENT) {
					string &dgram = d_fd2state[i].odgrams.front();
					// No need to sendto(), each socket with ID is connect()'ed since -U binding already knows
					// the remote IP:port to send to
					if ((r = send(i, dgram.c_str(), dgram.size(), 0)) <= 0)
						continue;

					d_fd2state[i].odgrams.pop_front();
					d_fd2state[i].ulports.pop_front();	// unused in server part; yet filled in external cmd_handler()
				}

				if (d_fd2state[i].obuf.empty() && d_fd2state[i].odgrams.empty())
					d_pfds[i].events &= ~POLLOUT;
			}
		}
	}

	return 0;
}


int server_session::handle_input(int i)
{

	string &cmd = d_fd2state[i].ibuf;

	if (cmd.size() < 7)
		return 0;

	unsigned short l = 0;
	if (sscanf(cmd.c_str(), "%hu:", &l) != 1)
		return -1;
	size_t len = l;

	if (len < 6)
		return -1;
	if (cmd.size() < 5 + len)	// 5bytes %05hu + :C:...
		return 0;

	if (cmd.find("D:I0:", 6) == 6) {
		d_pfds[d_iob.master0()].events |= POLLOUT;
		d_fd2state[d_iob.master0()].obuf += cmd.substr(5 + 6, len - 6);
	} else if (cmd.find("C:WS:", 6) == 6) {
		struct winsize ws;
		if (sscanf(cmd.c_str() + 5 + 6, "%hu:%hu:%hu:%hu", &ws.ws_row, &ws.ws_col, &ws.ws_xpixel, &ws.ws_ypixel) == 4) {
			if (d_iob.is_pty())
				ioctl(d_iob.master1(), TIOCSWINSZ, &ws);
		}
	// ping request
	} else if (cmd.find("C:PP:", 6) == 6) {
		const string echo = cmd.substr(5 + 6, len - 6);
		d_fd2state[d_sock].obuf += slen(6 + echo.size());
		d_fd2state[d_sock].obuf += ":C:PR:" + echo;
		d_pfds[d_sock].events |= POLLOUT;
	} else if (cmd.find("C:T:", 6) == 6 || cmd.find("C:U:", 6) == 6) {
		net_cmd_handler(cmd, d_fd2state, d_pfds, NETCMD_SEND_ALLOW);

	// remote peer has closed stdin
	} else if (cmd.find("C:CL:0", 6) == 6) {
		d_stdin_closed = 1;
	} else if (cmd.find("C:PR:", 6) == 6) {
		;	// ignore ping replies
	} else if (cmd.find("C:NO:", 6) == 6) {
		;	// ignore nops

	// The traffic management options may be triggered by the client, so these will not be
	// found in crashc.cc

	// disable traffic padding
	} else if (cmd.find("C:P0:", 6) == 6) {
		config::traffic_flags |= TRAFFIC_NOPAD;
	// enable maximum padding
	} else if (cmd.find("C:P9:", 6) == 6) {
		config::traffic_flags &= ~TRAFFIC_NOPAD;
		config::traffic_flags |= TRAFFIC_PADMAX;
	}

	cmd.erase(0, 5 + len);

	// one command was handled. There may be more in the ibuf
	return 1;
}


}

