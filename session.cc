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

#include <cstdio>
#include <string>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/time.h>
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
#include "session.h"
#include "misc.h"
#include "pty.h"
#include "log.h"


using namespace std;

// change in client my_major, my_minor accordingly
string server_session::banner = "1000 crashd-1.003 OK\r\n";
enum {
	const_message_size = 1024
};

server_session::server_session(int fd, SSL_CTX *ctx)
	: sock(fd), ssl(NULL), ssl_ctx(ctx), pubkey(NULL),
	  user("NULL"), cmd(""), home(""), shell(""), final_uid(0xffff)
{
	struct sockaddr_in sin4;
	struct sockaddr_in6 sin6;
	socklen_t slen = sizeof(struct sockaddr_in);
	struct sockaddr *sin = (struct sockaddr *)&sin4;

	memset(peer_ip, 0, sizeof(peer_ip));

	if (config::v6) {
		slen = sizeof(struct sockaddr_in6);
		sin = (struct sockaddr *)&sin6;
	}

	if (getpeername(fd, sin, &slen) < 0)
		return;

	if (config::v6) {
		inet_ntop(AF_INET6, &sin6.sin6_addr, peer_ip, sizeof(peer_ip));
	} else {
		inet_ntop(AF_INET, &sin4.sin_addr, peer_ip, sizeof(peer_ip));
	}

}


server_session::~server_session()
{
	if (ssl) {
		SSL_shutdown(ssl);
		//SSL_free(ssl);
	}

	if (pubkey)
		EVP_PKEY_free(pubkey);
	// Do not mess with SSL_CTX, its not owned by us, but by server {}
}


int server_session::handle_command(const string &tag, char *buf, unsigned short blen)
{
	if (tag == "window-size") {
		struct winsize ws;
		if (sscanf(buf, "%hu:%hu:%hu:%hu", &ws.ws_row, &ws.ws_col, &ws.ws_xpixel, &ws.ws_ypixel) != 4)
			return -1;
		if (iob.is_pty()) {
			if (ioctl(iob.master1(), TIOCSWINSZ, &ws) < 0)
				return -1;
		}
	}
	return 0;
}


int server_session::handle_data(const string &tag, char *buf, unsigned short blen)
{
	return writen(iob.master0(), buf, blen);
}


// == 1 if OK
int server_session::authenticate()
{
	unsigned char rand[256], md[EVP_MAX_MD_SIZE];

	memset(md, 0, sizeof(md));

	err = "server_session::authenticate::rand init failed";

	// Also add some entropy in the child-session, as the PRNG-state
	// is inherited from parent across fork()
	if (RAND_load_file("/dev/urandom", 16) != 16)
		return -1;
	if (RAND_bytes(rand, sizeof(rand)) != 1)
		return -1;
	EVP_MD_CTX md_ctx;
	const EVP_MD *sha512 = EVP_sha512();
	if (!sha512)
		return -1;
	EVP_MD_CTX_init(&md_ctx);
	if (EVP_DigestInit_ex(&md_ctx, sha512, NULL) != 1)
		return -1;
	if (EVP_DigestUpdate(&md_ctx, rand, sizeof(rand)) != 1)
		return -1;
	if (EVP_DigestFinal_ex(&md_ctx, md, NULL) != 1)
		return -1;

	char sbuf[const_message_size];

	memset(sbuf, 0, sizeof(sbuf));
	sprintf(sbuf, "A:sign:%hu:", (unsigned short)EVP_MD_size(sha512));
	memcpy(sbuf + strlen(sbuf), md, EVP_MD_size(sha512));

	err = "server_session::authenticate:: auth exchange";

	// write singing-request to client
	rewrite: ssize_t n = SSL_write(ssl, sbuf, const_message_size);
	switch (SSL_get_error(ssl, n)) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		return -1;
	case SSL_ERROR_WANT_WRITE:
	case SSL_ERROR_WANT_READ:
		goto rewrite;
	default:
		err = "server_session::authenticate::SSL_write:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	char rbuf[const_message_size + 1], cmdbuf[256], ubuf[64], token[1024];

	memset(rbuf, 0, sizeof(rbuf)); memset(ubuf, 0, sizeof(ubuf));
	memset(cmdbuf, 0, sizeof(cmdbuf)); memset(token, 0, sizeof(token));

	ssize_t r;
	repeek: r = SSL_peek(ssl, rbuf, const_message_size);
	switch (SSL_get_error(ssl, r)) {
	case SSL_ERROR_NONE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		return -1;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		goto repeek;
	default:
		err = "server_session::authenticate::SSL_peek:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	if ((size_t)r != const_message_size) {
		usleep(40);
		goto repeek;
	}
	SSL_read(ssl, rbuf, r);

	// start message parsing
	err = "server_session::authenticate::message format error";
	if (rbuf[0] != 'A') {
		return -1;
	}
	unsigned short major = 0, minor = 0, cmdlen = 0;
	if (sscanf(rbuf, "A:crash-%hu.%hu:%32[^:]:%hu:", &major, &minor, ubuf, &cmdlen) != 4) {
		return -1;
	}
	if (cmdlen >= sizeof(cmdbuf)) {
		return -1;
	}
	// find last ':'
	char *ptr = strchr(rbuf + 2, ':') + 1;
	if (!ptr)
		return -1;
	ptr = strchr(ptr, ':') + 1;
	if (!ptr)
		return -1;
	ptr = strchr(ptr, ':') + 1;
	if (!ptr || r - (ptr - rbuf) < (ssize_t)cmdlen) {
		return -1;
	}
	memcpy(cmdbuf, ptr, cmdlen);
	if (cmdlen)
		cmd = cmdbuf;

	ptr += cmdlen;
	unsigned short tlen = 0;
	if (sscanf(ptr, ":token:%hu:", &tlen) != 1)
		return -1;
	if (tlen >= sizeof(token) || tlen < 8)
		return -1;
	ptr = strchr(ptr + 7, ':') + 1;
	if (!ptr || r - (ptr - rbuf) < (ssize_t)tlen) {
		return -1;
	}
	memcpy(token, ptr, tlen);
	// end message parsing

	unsigned int i = 0;
	for (; i < sizeof(ubuf); ++i) {
		// just in case isspace() doesnt like \0 :)
		if (!isspace(ubuf[i]) || ubuf[i] == 0)
			break;
	}
	user = &ubuf[i];
	// some basic checks
	if (user.length() <= 1 || user.find("/", 0) != string::npos ||
	    user.find(":", 0) != string::npos)
		user = "[crashd]";

	char falsch[] = "/bin/false";
	struct passwd pw, *pwp = NULL;
	memset(&pw, 0, sizeof(pw));
	pw.pw_shell = falsch;

	char pwstr[4096];
	memset(pwstr, 0, sizeof(pwstr));
#ifndef ANDROID
	getpwnam_r(user.c_str(), &pw, pwstr, sizeof(pwstr), &pwp);
#else
	pwp = getpwnam(user.c_str());
#endif

	// invalid user, or
	// someone without a shell, except if always_login switch is given to crashd, or
	// -U was given and someone else than current user wants to authenticate
	if (!pwp || (!config::always_login && is_nologin(pwp->pw_shell)) ||
	    (!config::uid_change && (pwp->pw_uid != geteuid()))) {
		user = "[crashd]";
		//XXX emulate verifying in order to avoid
		// timing attacks
	} else {
		shell = pwp->pw_shell;
		chdir(pwp->pw_dir);
		home = pwp->pw_dir;

		if (config::uid_change && setgid(pwp->pw_gid) < 0) {
			err = "server_session::authenticate::setgid:";
			err += strerror(errno);
			return -1;
		}
		if (config::uid_change && initgroups(user.c_str(), pwp->pw_gid) < 0) {
			err = "server_session::authenticate::initgroups:";
			err += strerror(errno);
			return -1;
		}

		// Attention! we only set EUID to user, for accessing the keyfile.
		// Later on, before the command is actually executed (shell session)
		// the whole EUID/UID needs to be dropped. We need to keep root privs
		// in order to log utmp/wtmp entries later. And we cannot do that now since
		// we did not allocate a PTY yet. Otherwise we'd need to allocate a PTY
		// before user is authenticated which looks wrong to me.
		final_uid = pwp->pw_uid;
		if (config::uid_change && setreuid((uid_t)-1, pwp->pw_uid) < 0) {
			err = "server_session::authenticate::setreuid:";
			err += strerror(errno);
			return -1;
		}
		err = "auth failure for user '";
		err += user;
		err += "'";
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
		EVP_PKEY *pkey = PEM_read_PUBKEY(fstream, NULL, NULL, NULL);
		fclose(fstream);
		if (!pkey) {
			syslog().log("no userkey");
			return -1;
		}

		// Ok? see above comment. Will drop that later completely to "final_uid".
		if (config::uid_change)
			setreuid(0, 0);

		if (EVP_VerifyInit_ex(&md_ctx, sha512, NULL) != 1)
			return -1;
		if (EVP_VerifyUpdate(&md_ctx, md, EVP_MD_size(sha512)) != 1) // 'challenge' that was sent to client
			return -1;
		int pubkeylen = i2d_PublicKey(pubkey, NULL);
		if (pubkeylen <= 0 || pubkeylen >= 32000)
			return -1;
		unsigned char *b1 = NULL, *b2 = NULL;
		if ((b1 = (unsigned char *)malloc(pubkeylen)) == NULL)
			return -1;
		b2 = b1;
		if (i2d_PublicKey(pubkey, &b2) != pubkeylen)
			return -1;
		// DER encoding of server pubkey
		if (EVP_VerifyUpdate(&md_ctx, b1, pubkeylen) != 1) {
			free(b1);
			return -1;
		}
		free(b1);
		int v = EVP_VerifyFinal(&md_ctx, (unsigned char*)token, tlen, pkey);
		return v;
	}
	return 0;
}


int server_session::send_const_chunks(const string &tag, const char *buf, size_t blen)
{

	if (tag != "c0-stdout" && tag != "c0-stderr") {
		err = "server_session::send_const_chunk: Invalid tag";
		return -1;
	}

	char sbuf[const_message_size];
	size_t chunk_size = const_message_size - 20;	// room for D:tag...

	for (size_t i = 0; i < blen; i += chunk_size) {
		size_t n = chunk_size;
		if (blen - i < chunk_size)
			n = blen - i;

		memset(sbuf, 0, sizeof(sbuf));
		snprintf(sbuf, sizeof(sbuf), "D:%s:%hu:", tag.c_str(), (unsigned short)n);
		size_t slen = strlen(sbuf);
		memcpy(sbuf + slen, buf + i, n);
		rewrite1: ssize_t r = SSL_write(ssl, sbuf, sizeof(sbuf));
		switch (SSL_get_error(ssl, r)) {
		case SSL_ERROR_NONE:
			break;
		case SSL_ERROR_ZERO_RETURN:
			err = "server_session::send_const_chunks: Connection drop.";
			return 0;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			goto rewrite1;
		default:
			err = "server_session::send_const_chunks::SSL_write:";
			err += ERR_error_string(ERR_get_error(), NULL);
			return -1;
		}
	}
	return blen;
}


int server_session::handle()
{
	struct itimerval iti;

	memset(&iti, 0, sizeof(iti));
	iti.it_value.tv_sec = 12;
	setitimer(ITIMER_REAL, &iti, NULL);

	if (writen(sock, banner.c_str(), banner.length()) != (int)(banner.length())) {
		err = "server_session::handle::writen:";
		err += strerror(errno);
		return -1;
	}

	if ((ssl = SSL_new(ssl_ctx)) == NULL) {
		err = "server_session::handle::SSL_new:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	SSL_set_fd(ssl, sock);

	if (SSL_accept(ssl) <= 0) {
		err = "server_session::handle::SSL_accept:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}

	// Get our own X509 for authentication input. This has moved below
	// SSL_accept() since OSX ships with buggy OpenSSL that segfaults
	// with NULL ptr access if the SSL object is not connected: search for
	// 'NULL ptr deref when calling SSL_get_certificate'
	X509 *cert = SSL_get_certificate(ssl);
	if (!cert) {
		err = "server_session::handle::SSL_get_certificate:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}
	pubkey = X509_get_pubkey(cert);
	X509_free(cert);
	if (!pubkey) {
		err = "server_session::handle::X509_get_pubkey:";
		err += ERR_error_string(ERR_get_error(), NULL);
		return -1;
	}


	// authenticate, this already sets EGID/GID and groups
	// but NOT EUID/UID!
	if (authenticate() != 1) {
		return -1;
	}

	memset(&iti, 0, sizeof(iti));
	setitimer(ITIMER_REAL, &iti, NULL);

	string l = "SUCCESS: opening session for user '";
	l += user;
	l += "'";
	syslog().log(l);


	if (cmd.size() > 0)
		iob.init_pipe();
	else
		iob.init_pty(final_uid, -1, 0600);

	pid_t pid;
	if ((pid = fork()) == 0) {
		long mfd = sysconf(_SC_OPEN_MAX);
		for (long i = 0; i <= mfd; ++i) {
			if (i != iob.slave0() && i != iob.slave1() && i != iob.slave2())
				close(i);
		}
		setsid();
#ifdef __FreeBSD__
		if (setlogin(user.c_str()) < 0) {
			err = "FAIL: server_session::handle::setlogin:";
			err += strerror(errno);
			syslog().log(err);

			// No "return"s here, since we are in a child, and we want the
			// parent which is handling out crypto stream do the cleanup
			// and not return the ->handle() caller directly
			exit(1);
		}
#endif
		if (config::uid_change && setuid(final_uid) < 0) {
			err = "FAIL: server_session::handle::setuid:";
			err += strerror(errno);
			syslog().log(err);
			exit(1);
		}

		char *a[] = {NULL, NULL, NULL, NULL};

		// dont honor pw shell entry in case of always-login
		if (config::always_login) {
#ifdef ANDROID
			a[0] = strdup("/system/bin/sh");
#else
			a[0] = strdup("/bin/sh");
#endif
		} else
			a[0] = strdup(shell.c_str());

		if (cmd.size() > 0) {
			a[1] = strdup("-c");
			a[2] = strdup(cmd.c_str());
		}

		dup2(iob.slave0(), 0);
		dup2(iob.slave1(), 1);
		dup2(iob.slave2(), 2);

		iob.close_master();
		iob.close_slave();

		ioctl(0, TIOCSCTTY, 0);

		string h = "HOME=";
		h += home;
		char *const env[] = {strdup(h.c_str()), NULL};
		execve(*a, a, env);
		exit(0);
	} else if (pid < 0) {
		err = "server_session::handle::";
		err += strerror(errno);
		return -1;
	}

	if (iob.is_pty())
		logger::login(iob.pts_name(), user, peer_ip);

	if (config::uid_change && setuid(final_uid) < 0) {
		err = "server_session::handle::setuid:";
		err += strerror(errno);
		return -1;
	}

	iob.close_slave();

	char buf[8192], sbuf[const_message_size], rbuf[const_message_size + 1], tag[64];
	fd_set rset;
	ssize_t r = 0;
	int max = iob.master1() > sock ? iob.master1() : sock;
	max = max > iob.master2() ? max : iob.master2();
	++max;
	for (;;) {
		FD_ZERO(&rset);
		FD_SET(sock, &rset);

		// in the pty case, master1 and master2 are the same, thats OK
		FD_SET(iob.master1(), &rset);
		FD_SET(iob.master2(), &rset);
		memset(buf, 0, sizeof(buf));
		memset(sbuf, 0, sizeof(sbuf));
		memset(rbuf, 0, sizeof(rbuf));
		memset(tag, 0, sizeof(tag));

		if (select(max, &rset, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;
			err = "server_session::handle::select:";
			err += strerror(errno);
			return -1;
		}
		if (FD_ISSET(iob.master1(), &rset)) {
			if ((r = read(iob.master1(), buf, sizeof(buf))) <= 0) {
				if (errno == EINTR)
					continue;
				// process died; do a clean SSL_shutdown()
				break;
			}
			if (send_const_chunks("c0-stdout", buf, r) <= 0)
				return -1;
		// in the pty case, this is the same FD_ISSET() as above, as master1 and master2 are equal. thats OK and
		// this else is never taken
		} else if (FD_ISSET(iob.master2(), &rset)) {
			if ((r = read(iob.master2(), buf, sizeof(buf))) <= 0) {
				if (errno == EINTR)
					continue;
				// process died; do a clean SSL_shutdown()
				break;
			}
			if (send_const_chunks("c0-stderr", buf, r) <= 0)
				return -1;
		}
		if (FD_ISSET(sock, &rset)) {
			repeek: r = SSL_peek(ssl, rbuf, const_message_size);
			switch (SSL_get_error(ssl, r)) {
			case SSL_ERROR_NONE:
				break;
			case SSL_ERROR_ZERO_RETURN:
				return 0;
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				goto repeek;
			default:
				err = "server_session::handle::SSL_peek:";
				err += ERR_error_string(ERR_get_error(), NULL);
				return -1;
			}

			if ((size_t)r != const_message_size) {
				usleep(40);
				goto repeek;
			}

			SSL_read(ssl, rbuf, r);
			// must be either command or data
			if (rbuf[0] != 'C' && rbuf[0] != 'D') {
				break;
			}

			unsigned short len = 0;
			char c = 0;
			if (sscanf(rbuf, "%c:%32[^:]:%hu:", &c, tag, &len) != 3) {
				break;
			}

			if (len >= sizeof(sbuf)) {
				break;
			}
			// find last ':'
			char *ptr = strchr(rbuf + 2, ':') + 1;
			if (!ptr)
				break;
			ptr = strchr(ptr, ':') + 1;
			if (!ptr || r - (ptr - rbuf) < (ssize_t)len) {
				break;
			}
			memcpy(sbuf, ptr, len);

			if (c == 'D')
				handle_data(tag, sbuf, len);
			else if (c == 'C')
				handle_command(tag, sbuf, len);
		}
	}

	return 0;
}


