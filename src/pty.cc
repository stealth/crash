/*
 * Copyright (C) 2001-2021 Sebastian Krahmer.
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

#ifdef __linux__
#define _POSIX_C_SOURCE  200809L
#endif

#include "pty.h"
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <sys/stat.h>
#include <string>
#include <cstring>

using namespace std;

pty::pty(const pty &rhs)
{
	if (this == &rhs)
		return;
	_slave = dup(rhs._slave); _master = dup(rhs._master);
	m = rhs.m; s = rhs.s;
}

pty &pty::operator=(const pty &rhs)
{
	if (this == &rhs)
		return *this;
	_slave = dup(rhs._slave); _master = dup(rhs._master);
	m = rhs.m; s = rhs.s;
	return *this;
}


// Open master+slave terminal
// returns 0 on sucess, -1 on failure
int pty::open()
{
#ifdef OLD_BSD_PTY
	char ptys[] = "/dev/ptyXY";
	const char *it1 = "pqrstuvwxyzPQRST",
	           *it2 = "0123456789abcdef";

	for (; *it1 != 0; ++it1) {
		ptys[8] = *it1;
		for (; *it2 != 0; ++it2) {
			ptys[9] = *it2;

			// do master-part
			if ((_master = ::open(ptys, O_RDWR|O_NOCTTY)) < 0) {
				if (errno == ENOENT) {
					serr = strerror(errno);
					return -1;
				} else
					continue;
			}
			m = ptys;
			ptys[5] = 't';

			// master finished. Do slave-part.
			if ((_slave = ::open(ptys, O_RDWR|O_NOCTTY)) < 0) {
				::close(_master);
				serr = strerror(errno);
				return -1;
			}
			s = ptys;
			return 0;
		}
	}

	// out of terminals
	serr = "Out of ptys.";
	return -1;

#else
	if ((_master = posix_openpt(O_RDWR|O_NOCTTY)) < 0) {
		serr = strerror(errno);
		return -1;
	}

	grantpt(_master);
	unlockpt(_master);
	s = ptsname(_master);

	// master finished. Do slave-part.
	if ((_slave = ::open(s.c_str(), O_RDWR|O_NOCTTY)) < 0) {
		::close(_master);
		serr = strerror(errno);
		return -1;
	}

	return 0;
#endif
}


int pty::close_slave()
{
	::close(_slave);
	_slave = -1;
	return 0;
}


int pty::close_master()
{
	::close(_master);
	_master = -1;
	return 0;
}


int pty::close()
{
	if (_master > -1) {
		::close(_master);
		_master = -1;
	}
	if (_slave > -1) {
		::close(_slave);
		_slave = -1;
	}
	return 0;
}

int pty::grant(uid_t u, gid_t g, mode_t mode)
{
#ifdef OLD_BSD_PTY
	if (fchmod(_master, mode) < 0 || fchmod(_slave, mode) < 0) {
		serr = strerror(errno);
		return -1;
	}
	if (fchown(_master, u, g) < 0 || fchown(_slave, u, g) < 0) {
		serr = strerror(errno);
		return -1;
	}
#else
	if (fchmod(_slave, mode) < 0) {
		serr = strerror(errno);
		return -1;
	}
	if (fchown(_slave, u, g) < 0) {
		serr = strerror(errno);
		return -1;
	}
#endif
	return 0;
}

const char *pty::why()
{
	return serr.c_str();
}

