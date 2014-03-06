/*
 * Copyright (C) 2001-2009 Sebastian Krahmer.
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
#include "pty.h"
#include <sys/types.h>
#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <string>
#include <cstring>

#ifdef __sun__
#include <sys/ioctl.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#endif

pty98::pty98(const pty98 &rhs)
	: pty(rhs)
{
}

pty98 &pty98::operator=(const pty98 &rhs)
{
	pty::operator=(rhs);
	return *this;
}

int pty98::open()
{
#ifdef HAVE_UNIX98 
	m = "/dev/ptmx";

	if ((_master = ::open(m.c_str(), O_RDWR|O_NOCTTY)) < 0) {
		serr = strerror(errno);
		return -1;
	}
	if (grantpt(_master) < 0) {
		::close(_master);
		serr = strerror(errno);
		return -1;
	}

	unlockpt(_master);
#ifdef __linux__
	char buf[1024];
	memset(buf, 0, sizeof(buf));
	ptsname_r(_master, buf, sizeof(buf));
	s = buf;
#else
	s = ptsname(_master);
#endif

	if ((_slave = ::open(s.c_str(), O_RDWR|O_NOCTTY)) < 0) {
		::close(_master);
		serr = strerror(errno);
		return -1;
	}
#ifdef __sun__
	ioctl(_slave, I_PUSH, "ptem");
	ioctl(_slave, I_PUSH, "ldterm");
	ioctl(_slave, I_PUSH, "ttcompat");
#endif

#endif
	return 0;
}

