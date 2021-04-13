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

#ifndef crash_pty_h
#define crash_pty_h

#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string>

using namespace std;

// A BSD 4.3+ PTY API.
class pty {
protected:
	// file-descriptors for terminal
	int _master{-1}, _slave{-1};

	// names of device-files
	string m{""}, s{""}, serr{""};
public:
	pty()
	{
	}

	virtual ~pty()
	{
		close();
	}

	// Copy-constructor
	pty(const pty &rhs);

	// Assign-operator
	pty &operator=(const pty &rhs);

	// open master+slave terminal
	virtual int open();

	// close both
	int close();

	int close_master();

	int close_slave();

	int master() { return _master; }

	int slave() { return _slave; }

	string mname() { return m; }

	string sname() { return s; }

	// do chown, chmod
	virtual int grant(uid_t, gid_t, mode_t);

	const char* why();
};

class pty98 : public pty {
public:
	pty98() : pty() {}

	virtual ~pty98() {}


	pty98(const pty98 &);

	pty98 &operator=(const pty98 &);

	virtual int open();

	virtual int grant(uid_t, gid_t, mode_t);
};


#endif
