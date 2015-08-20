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

#ifndef __iobox_h__
#define __iobox_h__

#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include "pty.h"


typedef enum {
	MODE_INVALID	= 0,
	MODE_PTY	= 1,
	MODE_PIPE	= 2
} iobox_mode_t;


/* an I/O layer abstraction class that could be a pty or a pipe,
 * depending on whether an pty needs to be allocated or not. This makes the
 * session loop much more readable.
 * In the pty case, slave0, slave1, slave2 are all the same as only one pty
 * is needed for IPC. In pipe case, theres a pipe pair for each slave0/master0,
 * slave1/master1, slave2/master2 so that the session loop can distinguish between
 * stdout and stderr writes of the child and can mux this through the crash client.
 * This is good for some programs which require stdout/stderr split to distinguish
 * output data from errors (such as opmsg).
 */

class iobox {

	int in[2], out[2], err[2];

#ifdef HAVE_UNIX98
	pty98 _pty;
#else
	pty _pty;
#endif

	iobox_mode_t mode;

	std::string serr;

public:

	const char *why() { return serr.c_str(); }

	iobox();

	~iobox();

	bool is_pty() { return mode == MODE_PTY; }

	int init_pipe();

	int init_pty(uid_t, gid_t, mode_t);

	int slave0();

	int close_slave0();

	int slave1();

	int close_slave1();

	int slave2();

	int close_slave2();

	int master0();

	int close_master0();

	int master1();

	int close_master1();

	int master2();

	int close_master2();

	int close_master();

	int close_slave();

	const std::string pts_name()
	{
		if (mode == MODE_PTY)
			return _pty.sname();
		return "";
	}

};


#endif
