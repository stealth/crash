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

#include <unistd.h>
#include <errno.h>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include "pty.h"
#include "iobox.h"


iobox::iobox()
{
	in[0] = in[1] = -1;
	out[0] = out[1] = -1;
	err[0] = err[1] = -1;

	mode = MODE_INVALID;

	serr = "";
}


iobox::~iobox()
{
	if (mode == MODE_PTY)
		_pty.close();
	else if (mode == MODE_PIPE || mode == MODE_SOCKET) {
		close(in[0]); close(in[1]);
		close(out[0]); close(out[1]);
		close(err[0]); close(err[1]);
	}
}


int iobox::init_pty(uid_t u, gid_t g, mode_t m)
{
	mode = MODE_PTY;

	if (_pty.open() < 0) {
		serr = "iobox::init_pty::";
		serr += _pty.why();
		return -1;
	}
	if (_pty.grant(u, g, m) < 0) {
		serr = "iobox::init_pty::";
		serr += _pty.why();
		return -1;
	}
	return 0;
}


int iobox::init_pipe()
{
	mode = MODE_PIPE;

	if (pipe(in) < 0) {
		serr = "iobox::init_pipe:";
		serr += strerror(errno);
		return -1;
	}
	if (pipe(out) < 0) {
		serr = "iobox::init_pipe:";
		serr += strerror(errno);
		return -1;
	}
	if (pipe(err) < 0) {
		serr = "iobox::init_pipe:";
		serr += strerror(errno);
		return -1;
	}
	return 0;
}


int iobox::init_socket()
{
	mode = MODE_SOCKET;

	if (socketpair(PF_UNIX, SOCK_SEQPACKET, 0, in) < 0) {
		serr = "iobox::init_socket:";
		serr += strerror(errno);
		return -1;
	}
	if (socketpair(PF_UNIX, SOCK_SEQPACKET, 0, out) < 0) {
		serr = "iobox::init_socket:";
		serr += strerror(errno);
		return -1;
	}
	if (socketpair(PF_UNIX, SOCK_SEQPACKET, 0, err) < 0) {
		serr = "iobox::init_socket:";
		serr += strerror(errno);
		return -1;
	}
	return 0;
}


int iobox::slave0()
{
	if (mode == MODE_PTY) {
		return _pty.slave();
	} else {
		return in[0];	// read end for slave stdin
	}

	return -1;
}


int iobox::close_slave0()
{
	if (mode == MODE_PTY) {
		return _pty.close_slave();
	} else {
		close(in[0]);
		in[0] = -1;
		return 0;
	}
	return -1;
}


int iobox::slave1()
{
	if (mode == MODE_PTY) {
		return _pty.slave();
	} else {
		return out[1];	// write end for slave stdout
	}

	return -1;
}


int iobox::close_slave1()
{
	if (mode == MODE_PTY) {
		return _pty.close_slave();
	} else {
		close(out[1]);
		out[1] = -1;
		return 0;
	}

	return -1;
}


int iobox::slave2()
{
	if (mode == MODE_PTY) {
		return _pty.slave();
	} else {
		return err[1];	// write end for slave stderr
	}

	return -1;
}


int iobox::close_slave2()
{
	if (mode == MODE_PTY) {
		return _pty.close_slave();
	} else {
		close(err[1]);
		err[1] = -1;
		return 0;
	}

	return -1;
}


int iobox::master0()
{
	if (mode == MODE_PTY) {
		return _pty.master();
	} else {
		return in[1];	// write end for what appears on slave stdin
	}

	return -1;
}


int iobox::close_master0()
{
	if (mode == MODE_PTY) {
		return _pty.close_master();
	} else {
		close(in[1]);
		in[1] = -1;
		return -1;
	}

	return -1;

}


int iobox::master1()
{
	if (mode == MODE_PTY) {
		return _pty.master();
	} else {
		return out[0];	// read end for slave's stdout
	}

	return -1;
}


int iobox::close_master1()
{
	if (mode == MODE_PTY) {
		return _pty.close_master();
	} else {
		close(out[0]);
		out[0] = -1;
		return 0;
	}

	return -1;
}


int iobox::master2()
{
	if (mode == MODE_PTY) {
		return _pty.master();
	} else {
		return err[0];	// read end for slave's stderr
	}

	return -1;
}


int iobox::close_master2()
{
	if (mode == MODE_PTY) {
		return _pty.close_master();
	} else {
		close(err[0]);
		err[0] = -1;
		return 0;
	}

	return -1;
}


int iobox::close_master()
{
	if (mode == MODE_PTY) {
		return _pty.close_master();
	} else {
		close_master0();
		close_master1();
		close_master2();
		return 0;
	}

	return -1;
}


int iobox::close_slave()
{
	if (mode == MODE_PTY) {
		return _pty.close_slave();
	} else {
		close_slave0();
		close_slave1();
		close_slave2();
		return 0;
	}

	return -1;
}

