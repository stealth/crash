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

#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include "pty.h"
#include "iobox.h"


iobox::iobox()
{
}


iobox::~iobox()
{
	if (d_mode == MODE_PTY)
		d_pty.close();
	else if (d_mode == MODE_PIPE || d_mode == MODE_SOCKET) {
		close(d_in[0]); close(d_in[1]);
		close(d_out[0]); close(d_out[1]);
		close(d_err[0]); close(d_err[1]);
	}
}


int iobox::init_pty(uid_t u, gid_t g, mode_t m)
{
	d_mode = MODE_PTY;

	if (d_pty.open() < 0) {
		d_serr = "iobox::init_pty::";
		d_serr += d_pty.why();
		return -1;
	}
	if (d_pty.grant(u, g, m) < 0) {
		d_serr = "iobox::init_pty::";
		d_serr += d_pty.why();
		return -1;
	}
	return 0;
}


int iobox::init_pipe()
{
	d_mode = MODE_PIPE;

	if (pipe(d_in) < 0) {
		d_serr = "iobox::init_pipe:";
		d_serr += strerror(errno);
		return -1;
	}
	if (pipe(d_out) < 0) {
		d_serr = "iobox::init_pipe:";
		d_serr += strerror(errno);
		return -1;
	}
	if (pipe(d_err) < 0) {
		d_serr = "iobox::init_pipe:";
		d_serr += strerror(errno);
		return -1;
	}
	return 0;
}


int iobox::init_socket()
{
	d_mode = MODE_SOCKET;

	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, d_in) < 0) {
		d_serr = "iobox::init_socket:";
		d_serr += strerror(errno);
		return -1;
	}
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, d_out) < 0) {
		d_serr = "iobox::init_socket:";
		d_serr += strerror(errno);
		return -1;
	}
	if (socketpair(PF_UNIX, SOCK_DGRAM, 0, d_err) < 0) {
		d_serr = "iobox::init_socket:";
		d_serr += strerror(errno);
		return -1;
	}
	return 0;
}


int iobox::slave0()
{
	if (d_mode == MODE_PTY) {
		return d_pty.slave();
	} else {
		return d_in[0];	// read end for slave stdin
	}

	return -1;
}


int iobox::close_slave0()
{
	if (d_mode == MODE_PTY) {
		return d_pty.close_slave();
	} else {
		close(d_in[0]);
		d_in[0] = -1;
		return 0;
	}
	return -1;
}


int iobox::slave1()
{
	if (d_mode == MODE_PTY) {
		return d_pty.slave();
	} else {
		return d_out[1];	// write end for slave stdout
	}

	return -1;
}


int iobox::close_slave1()
{
	if (d_mode == MODE_PTY) {
		return d_pty.close_slave();
	} else {
		close(d_out[1]);
		d_out[1] = -1;
		return 0;
	}

	return -1;
}


int iobox::slave2()
{
	if (d_mode == MODE_PTY) {
		return d_pty.slave();
	} else {
		return d_err[1];	// write end for slave stderr
	}

	return -1;
}


int iobox::close_slave2()
{
	if (d_mode == MODE_PTY) {
		return d_pty.close_slave();
	} else {
		close(d_err[1]);
		d_err[1] = -1;
		return 0;
	}

	return -1;
}


int iobox::master0()
{
	if (d_mode == MODE_PTY) {
		return d_pty.master();
	} else {
		return d_in[1];	// write end for what appears on slave stdin
	}

	return -1;
}


int iobox::close_master0()
{
	if (d_mode == MODE_PTY) {
		return d_pty.close_master();
	} else {
		close(d_in[1]);
		d_in[1] = -1;
		return -1;
	}

	return -1;

}


int iobox::master1()
{
	if (d_mode == MODE_PTY) {
		return d_pty.master();
	} else {
		return d_out[0];	// read end for slave's stdout
	}

	return -1;
}


int iobox::close_master1()
{
	if (d_mode == MODE_PTY) {
		return d_pty.close_master();
	} else {
		close(d_out[0]);
		d_out[0] = -1;
		return 0;
	}

	return -1;
}


int iobox::master2()
{
	if (d_mode == MODE_PTY) {
		return d_pty.master();
	} else {
		return d_err[0];	// read end for slave's stderr
	}

	return -1;
}


int iobox::close_master2()
{
	if (d_mode == MODE_PTY) {
		return d_pty.close_master();
	} else {
		close(d_err[0]);
		d_err[0] = -1;
		return 0;
	}

	return -1;
}


int iobox::close_master()
{
	if (d_mode == MODE_PTY) {
		return d_pty.close_master();
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
	if (d_mode == MODE_PTY) {
		return d_pty.close_slave();
	} else {
		close_slave0();
		close_slave1();
		close_slave2();
		return 0;
	}

	return -1;
}

