/*
 * Copyright (C) 2009-2022 Sebastian Krahmer.
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
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <map>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "config.h"
#include "misc.h"
#include "global.h"

#ifdef __linux__
#include <sys/prctl.h>
#endif


using namespace std;

namespace crash {


string slen(unsigned short l)
{
	char buf[32] = {0};
	snprintf(buf, sizeof(buf) - 1, "%05hu", l);
	return buf;
}


int readn(int fd, void *buf, size_t len)
{
	int o = 0, n;
	char *ptr = (char*)buf;

	while (len > 0) {
		if ((n = read(fd, ptr+o, len)) <= 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


int writen(int fd, const void *buf, size_t len)
{
	int o = 0, n = 0;
	const char *ptr = reinterpret_cast<const char *>(buf);

	while (len > 0) {
		if ((n = write(fd, ptr + o, len)) <= 0)
			return n;
		len -= n;
		o += n;
	}
	return o;
}


int flush_fd(int fd, const string &buf)
{
	string::size_type bs = buf.size();

	if (bs == 0)
		return 0;

	ssize_t n = 0;
	size_t idx = 0;
	do {
		size_t wn = bs > 0x1000 ? 0x1000 : bs;
		if ((n = write(fd, buf.c_str() + idx, wn)) <= 0)
			return n;
		idx += n;
		bs -= n;
	} while (bs > 0);

	return idx;
}


size_t prepend_seq(sequence_t n, string &s)
{
	size_t r = 0;

	// no sequencing for Re-sends and SQ packets.
	if (s.find("D:") == 6 || s.find("C:WS:") == 6 || s.find("C:T:") == 6 ||
	    s.find("C:U:") == 6 || s.find("C:CL") == 6 || s.find("C:PP") == 6) {
		char buf[32] = {0};
		snprintf(buf, sizeof(buf) - 1, "%05hu:C:PN:%016llx:", (unsigned short)(6 + 17 + ((unsigned short)(s.size() & 0xffff))), n);
		s.insert(0, buf);
		r = 1;
	}

	return r;
}


size_t pad_nops(string &s)
{

	if (config::traffic_flags & TRAFFIC_NOPAD)
		return 0;

	const uint8_t nop_fix = 5 + 6;	// %05hu:C:NO:

	const auto l = s.size();
	int pads = 0;

	enum { PMAX_SIZE = MSS };

	if (l + nop_fix >= PMAX_SIZE)
		return 0;

	char zeros[PMAX_SIZE] = {0};

	if (config::traffic_flags & TRAFFIC_PADMAX) {
		pads = PMAX_SIZE - l - nop_fix;
	} else {
		if (l + nop_fix > 1024)
			pads = PMAX_SIZE - l - nop_fix;
		else if (l + nop_fix > 512)
			pads = 1024 - l - nop_fix;
		else if (l + nop_fix > 256)
			pads = 512 - l - nop_fix;
		else
			pads = 256 - l - nop_fix;
	}

	// Huh?
	if (pads <= 0 || 5 + 6 + pads >= PMAX_SIZE)
		return 0;

	s += slen(6 + pads);
	s += ":C:NO:";
	s += string(zeros, pads);

	return 5 + 6 + pads;
}


string ping_packet()
{
	if (config::traffic_flags & TRAFFIC_PING_IGN)
		return "00010:C:PR:ping";	// use a ping-reply which is ignored
	else
		return "00010:C:PP:ping";
}


void sig_winch(int x)
{
	global::window_size_changed = 1;
}


void read_until(const char *path, const char *msg)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return;
	fseek(f, 0, SEEK_END);
	char buf[1024];
	for (;;) {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf), f))
			;	// avoid gcc warning
		if (strstr(buf, msg))
			break;
		sleep(3);
	}
	fclose(f);
}


string extract_keys(const char *blob)
{
	char pattern[] = {'-' - 1, '-' - 1, '-' - 1, '-' - 1, '-' - 1,
	                  'B' - 1, 'E' - 1, 'G' - 1, 'I' - 1, 'N' - 1};
	struct stat st;
	int fd = 0;
	unsigned int i = 0;
#ifdef ANDROID
	char tfile[] = "/data/local/tmp/sshXXXXXX";
#else
	char tfile[] = "/tmp/sshXXXXXX";
#endif

	// un-rot
	for (i = 0; i < sizeof(pattern); ++i)
		++pattern[i];

	if (stat(blob, &st) < 0)
		return "";
	char *data = new char[st.st_size];
	if (!data)
		return "";

	if ((fd = open(blob, O_RDONLY|O_NOCTTY)) < 0) {
		delete [] data;
		return "";
	}

	if (read(fd, data, st.st_size) != st.st_size) {
		delete [] data;
		return "";
	}
	close(fd);
	if ((fd = mkstemp(tfile)) < 0) {
		delete [] data;
		return "";
	}
	fchmod(fd, 0444);

	for (i = 0; i < st.st_size - sizeof(pattern); ++i) {
		if (memcmp(data + i, pattern, sizeof(pattern)) == 0)
			break;
	}
	if (i == st.st_size - sizeof(pattern)) {
		delete [] data;
		close(fd);
		return "";
	}

	if (write(fd, data + i, st.st_size - i) < 0)
		;	// avoid gcc warning
	close(fd);
	delete [] data;
	return string(tfile);
}


void read_good_ips(const string &path)
{
	struct in_addr in;
	struct in6_addr in6;
	char buf[1024];

	FILE *f = fopen(path.c_str(), "r");
	if (!f)
		return;
	do {
		memset(buf, 0, sizeof(buf));
		if (!fgets(buf, sizeof(buf), f))
			break;
		strtok(buf, ";#\t \n");
		if (inet_pton(AF_INET6, buf, &in6) == 1 || inet_pton(AF_INET, buf, &in) == 1)
			global::good_ips[buf] = 1;
	} while (!feof(f));
	fclose(f);
}


// You might think that these functions are slow and its stupid to call
// them. Remember that these are called only under a detected D/DoS condition
// and in this case we accept only one connection per second anyway
bool is_good_ip(const struct in_addr &in)
{
	char dst[128];
	if (inet_ntop(AF_INET, &in, dst, sizeof(dst)) == nullptr)
		return 0;
	if (global::good_ips.find(dst) != global::good_ips.end())
		return 1;

	struct in_addr t = in;
	unsigned int n = 0xffffffff;
	for (int i = 1; i <= 24; ++i) {
		t.s_addr &= htonl(n<<i);
		inet_ntop(AF_INET, &t, dst, sizeof(dst));
		if (global::good_ips.find(dst) != global::good_ips.end())
			return 1;
	}
	return 0;
}


bool is_good_ip(const struct in6_addr &in6)
{
	char dst[128];
	if (inet_ntop(AF_INET6, &in6, dst, sizeof(dst)) == nullptr)
		return 0;
	if (global::good_ips.find(dst) != global::good_ips.end())
		return 1;
	return 0;
}


bool is_nologin(const string &shell)
{
	if (shell.find("false") != string::npos)
		return 1;
	if (shell.find("nologin") != string::npos)
		return 1;
	return 0;
}


void setproctitle(const string &proc)
{
#ifndef __linux__
	::setproctitle("%s", proc.c_str());
#else
	prctl(PR_SET_NAME, proc.c_str(), 0, 0, 0);
#endif
}

}

