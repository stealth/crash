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

#include <syslog.h>
#include <string>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include "log.h"
#include "config.h"

#ifdef __FreeBSD__
#include <libutil.h>
#endif

using namespace std;

namespace crash {

logger::logger()
{
	openlog("crashd", LOG_NOWAIT|LOG_PID, LOG_DAEMON);
}


logger::~logger()
{
	closelog();
}


void logger::log(const string &msg)
{
	if (!config::silent)
		::syslog(LOG_NOTICE, "%s", msg.c_str());
}


logger &syslog()
{
	static logger L;
	return L;
}


#if defined ANDROID || defined EMBEDDED
void logger::login(const string &dev, const string &user, const string &host)
{
}


void logger::logout(pid_t pid)
{
}


#else

#include <utmpx.h>

void logger::login(const string &dev, const string &user, const string &host)
{
	if (config::silent)
		return;

	struct utmpx utx;
	memset(&utx, 0, sizeof(utx));

	utx.ut_pid = getpid();
	utx.ut_type = USER_PROCESS;

	const char *ptr = nullptr;
	if (strstr(dev.c_str(), "/dev/"))
		ptr = dev.c_str() + 5;
	else
		ptr = dev.c_str();

	snprintf(utx.ut_line, sizeof(utx.ut_line), "%s", ptr);
	snprintf(utx.ut_user, sizeof(utx.ut_user), "%s", user.c_str());
	snprintf(utx.ut_id, sizeof(utx.ut_id), "%04x", utx.ut_pid);

	timeval tv;
	gettimeofday(&tv, nullptr);
	memcpy(&utx.ut_tv, &tv, sizeof(tv));

	setutxent();
	pututxline(&utx);
	endutxent();
}


void logger::logout(pid_t pid)
{
	if (config::silent)
		return;

	timeval tv;
	setutxent();
	struct utmpx *t = nullptr;
	for (;;) {
		t = getutxent();

		if (!t)
			break;
		if (t->ut_pid != pid || t->ut_type != USER_PROCESS)
			continue;
		t->ut_type = DEAD_PROCESS;
		gettimeofday(&tv, nullptr);
		memcpy(&t->ut_tv, &tv, sizeof(tv));
		memset(t->ut_user, 0, sizeof(t->ut_user));
		pututxline(t);
		break;
	}
	endutxent();

}

}

#endif

