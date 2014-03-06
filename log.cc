/*
 * Copyright (C) 2009 Sebastian Krahmer.
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
#include <utmp.h>
#include <fcntl.h>
#include "log.h"
#include "config.h"

#ifdef __FreeBSD__
#include <libutil.h>
#endif

using namespace std;

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
		syslog(LOG_NOTICE, "%s", msg.c_str());
}


logger &syslog()
{
	static logger L;
	return L;
}


#ifdef ANDROID
void logger::login(const string &dev, const string &user, const string &host)
{
}

#else

void logger::login(const string &dev, const string &user, const string &host)
{
	if (config::silent)
		return;

	struct utmp ut;
	memset(&ut, 0, sizeof(ut));
#ifndef __FreeBSD__
	ut.ut_pid = getpid();
	ut.ut_type = USER_PROCESS;
#endif
	const char *ptr = NULL;
	if (strstr(dev.c_str(), "/dev/"))
		ptr = dev.c_str() + 5;
	else
		ptr = dev.c_str();

	snprintf(ut.ut_line, sizeof(ut.ut_line), "%s", ptr);
	snprintf(ut.ut_name, sizeof(ut.ut_name), "%s", user.c_str());
#ifndef __FreeBSD__
	snprintf(ut.ut_id, sizeof(ut.ut_id), "%04x", ut.ut_pid);
#endif
#ifndef __sun__
	snprintf(ut.ut_host, sizeof(ut.ut_host), "%s", host.c_str());
#endif

	struct timeval tv;
	gettimeofday(&tv, NULL);
	ut.ut_time = tv.tv_sec;

#ifdef __sun__
	utmpname("/var/adm/utmpx");
#else
#if !defined __FreeBSD__
	utmpname("/var/run/utmp");
#endif
#endif

#ifdef __FreeBSD__
	::login(&ut);
#else
	setutent();
	pututline(&ut);
	endutent();
#endif

#ifdef __sun__
	int fd = open("/var/adm/wtmpx", O_WRONLY|O_APPEND);
#else
	int fd = open("/var/log/wtmp", O_WRONLY|O_APPEND);
#endif
	if (fd < 0)
		return;
	write(fd, &ut, sizeof(struct utmp));
	close(fd);
}

#endif

#ifdef ANDROID
void logger::logout(pid_t pid)
{
}

#else

void logger::logout(pid_t pid)
{
	if (config::silent)
		return;

	struct timeval tv;
	gettimeofday(&tv, NULL);

	struct utmp ut;
	memset(&ut, 0, sizeof(ut));

#ifdef __sun__
	utmpname("/var/adm/utmpx");
#else
#if !defined __FreeBSD__
	utmpname("/var/run/utmp");
#endif
#endif

#ifndef __FreeBSD__
	setutent();
	struct utmp *t = NULL;
	for (;;) {
#if !defined __sun__ && !defined EMBEDDED
		getutent_r(&ut, &t);
#else
		t = getutent();
#endif
		if (!t)
			break;
		if (t->ut_pid != pid || t->ut_type != USER_PROCESS)
			continue;
		t->ut_type = DEAD_PROCESS;
		t->ut_time = tv.tv_sec;
		memset(t->ut_name, 0, sizeof(t->ut_name));
		setutent();
		pututline(t);
		break;
	}
	endutent();

#ifdef __sun__
	utmpname("/var/run/wtmpx");
#else
	utmpname("/var/log/wtmp");
#endif
	setutent();
	for (;;) {
#if !defined __sun__ && !defined EMBEDDED
		getutent_r(&ut, &t);
#else
		t = getutent();
#endif
		if (!t)
			break;
		if (t->ut_pid != pid || t->ut_type != USER_PROCESS)
			continue;
		t->ut_type = DEAD_PROCESS;
		t->ut_time = tv.tv_sec;
		t->ut_exit.e_termination = 0;
		t->ut_exit.e_exit = 0;
		memset(t->ut_name, 0, sizeof(t->ut_name));
#ifndef __sun__
		memset(t->ut_host, 0, sizeof(t->ut_host));
#endif
		break;
	}
	endutent();

#ifdef __sun__
	int fd = open("/var/adm/wtmpx", O_WRONLY|O_APPEND);
#else
	int fd = open("/var/log/wtmp", O_WRONLY|O_APPEND);
#endif
	if (fd < 0)
		return;
	write(fd, t, sizeof(struct utmp));
	close(fd);
#endif // ! __FreeBSD__
}

#endif

