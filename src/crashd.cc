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

#include <iostream>
#include <cstdio>
#include <memory>
#include <cstring>
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
using namespace crash;


void help(const char *p)
{
	printf("\nUsage:\t%s [-U] [-q] [-a] [-6] [-D] [-H host] [-p port] [-A auth keys]\n"
	       "\t [-k server key-file] [-c server X509 cert] [-L [ip]:port] [-S SNI]\n"
	       "\t [-t trigger-file] [-m trigger message] [-e] [-g good IPs] [-N] [-R]\n"
	       "\t [-x socks5://[ip]:port] [-w]\n\n"
	       "\t -a -- always login if authenticated, despite false/nologin shells\n"
	       "\t -U -- run as user (e.g. turn off setuid() calls) if invoked as such\n"
	       "\t -e -- extract key and certfile from the binary itself (no -k/-c needed)\n"
	       "\t -q -- quiet mode, turns off logging and utmp entries\n"
	       "\t -6 -- use IPv6 rather than IPv4\n"
	       "\t -w -- setproctitle to `%s` (must be last arg!)\n"
	       "\t -H -- host to connect to; if omitted: passive connect (default)\n"
	       "\t -p -- port to connect to when active connect; default is %s\n"
	       "\t -L -- local [ip]:port used for binding ([%s]:%s)\n"
	       "\t -g -- file containing list of good IP/IP6's in D/DoS case (default off)\n"
	       "\t -A -- authorized-key file for users if starts with '/'; folder inside ~\n"
	       "\t       containing authorized_keys file otherwise; 'self' means to use\n"
	       "\t       blob-extraction (see -e); default is %s\n"
	       "\t -k -- servers key file; default is %s\n"
	       "\t -c -- X509 certificate-file that belongs to serverkey (-k);\n"
	       "\t       default is %s\n"
	       "\t -t -- watch triggerfile for certain message (-m) before connect/listen\n"
	       "\t -m -- wait with connect/listen until message in file (-t) is seen\n"
	       "\t -N -- disable TCP/UDP port forwarding\n"
	       "\t -D -- use DTLS transport (requires -S)\n"
	       "\t -x -- use this SOCKS5 proxy when using active connect\n"
	       "\t -R -- allow clients to roam sessions\n"
	       "\t -S -- SNI to hide behind\n\n",
	       p, TITLE, config::port.c_str(), config::laddr.c_str(), config::lport.c_str(), config::user_keys.c_str(), config::keyfile.c_str(),
	       config::certfile.c_str());
}


void sig_chld(int)
{
	pid_t pid = 0;
	while ((pid = waitpid(-1, nullptr, WNOHANG)) > 0) {
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
	char *argv0 = strdup(argv[0]);
	int orig_argc = argc;

	// First of all, some ugly parsing, so it can be called
	// via CGI too!
	char *ptr1 = nullptr, *ptr2 = nullptr, *ptr3 = nullptr;
	if ((ptr1 = getenv("QUERY_STRING")) != nullptr) {
		setbuffer(stdout, nullptr, 0);
		printf("Content-Type: text/html\r\n\r\n");
		argv = (char **)malloc(100 * sizeof(char *));
		if (!argv) {
			printf("Out of memory!\n");
			return 1;
		}
		i = 1;
		memset(argv, 0, 100 * sizeof(char *));
		argv[0] = strdup("[nfsd]");

		while (i < 20 && (ptr2 = strchr(ptr1, '&')) != nullptr) {
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
		if ((ptr2 = strchr(ptr1, '=')) != nullptr) {
			*ptr2 = 0;
			argv[i++] = strdup(ptr1);
			if (strcmp(ptr2 + 1, "1"))
				argv[i++] = strdup(ptr2 + 1);
		}
		argc = i;
		for (i = 0; i < argc; ++i)
			printf("%s\r\n\r\n", argv[i]);
	}

	printf("\ncrypted admin shell (C) 2023 Sebastian Krahmer https://github.com/stealth/crash\n\n");

	char ip[128] = {0}, lport[16] = {0};

	while ((c = getopt(argc, argv, "6qhH:p:A:t:m:k:c:L:g:DUweaS:NR")) != -1) {
		switch (c) {
		case 'D':
			config::transport = "dtls1";
			break;
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
			if (config::laddr == "0.0.0.0")
				config::laddr = "::";
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
			strcpy(orig_argv[0], TITLE);
			setproctitle(TITLE);
			break;
		case 'H':
			config::host = optarg;
			break;
		case 'p':
			config::port = optarg;
			break;
		case 'L':
			if (sscanf(optarg, "[%127[^]]]:%15[0-9]", ip, lport) == 2) {
				config::laddr = ip;
				config::lport = lport;
			}
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
		case 'S':
			config::sni = optarg;
			break;
		case 'N':
			config::no_net = 1;
			break;
		case 'R':
			config::allow_roam = 1;
			break;
		case 'x':
			if (sscanf(optarg, "socks5://[%127[^]]]:%15[0-9]", ip, lport) == 2) {
				config::socks5_connect_proxy = ip;
				config::socks5_connect_proxy_port = lport;
			}
			break;
		default:
			help(*orig_argv);
			return 0;
		}
	}

	if (config::transport == "dtls1" && config::sni.empty()) {
		printf("Config error. DTLS option requires SNI. Exiting.\n\n");
		return 1;
	}

	if (config::transport == "tls1" && config::allow_roam) {
		printf("Config error. TCP/TLS sessions cannot roam. Exiting.\n\n");
		return 1;
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = sig_chld;
	sigaction(SIGCHLD, &sa, nullptr);

	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, nullptr);

	sa.sa_handler = sig_alarm;
	sigaction(SIGALRM, &sa, nullptr);

	if (RAND_load_file("/dev/urandom", 256) != 256)
		RAND_load_file("/dev/random", 8);

	if (config::good_ip_file.length() > 0)
		read_good_ips(config::good_ip_file);

	if (fork() != 0)
		return 0;

	global::crashd_pid = getpid();

	//chdir("/"); No, we like to have the possibility to find keyfiles etc in "."
	int max = sysconf(_SC_OPEN_MAX);
	for (i = 0; i <= max; ++i)
		close(i);
	open("/dev/null", O_RDWR|O_NOCTTY);
	dup2(0, 1); dup2(1, 2);
	setsid();

	// If a message-trigger has been given
	if (config::tmsg.length() > 0)
		read_until(config::tfile.c_str(), config::tmsg.c_str());

	// extract key/cert from ELF binary into tmp file
	if (config::extract_blob) {
		config::keyfile = extract_keys(argv0);
		config::certfile = config::keyfile;
		if (config::keyfile.size() == 0)
			return 1;
		if (config::user_keys == "self")
			config::user_keys = config::keyfile;
	}

	Server *s = new (nothrow) Server(config::transport, config::sni);
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

