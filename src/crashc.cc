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
#include <cerrno>
#include <string>
#include <signal.h>
#include <sys/resource.h>
#include <termios.h>
#include <signal.h>

#include "config.h"
#include "session.h"
#include "global.h"


using namespace std;
using namespace crash;


void help(const char *p)
{
	printf("\nUsage:\t%s [-6] [-v] [-H host] [-p port] [-L [ip]:port] [-i auth keyfile]\n"
	       "\t [-K server key/s] [-c cmd] [-S SNI] [-D] [-X IP] [-U lport:[ip]:rport]\n"
	       "\t [-T lport:[ip]:rport] [-Y lport:SNI:[ip]:rport [-4 lport] [-5 lport]\n"
	       "\t [-R level] [-N] [-x socks5://[ip]:port] [-t ticket] <-l user>\n\n"
	       "\t -6 -- use IPv6 instead of IPv4\n"
	       "\t -v -- be verbose\n"
	       "\t -H -- host to connect to; if omitted: passive (default)\n"
	       "\t -p -- port to connect to; default is %s\n"
	       "\t -L -- local [ip]:port used for binding (default [0.0.0.0]:0)\n"
	       "\t -i -- private key used for authentication\n"
	       "\t -K -- folder of known host keys if it ends with '/';\n"
	       "\t       absolute path of known-hosts file otherwise;\n"
	       "\t       'none' to disable; default is %s\n"
	       "\t -c -- command to execute on remote host\n"
	       "\t -X -- if proxying is enabled, bind to this IP (default 127.0.0.1)\n"
	       "\t -N -- enable DNS resolving in SOCKS5 proxy\n"
	       "\t -Y -- forward TLS port lport with SNI to ip:rport on remote site\n"
	       "\t -U -- forward UDP port lport to ip:rport on remote site\n"
	       "\t -T -- forward TCP port lport to ip:rport on remote site\n"
	       "\t -4 -- start SOCKS4 server on lport to forward TCP sessions\n"
	       "\t -5 -- start SOCKS5 server on lport to forward TCP sessions\n"
	       "\t -R -- traffic blinding level (0-6, default 1)\n"
	       "\t -D -- use DTLS transport (requires -S)\n"
	       "\t -S -- SNI to use\n"
	       "\t -t -- ticket-file to use for suspend/resume\n"
	       "\t -x -- use this SOCKS5 proxy when connecting\n"
	       "\t -l -- user to login as (no default!)\n\n",
	       p, config::port.c_str(), config::server_keys.c_str());
}


void sig_int(int x)
{
	return;
}


int main(int argc, char **argv)
{
	struct sigaction sa;
	string ostr = "";

	int c = 0, traffic_policy = 1;
	char lport[16] = {0}, port_hex[16] = {0}, ip[128] = {0}, sni[128] = {0};
	uint16_t rport = 0;

	// in client mode we do not bind to a specific port by default
	config::lport = "0";

	while ((c = getopt(argc, argv, "6vhH:K:p:L:X:Y:l:i:c:R:T:U:5:4:S:x:DNt:")) != -1) {
		switch (c) {
		case 't':
			config::ticket = optarg;
			break;
		case 'N':
			config::socks5_dns = 1;
			break;
		case 'D':
			config::transport = "dtls1";
			break;
		case '6':
			if (config::laddr == "0.0.0.0")
				config::laddr = "::";
			config::v6 = 1;
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
		case 'X':
			config::local_proxy_ip = optarg;
			break;
		case 'K':
			config::server_keys = optarg;
			if (config::server_keys == "none")
				config::no_hk_check = 1;
			break;
		case 'l':
			config::user = optarg;
			break;
		case 'i':
			config::user_keys = optarg;
			break;
		case 'c':
			config::cmd = optarg;
			break;
		case 'v':
			config::verbose = 1;
			break;
		case 'R':
			traffic_policy = atoi(optarg);
			break;
		case 'T':
			if (sscanf(optarg, "%15[0-9]:[%127[^]]]:%hu", lport, ip, &rport) == 3) {
				snprintf(port_hex, sizeof(port_hex), "%04hx", rport);
				config::tcp_listens[lport] = string(ip) + "/" + string(port_hex) + "/";
				ostr += "crashc: set up local TCP port " + string(lport) + " to proxy to " + string(ip) + ":" + to_string(rport) + " @ remote.\n";
			}
			break;
		case 'U':
			if (sscanf(optarg, "%15[0-9]:[%127[^]]]:%hu", lport, ip, &rport) == 3) {
				snprintf(port_hex, sizeof(port_hex), "%04hx", rport);
				config::udp_listens[lport] = string(ip) + "/" + string(port_hex) + "/";
				ostr += "crashc: set up local UDP port " + string(lport) + " to proxy to " + string(ip) + ":" + to_string(rport) + " @ remote.\n";
			}
			break;
		case 'Y':
			if (sscanf(optarg, "%15[0-9]:%127[^:]:[%127[^]]]:%hu", lport, sni, ip, &rport) == 4) {
				config::sni2node[sni] = { ip, rport};
				config::tcp_listens[lport] = "SNI";
				ostr += "crashc: set up local TCP port "  + string(lport) + " to proxy for SNI " + sni + " to " + string(ip) + ":" + to_string(rport) + " @ remote.\n";
			}
		case '4':
			if (config::socks4_fd == -1) {
				config::socks4_port = strtoul(optarg, nullptr, 10);
				if ((config::socks4_fd = tcp_listen(config::local_proxy_ip, optarg)) > 0)
					ostr += "crashc: set up SOCKS4 port on " + string(optarg) + "\n";
			}
			break;
		case '5':
			if (config::socks5_fd == -1) {
				config::socks5_port = strtoul(optarg, nullptr, 10);
				if ((config::socks5_fd = tcp_listen(config::local_proxy_ip, optarg)) > 0)
					ostr += "crashc: set up SOCKS5 port on " + string(optarg) + "\n";
			}
			break;
		case 'S':
			config::sni = optarg;
			break;
		case 'x':
			if (sscanf(optarg, "socks5://[%127[^]]]:%hu", ip, &rport) == 2) {
				config::socks5_connect_proxy = ip;
				config::socks5_connect_proxy_port = to_string(rport);
			}
			break;
		default:
			help(*argv);
			return 0;
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sig_winch;
	sigaction(SIGWINCH, &sa, nullptr);
	sa.sa_handler = sig_int;
	sigaction(SIGINT, &sa, nullptr);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, nullptr);

	if (config::user.length() == 0 || (config::transport == "dtls1" && config::sni.empty()) ||
	    (config::transport == "dtls1" && config::socks5_connect_proxy.size() > 0)) {
		printf("\nMissing or invalid combination of options.\n");
		help(*argv);
		return 1;
	}

	if (traffic_policy < 0 || traffic_policy > 6)
		traffic_policy = 1;

	switch (traffic_policy) {
	case 0:
		config::traffic_flags = TRAFFIC_NOPAD;
		break;
	case 1:
		config::traffic_flags = TRAFFIC_PAD1;
		break;
	case 2:
		config::traffic_flags = TRAFFIC_PAD1|TRAFFIC_INJECT|TRAFFIC_PING_IGN;
		break;
	case 3:
		config::traffic_flags = TRAFFIC_PAD1|TRAFFIC_INJECT;
		break;
	case 4:
		config::traffic_flags = TRAFFIC_PADMAX;
		break;
	case 5:
		config::traffic_flags = TRAFFIC_PADMAX|TRAFFIC_INJECT|TRAFFIC_PING_IGN;
		break;
	case 6:
		config::traffic_flags = TRAFFIC_PADMAX|TRAFFIC_INJECT;
	}

	// DTLS (UDP) always needs to inject SQ packets on timeout for RX/TX sync
	if (config::transport == "dtls1")
		config::traffic_flags |= TRAFFIC_INJECT;

	if (config::verbose) {
		fprintf(stderr, "\ncrypted admin shell (C) 2022 Sebastian Krahmer https://github.com/stealth/crash\n\n%s\n", ostr.c_str());
		fprintf(stderr, "crashc: starting crypted administration shell\n");
		if (!config::host.empty())
			fprintf(stderr, "crashc: connecting to [%s]:%s ...\n\n", config::host.c_str(), config::port.c_str());
		else
			fprintf(stderr, "crashc: listen for back-connect on [%s]:%s ...\n\n", config::laddr.c_str(), config::lport.c_str());
	}
	client_session csess(config::ticket, config::transport, config::sni);
	if (csess.setup() < 0) {
		fprintf(stderr, "crashc: %s\n", csess.why());
		return 1;
	}

	if (csess.handle() < 0) {
		fprintf(stderr, "crashc: %s\n", csess.why());
		return 1;
	}

	if (config::verbose) {
		if (csess.suspended())
			fprintf(stderr, "\ncrashc: suspended.\n");
		fprintf(stderr, "crashc: closing connection.\n");
	}

	if (!global::input_received)
		fprintf(stderr, "crashc: No input received. Error. Auth failure?\n");

	return 0;
}

