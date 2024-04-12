/*
 * Copyright (C) 2024 Sebastian Krahmer.
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

#include <string>
#include <poll.h>
#include <regex>
#include <sys/time.h>
#include "config.h"
#include "misc.h"

extern "C" {
#include <openssl/ssl.h>
#include <openssl/err.h>
}

namespace crash {


using namespace std;

// -G method:secret:param
// as of now there is only "redirect1" disguise

int disguise_filter(SSL *ssl)
{

	if (config::disguise_method != "redirect1")
		return 1;

	string req = "";
	req.reserve(1024);
	char buf[1024] = {0};

	pollfd pfd = {0};
	if ((pfd.fd = SSL_get_fd(ssl)) < 0)
		return -1;
	pfd.events = POLLIN;

	int pn = 0;

	timeval start = {0}, now = {0};
	gettimeofday(&start, nullptr);

	bool http_complete = 0;
	string::size_type nlnl = string::npos;

	for (;;) {
		gettimeofday(&now, nullptr);

		// timeout -> invalid request?
		if (now.tv_sec - start.tv_sec > 3)
			break;

		if ((pn = poll(&pfd, 1, TCP_POLL_TO)) < 0)
			return -1;
		if (pn == 0)
			continue;

		ssize_t n = SSL_peek(ssl, buf, sizeof(buf));
		switch (SSL_get_error(ssl, n)) {
		case SSL_ERROR_NONE:
			req += string(buf, n);
			break;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			break;
		case SSL_ERROR_ZERO_RETURN:
			// fallthrough
		default:
			return -1;
		}

		// someone who knows, success
		if (req.find(config::disguise_secret) == 0) {

			// We just peeked, so really take these bytes from the layer (according to manpage)
			// SSL_read() must return it w/o error if SSL_peek() did so.
			SSL_read(ssl, buf, config::disguise_secret.size());
			return 1;
		}

		// look for complete HTTP hdr
		if ((nlnl = req.rfind("\r\n\r\n")) != string::npos) {
			http_complete = 1;
			break;
		}
	}

	// should be some sort of HTTP request by now

	struct tm tm = {0};
	char gmt_date[128] = {0};
	gmtime_r(&now.tv_sec, &tm);
	strftime(gmt_date, sizeof(gmt_date), "%a, %d %b %Y %H:%M:%S GMT\r\n", &tm);

	string bad = "HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n";
	bad += "Date: " + string(gmt_date);
	bad += "Content-Type: text/html\r\nContent-Length: 150\r\nConnection: close\r\n\r\n"
	       "<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n"
	       "<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n"
	       "</body>\r\n</html>\r\n";


	if (!http_complete) {
		SSL_write(ssl, bad.c_str(), bad.size());
		return 0;
	}

	auto r = regex("^(POST|GET|HEAD) +/[^ ]* +HTTP/1\\.1\r\n");
	if (regex_search(req, r) != 1) {
		SSL_write(ssl, bad.c_str(), bad.size());
		return 0;
	}

	r = regex("\r\nHost: *[a-zA-Z0-9-_:]+\r\n");
	if (regex_search(req, r) != 1) {
		SSL_write(ssl, bad.c_str(), bad.size());
		return 0;
	}

	// must exist
	string::size_type nl = req.find("\r\n"), prev_nl = string::npos;
	prev_nl = nl + 2;
	nl = req.find("\r\n", prev_nl);

	// Each line after initial GET must be of "Key: Value" form
	for (http_complete = 0; nl != string::npos;) {
		if (nl == nlnl) {
			http_complete = 1;
			break;
		}
		nl += 2;
		if (req.substr(prev_nl, nl - prev_nl).find(":") == string::npos)
			break;
		prev_nl = nl;
		nl = req.find("\r\n", nl);
	}

	if (!http_complete) {
		SSL_write(ssl, bad.c_str(), bad.size());
		return 0;
	}

	string redir = "HTTP/1.1 301 Moved Permanently\r\nServer: nginx\r\n";
	redir += "Date: " + string(gmt_date);
	redir += "Content-Type: text/html\r\nContent-Length: 138\r\nConnection: close\r\n"
	         "Location: " + config::disguise_action + "\r\n\r\n"
	         "<html>\r\n<head><title>301 Found</title></head>\r\n<body>\r\n"
	         "<center><h1>301 Found</h1></center>\r\n<hr><center>nginx</center>\r\n"
	         "</body>\r\n</html>\r\n";

	SSL_write(ssl, redir.c_str(), redir.size());
	return 0;
}

}

