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

#ifndef crash_session_h
#define crash_session_h

#include <poll.h>
#include <map>
#include <unistd.h>
#include <string>
#include <cstdint>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <termios.h>

#include "net.h"
#include "misc.h"
#include "iobox.h"

extern "C" {
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
}


namespace crash {


class session {

protected:

	std::string d_err{""};
	std::string d_transport{"tls1"}, d_sni{""};

	// keep sent packets in DGRAM case in a tx map for requested resends
	// and keep rx packets that arrived out of order for later processing
	std::map<sequence_t, std::string> d_tx_map, d_rx_map;

	SSL *d_ssl{nullptr};

	EVP_PKEY *d_pubkey{nullptr}, *d_privkey{nullptr};

	state *d_fd2state{nullptr};

	pollfd *d_pfds{nullptr};

	string::size_type d_last_ssl_qlen = 0;

	struct {
		// next TX seq# to come in the next send, next RX seq# to be expected on receive
		sequence_t tx_sequence{1}, rx_sequence{1};

		// last acknowledged RX seq# by peer, detected lost packet with seq#
		sequence_t last_rx_seen{0}, packet_loss{0};

		// last seq# that we acked to peer, last tx seq# that we injected a SQ pkt
		sequence_t last_rx_acked{0}, last_tx_sq_added{0};
	} d_flow;

	struct {
		int max{TCP_POLL_TO}, next{TCP_POLL_TO}, min{100};
	} d_poll_to;

	time_t d_now{0};

	uint32_t d_net_cmd_flags{0};

	int d_peer_fd{-1}, d_family{AF_INET}, d_type{SOCK_STREAM}, d_max_fd{0};

	unsigned int d_chunk_size{TCP_CHUNK_SIZE};

	uint16_t d_major{3}, d_minor{0};

	// my own stringview for optimization of tx_string() in C++11 that doesn't have it yet
	class strview {
		const char *d_cstr{nullptr};
		std::string::size_type d_size{0};
	public:

		// not owning
		strview(const std::string &s) { d_cstr = s.c_str(); d_size = s.size(); }

		strview(const char *cptr, std::string::size_type l) { d_cstr = cptr; d_size = l; }

		const char *c_str() const { return d_cstr; }

		const std::string::size_type size() const { return d_size; }
	};

	int tx_add(int, const std::string &);

	int tx_remove(int i, string::size_type);

	strview tx_string(int fd, std::string &bk_str)
	{
		sequence_t s = 0;
		return tx_string(fd, s, bk_str);
	}

	strview tx_string(int, sequence_t &, std::string &, std::string::size_type max = CHUNK_SIZE);

	std::string tx_string_and_clear(int, std::string::size_type max = 0);

	std::string::size_type tx_size(int);

	void tx_clear(int);

	bool tx_empty(int);

	bool tx_can_add(int);

	int tx_add_sq(int);

	bool tx_must_add_sq(int);

	virtual int authenticate() = 0;

	virtual int handle_input(int) = 0;

	int net_cmd_handler(const std::string &);

public:

	session(const std::string &, const std::string &);

	virtual ~session();

	const char *why()
	{
		return d_err.c_str();
	}
};


class client_session : public session {

	std::string d_sbanner{""};

	struct termios d_tattr, d_old_tattr;

	SSL_CTX *d_ssl_ctx{nullptr};

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	const SSL_METHOD *d_ssl_method{nullptr};
#else
	SSL_METHOD *d_ssl_method{nullptr};
#endif

	bool d_has_tty{0};

protected:

	int send_window_size();

	int check_server_key();

	virtual int authenticate() override;

	virtual int handle_input(int) override;

public:

	client_session(const std::string &t, const std::string &sni)
	 : session(t, sni)
	{
	}

	~client_session();

	int setup();

	int handle();
};



class server_session : public session {

	int d_stdin_closed{0};

	std::string d_user{""}, d_cmd{""}, d_home{""}, d_shell{""};

	std::string d_banner{"1000 crashd-3.0000 OK\r\n"};	// keep in sync with d_major and d_minor

	iobox d_iob;

	uid_t d_final_uid{0xffff};
	char d_peer_ip[64]{0};

protected:

#if defined LIBRESSL_VERSION_NUMBER || defined BORINGSSL_API_VERSION
	char d_dlisten_param[128]{0};
#else
	BIO_ADDR *d_dlisten_param{nullptr};
#endif

	virtual int authenticate() override;

	virtual int handle_input(int) override;

public:

	server_session(int, const std::string &, const std::string &);

	~server_session();

	int handle(SSL_CTX *);

};

}

#endif

