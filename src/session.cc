/*
 * Copyright (C) 2009-2024 Sebastian Krahmer.
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

#include <map>
#include <string>
#include <cstdint>
#include <cstdio>
#include <sys/socket.h>
#include <sys/types.h>

extern "C" {
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
}

#include "net.h"
#include "config.h"
#include "session.h"
#include "missing.h"


namespace crash {


session::session(const string &t, const string &sni)
	: d_transport(t), d_sni(sni)
{
	if (d_transport == "dtls1") {
		d_type = SOCK_DGRAM;
		d_chunk_size = UDP_CHUNK_SIZE;
		d_poll_to.max = d_poll_to.next = UDP_POLL_TO;
		d_bio_peer = BIO_ADDR_new();
	}
	d_now = time(nullptr);
}


session::~session()
{
	if (d_bio_peer)
		crash::BIO_ADDR_free(d_bio_peer);

	// OK to free d_bio, as we up_refed +1 for ourself just
	// after creating and BIO_free_all() as called on SSL_free()
	// will only free (downref) its copies
	BIO_free(d_bio);

	if (d_ssl) {
		SSL_shutdown(d_ssl);
		SSL_free(d_ssl);
	}
	if (d_pubkey)
		EVP_PKEY_free(d_pubkey);
	if (d_privkey)
		EVP_PKEY_free(d_privkey);

	if (d_type == SOCK_STREAM)
		shutdown(d_peer_fd, SHUT_RDWR);

	if (d_fd2state) {
		for (int i = 3; i <= d_max_fd; ++i) {
			if (d_fd2state[i].state != STATE_INVALID)
				close(i);
		}
		delete [] d_fd2state;
	}

	delete [] d_pfds;

	close(d_peer_fd);
}


int session::tx_add_mult(int fd, const string &s)
{
	tx_add(fd, s);

	// If traffic multiplier is configured, do so for data packets
	if (config::traffic_multiply > 1 && d_fd2state[fd].state == STATE_SSL) {
		for (uint32_t i = 1; i < config::traffic_multiply; ++i) {
			string np = "";

			if (pad_nops(np) > 0)
				tx_add(fd, np);
		}
	}

	return 0;
}


int session::tx_add(int fd, const string &s)
{
	d_fd2state[fd].tx_len += s.size();

	if (d_fd2state[fd].state == STATE_SSL && d_type == SOCK_DGRAM) {
		d_fd2state[fd].ovec.push_back(s);
	} else {
		if (d_fd2state[fd].ovec.empty())
			d_fd2state[fd].ovec.push_back(s);
		else
			d_fd2state[fd].ovec[0] += s;
	}

	return 0;
}


int session::tx_remove(int fd, string::size_type n)
{

	if (d_fd2state[fd].ovec.empty())
		return 0;

	if (d_fd2state[fd].state == STATE_SSL && d_type == SOCK_DGRAM) {
		return 0;	// No removing of dgram data. It was already removed by tx_string().
	} else {
		d_fd2state[fd].ovec[0].erase(0, n);
	}

	if (n <= d_fd2state[fd].tx_len)
		d_fd2state[fd].tx_len -= n;
	else
		d_fd2state[fd].tx_len = 0;

	return 0;
}


string::size_type session::tx_size(int fd)
{
	return d_fd2state[fd].tx_len;
}


session::strview session::tx_string(int fd, sequence_t &seq, string &bk_str, string::size_type max)
{
	bk_str.clear();
	seq = 0;

	strview sv = bk_str;

	if (d_fd2state[fd].ovec.empty())
		return sv;

	// only SSL sockets need special treatments of dgram/stream/sequenced packets,
	// other out-buffers such as for pty, stdout etc just get the plain data
	if (d_fd2state[fd].state == STATE_SSL) {
		if (d_type == SOCK_STREAM) {
			// Only pad if since last padding new payload data was added to queue.
			// As there is only one socket (d_peer_fd) where we pad outgoing data,
			// one variable (d_last_ssl_qlen) is sufficient and we don't need to have
			// a variable inside d_fd2state.
			if (d_last_ssl_qlen < d_fd2state[fd].ovec[0].size())
				d_fd2state[fd].tx_len += pad_nops(d_fd2state[fd].ovec[0]);

			if (d_fd2state[fd].ovec[0].size() > max)
				sv = { d_fd2state[fd].ovec[0].c_str(), max };
			else
				sv = { d_fd2state[fd].ovec[0].c_str(), d_fd2state[fd].ovec[0].size() };
		} else {
			bool nop_only = 0;
			auto it = d_fd2state[fd].ovec.begin();
			for (; it != d_fd2state[fd].ovec.end(); ++it) {

				// SQ-packets, already sequenced packets (via d_tx_map<> resend) and pure NOPs only as single dgrams
				if (it->find("C:SQ:") == 6 || it->find("C:PN:") == 6 || it->find("C:NO:") == 6) {
					if (bk_str.empty()) {
						if (it->find("C:NO:") == 6)
							nop_only = 1;
						bk_str = *it++;
					}
					break;
				}
				if (bk_str.size() + it->size() + SEQ_PSIZE <= max)
					bk_str += *it;
				else
					break;
			}

			// In dgram case the data is immediately removed from queueing by tx_string(),
			// since SSL socket will be blocking and not writing partial
			// (it is either written at once or not at all) and the final dgram will be kept
			// in d_tx_map<> for a possible resend. This makes modding the ovec[] with :PN:...
			// and pads spanning multiple vector entries unnecessary.
			d_fd2state[fd].tx_len -= bk_str.size();
			d_fd2state[fd].ovec.erase(d_fd2state[fd].ovec.begin(), it);

			// If a seq# was added, pass it to upper layer. It may be a resend from d_tx_map<>,
			// in which case no new seq# is added and 'seq' stays 0 to signal this.
			if (prepend_seq(d_flow.tx_sequence, bk_str) > 0)
				seq = d_flow.tx_sequence;

			// If it was a single NOP pkt, its already padded
			if (!nop_only)
				pad_nops(bk_str);

			// dgram case needs to have strview of backing string returned, as content was removed from ovec
			return sv = bk_str;
		}
	} else {
		if (d_fd2state[fd].ovec[0].size() > max)
			sv = { d_fd2state[fd].ovec[0].c_str(), max };
		else
			sv = { d_fd2state[fd].ovec[0].c_str(), d_fd2state[fd].ovec[0].size() };
	}

	return sv;
}


string session::tx_string_and_clear(int fd, string::size_type max)
{
	sequence_t seq = 0;
	string bk_str;
	bk_str.reserve(2*CHUNK_SIZE);

	if (tx_empty(fd))
		return bk_str;

	if (max == 0)
		max = tx_size(fd);

	auto sv = tx_string(fd, seq, bk_str, max);

	// if backing string is empty after return, it means we have SOCK_STREAM based optimization
	// and need to copy the strview, as we are meant to return a string that survives
	// the clearance of ovec buffers
	if (bk_str.empty())
		bk_str = string(sv.c_str(), sv.size());

	// now we have the str, it can be cleared
	tx_clear(fd);

	// no move(), RVO
	return bk_str;
}


bool session::tx_empty(int fd)
{
	return d_fd2state[fd].tx_len == 0;
}


void session::tx_clear(int fd)
{
	d_fd2state[fd].tx_len = 0;
	d_fd2state[fd].ovec.clear();
}


bool session::tx_can_add(int fd)
{
	// only send new dgrams if peer acknowledged us ours within a certain window (peer's RX# is our TX#)
	return (d_type == SOCK_STREAM || (d_flow.tx_sequence - d_flow.last_rx_seen <= MAX_OVEC_SIZE));
}


bool session::tx_must_add_sq(int fd)
{
	if (d_fd2state[fd].state == STATE_INVALID)
		return 0;

	// if we did not send a SQ pkt for quite some time, force one
	if (d_flow.tx_sequence - d_flow.last_tx_sq_added > MAX_OVEC_SIZE)
		return 1;

	return 0;
}


int session::tx_add_sq(int fd)
{
	if (d_fd2state[fd].state == STATE_INVALID)
		return 0;

	char buf[64] = {0};
	snprintf(buf, sizeof(buf) - 1, "%05hu:C:SQ:%016llx:%016llx:", (unsigned short)(6 + 34), d_flow.rx_sequence, d_flow.tx_sequence);

	tx_add(fd, buf);
	d_pfds[fd].events |= POLLOUT;

	d_flow.last_rx_acked = d_flow.rx_sequence;
	d_flow.last_tx_sq_added = d_flow.tx_sequence;

	return 1;
}


// cmd handler that is common for client and server sessions
int session::handle_input(int i)
{
	string &cmd = d_fd2state[i].ibuf;

	if (cmd.size() < 7)
		return 0;

	unsigned short l = 0;
	if (sscanf(cmd.c_str(), "%05hu:", &l) != 1)
		return 0;
	size_t len = l;

	if (len < 6)
		return -1;
	if (cmd.size() < 5 + len)	// 5bytes %05hu + :C:...
		return 0;

	if (d_type == SOCK_DGRAM && cmd.find("C:SQ:", 6) == 6) {
		sequence_t peer_rx = 0, peer_tx = 0;
		if (sscanf(cmd.c_str() + 5, ":C:SQ:%016llx:%016llx:", &peer_rx, &peer_tx) == 2) {

			// up to seq# 'peer_rx' has been received, so remove from our TX map
			for (; d_flow.last_rx_seen < peer_rx; ++d_flow.last_rx_seen)
				d_tx_map.erase(d_flow.last_rx_seen);

			// peer is missing some of our packets?
			if (peer_rx < d_flow.tx_sequence) {

				// re-send some of the missing packets, if any
				for (sequence_t i = peer_rx; i < d_flow.tx_sequence && i - peer_rx <= MAX_OVEC_SIZE/2; ++i) {
					tx_add(d_peer_fd, d_tx_map[i]);
					d_pfds[d_peer_fd].events |= POLLOUT;
				}
			}
		}

	// packet seq number as added by prepend_seq()
	} else if (d_type == SOCK_DGRAM && cmd.find("C:PN:", 6) == 6) {
		sequence_t seq = 0;
		if (sscanf(cmd.c_str() + 5, ":C:PN:%016llx:", &seq) == 1) {

			// keep seq#s that are to be expected in future and try to put some in order
			// that may be found in d_rx_map<>
			if (seq > d_flow.rx_sequence) {

				// :PN: packets wrap the next data packet completely with its len
				d_rx_map[seq] = cmd.substr(0, 5 + len);
				cmd.erase(0, 5 + len);

				// maybe the expected seq# was already put to the d_rx_map<> ?
				if (d_rx_map.count(d_flow.rx_sequence) > 0) {
					cmd.insert(0, move(d_rx_map[d_flow.rx_sequence]));
					d_rx_map.erase(d_flow.rx_sequence);
				}
				return 1;

			// the exact next expected seq#, increase and continue processing
			} else if (seq == d_flow.rx_sequence) {

				// Acknowledge so far, if we received more than half of the window w/o acking them.
				// If we miss this code path due to missing :PN: pkts, the main poll loop will trigger sending
				// acks by timeouts.
				if (d_flow.rx_sequence - d_flow.last_rx_acked >= MAX_OVEC_SIZE/2)
					tx_add_sq(d_peer_fd);

				++d_flow.rx_sequence;
				d_rx_map.erase(seq);	// erase from map in case it was kept

				// Check rx map for possibly next packet to process along and
				// erase from map if any. Insert right behind currently processed packet in this case.
				auto next = d_rx_map.find(d_flow.rx_sequence);
				if (next != d_rx_map.end()) {
					cmd.insert(5 + len, move(next->second));
					d_rx_map.erase(next);
				}

				// :PN: packets wrap the entire packet with its len, so let remove the fixed :PN: seq# hdr
				// to obtain data packet for next processing loop.
				len = SEQ_PSIZE - 5;

			// remove duped packets from queue
			} else {
				;	// done by 'cmd.erase(0, 5 + len);' at end of the function
			}
		}
	// ping request
	} else if (cmd.find("C:PP:", 6) == 6) {
		const string echo = cmd.substr(5 + 6, len - 6);
		tx_add(d_peer_fd, slen(6 + echo.size()) + ":C:PR:" + echo);
		d_pfds[d_peer_fd].events |= POLLOUT;
	} else if (cmd.find("C:T:", 6) == 6 || cmd.find("C:U:", 6) == 6) {

		// also remove cmd from buffer it net handler returns error
		net_cmd_handler(cmd);

	} else if (cmd.find("C:PR:", 6) == 6) {
		;	// ignore ping replies
	} else if (cmd.find("C:NO:", 6) == 6) {
		;	// ignore nops

	// disable traffic padding
	} else if (cmd.find("C:P0:", 6) == 6) {
		config::traffic_flags |= TRAFFIC_NOPAD;
	} else if (cmd.find("C:P1:", 6) == 6) {
		config::traffic_flags &= ~TRAFFIC_NOPAD;
		config::traffic_flags |= TRAFFIC_PADRND;
	} else if (cmd.find("C:P4:", 6) == 6) {
		config::traffic_flags &= ~TRAFFIC_NOPAD;
		config::traffic_flags |= TRAFFIC_PAD1;
	// enable maximum padding
	} else if (cmd.find("C:P9:", 6) == 6) {
		config::traffic_flags &= ~TRAFFIC_NOPAD;
		config::traffic_flags |= TRAFFIC_PADMAX;

	} else {

		// Valid len/data packet but no command handled. Do not erase it, it may be for the derived
		// class. Let them check and erase.
		return 1;
	}

	// One command was handled above. Erase this particular cmd.
	cmd.erase(0, 5 + len);

	// There may be more cmds in the ibuf. Pass to derived class.
	return 1;
}


/*
 * C:T:N:IP/port/ID/		-> open new TCP connection to IP:port
 * C:T:C:IP/port/ID/	  	-> connection to IP:port is estabished on remote side
 * C:T:S:IP/port/ID/data	-> send data to IP:port
 * C:T:R:IP/port/ID/data	-> data received from IP:port on remote side
 * C:T:F:IP/port/ID/		-> close connection belonging to IP:port
 *
 * C:U:S:IP/port/ID/data	-> send UDP datagram to IP:port
 * C:U:R:IP/port/ID/data	-> received UDP datagram from IP:port on remote side
 *
 */
int session::net_cmd_handler(const string &cmd)
{
	char C[16] = {0}, proto[16] = {0}, op[16] = {0}, host[128] = {0};
	uint16_t port = 0, id = 0;
	unsigned short len = 0;
	int sock = -1;

	// ID is the logical channel to distinguish between multiple same host:port connections.
	// The accepted socket fd of the local part is unique and good for it. FDID_MAX ensures it can be encoded as %hx.
	if (sscanf(cmd.c_str(), "%05hu:%15[^:]:%15[^:]:%15[^:]:%127[^/]/%04hx/%04hx/", &len, C, proto, op, host, &port, &id) != 7)
		return 0;

	auto slash = cmd.find("/");
	const string node = string(host) + cmd.substr(slash, 11);

	if (len < 7 + node.size() || len > cmd.size() - 5)
		return 0;

	if (C[0] != 'C' || (proto[0] != 'T' && proto[0] != 'U'))
		return -1;

	// open new non-blocking connection
	if (cmd.find("C:T:N:", 6) == 6 && (d_net_cmd_flags & NETCMD_SEND_ALLOW)) {
		if ((sock = tcp_connect(host, to_string(port))) < 0)
			return -1;

		d_pfds[sock].revents = 0;
		d_pfds[sock].events = POLLOUT;
		d_pfds[sock].fd = sock;

		d_fd2state[sock].fd = sock;
		d_fd2state[sock].state = STATE_CONNECT;
		d_fd2state[sock].odgrams.clear();
		d_fd2state[sock].rnode = node;
		d_fd2state[sock].time = d_now;
		tx_clear(sock);

		tcp_nodes2sock[node] = sock;

	// non-blocking connect() got ready
	} else if (cmd.find("C:T:C:", 6) == 6) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;

		d_pfds[sock].events = POLLIN;

		d_fd2state[sock].fd = sock;
		d_fd2state[sock].state = STATE_CONNECTED;
		d_fd2state[sock].odgrams.clear();
		d_fd2state[sock].time = d_now;
		tx_clear(sock);

	// finish connection
	} else if (cmd.find("C:T:F:", 6) == 6) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;
		tcp_nodes2sock.erase(it);

		// flush any remaining data
		flush_fd(sock, tx_string_and_clear(sock));

		// sock will be closed in main poll() loop via timeout
		shutdown(sock, SHUT_RDWR);
		d_pfds[sock].fd = -1;
		d_pfds[sock].events = 0;

		d_fd2state[sock].state = STATE_CLOSING;
		d_fd2state[sock].odgrams.clear();
		d_fd2state[sock].time = d_now;

	// Send or receive data. No NETCMD_SEND_ALLOW check, since the node will not be in
	// the tcp_nodes2sock map in the first place, as there was no tcp_connect() and no map
	// insertion.
	} else if (cmd.find("C:T:S:", 6) == 6 || cmd.find("C:T:R:", 6) == 6) {
		auto it = tcp_nodes2sock.find(node);
		if (it == tcp_nodes2sock.end())
			return -1;
		sock = it->second;
		tx_add(sock, cmd.substr(5 + 7 + node.size(), len - 7 - node.size()));	// strip off data part
		d_pfds[sock].events |= POLLOUT;
		d_fd2state[sock].time = d_now;

	} else if (cmd.find("C:U:S:", 6) == 6 || cmd.find("C:U:R:", 6) == 6) {
		auto it = udp_nodes2sock.find(node);
		if (it == udp_nodes2sock.end()) {
			if (!(d_net_cmd_flags & NETCMD_SEND_ALLOW))
				return 0;
			if ((sock = udp_connect(host, to_string(port))) < 0)
				return -1;
			udp_nodes2sock[node] = sock;

			// Just fill rnode part in server side. client main loop expects ID/ part not to be
			// appended
			d_fd2state[sock].rnode = node;
			d_fd2state[sock].state = STATE_UDPCLIENT;
			d_fd2state[sock].fd = sock;
		} else
			sock = it->second;

		d_pfds[sock].revents = 0;
		d_pfds[sock].fd = sock;
		d_pfds[sock].events = POLLIN;

		if (cmd.size() > 5 + 7 + node.size()) {
			d_fd2state[sock].odgrams.push_back({id, cmd.substr(5 + 7 + node.size(), len - 7 - node.size())});	// strip off data part (startes after "%05hu:C:U:S")
			d_pfds[sock].events |= POLLOUT;
		}
		d_fd2state[sock].time = d_now;
	}

	return 1;
}


}

