#include <map>
#include <cstdint>
#include <string>
#include <utility>
#include "misc.h"

namespace config
{
	bool verbose = 0, silent = 0, v6 = 0, uid_change = 1, wrap = 0,
	     always_login = 0, extract_blob = 0, no_hk_check = 0, no_net = 0, socks5_dns = 0, allow_roam = 0;

	uint32_t traffic_flags = crash::TRAFFIC_PAD1, traffic_multiply = 0;

	std::string keyfile = "./serverkey.priv", certfile = "./serverkey.pub";
	std::string host = "", port = "2222", laddr = "0.0.0.0", lport = "2222", local_proxy_ip = "127.0.0.1", sni = "", ticket = "";

	std::string transport = "tls1";

	// If ends with "/", its interpreted as current
	// subdirectory that contains the known server pubkeys;
	// otherwise as a absolute path for the file containing the
	// server pubkey
	std::string server_keys = ".crash/";

	// Two meanings: for server:
	// If starts with "/", its interpreted as the absolute path
	// of the file containing the auth-key (be CAREFULL since this
	// may open root-hole, depending on permission of the file).
	// otherwise, its interpreted as ~/$user_keys/authorized_keys
	// where ~ depends on the user that wants to authenticate
	// for client: this should be the absolute path of the file
	// containing the private key used to authenticate against
	// the server
	std::string user_keys = ".crash";

	std::string user = "";
	std::string cmd = "";

	// trigger-file / trigger-message
	std::string tfile = "/var/log/messages", tmsg = "";

	std::string good_ip_file = "";

	std::string disguise_method = "", disguise_secret = "", disguise_action = "";

	std::string socks5_connect_proxy = "", socks5_connect_proxy_port = "";

	std::map<std::string, std::string> tcp_listens, udp_listens;

	std::map<std::string, std::pair<std::string, uint16_t>> sni2node;

	int socks5_port = -1, socks5_fd = -1, socks4_port = -1, socks4_fd = -1;
}

