#ifndef crash_config_h
#define crash_config_h

#include <string>

namespace config
{
	extern bool verbose, silent, v6, uid_change, wrap,
	            always_login, extract_blob;

	extern std::string keyfile, certfile, host, port, local_port;
	extern std::string server_keys, user_keys, user, cmd;

	extern std::string tfile, tmsg, good_ip_file;
}

#endif

