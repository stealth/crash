#include <sys/types.h>
#include <map>
#include <string>


namespace global {

	bool window_size_changed = 0;

	pid_t crashd_pid = 0;

	std::map<std::string, unsigned int> good_ips;
}

