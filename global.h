#ifndef crash_global_h
#define crash_global_h

#include <sys/types.h>
#include <string>
#include <map>


namespace global {
	extern bool window_size_changed;
	extern pid_t crashd_pid;
	extern std::map<std::string, unsigned int> good_ips;
}

#endif
