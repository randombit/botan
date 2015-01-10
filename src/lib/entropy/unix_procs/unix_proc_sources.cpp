/*
* Program List for Unix_EntropySource
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/unix_procs.h>

namespace Botan {

/**
* Default Commands for Entropy Gathering
*/
std::vector<std::vector<std::string>> Unix_EntropySource::get_default_sources()
   {
   std::vector<std::vector<std::string>> srcs;

   srcs.push_back({ "netstat", "-in" });
   srcs.push_back({ "pfstat" });
   srcs.push_back({ "vmstat", "-s" });
   srcs.push_back({ "vmstat" });

   srcs.push_back({ "arp", "-a", "-n" });
   srcs.push_back({ "ifconfig", "-a" });
   srcs.push_back({ "iostat" });
   srcs.push_back({ "ipcs", "-a" });
   srcs.push_back({ "mpstat" });
   srcs.push_back({ "netstat", "-an" });
   srcs.push_back({ "netstat", "-s" });
   srcs.push_back({ "nfsstat" });
   srcs.push_back({ "portstat" });
   srcs.push_back({ "procinfo", "-a" });
   srcs.push_back({ "pstat", "-T" });
   srcs.push_back({ "pstat", "-s" });
   srcs.push_back({ "uname", "-a" });
   srcs.push_back({ "uptime" });

   srcs.push_back({ "listarea" });
   srcs.push_back({ "listdev" });
   srcs.push_back({ "ps", "-A" });
   srcs.push_back({ "sysinfo" });

   srcs.push_back({ "finger" });
   srcs.push_back({ "mailstats" });
   srcs.push_back({ "rpcinfo", "-p", "localhost" });
   srcs.push_back({ "who" });

   srcs.push_back({ "df", "-l" });
   srcs.push_back({ "dmesg" });
   srcs.push_back({ "last", "-5" });
   srcs.push_back({ "ls", "-alni", "/proc" });
   srcs.push_back({ "ls", "-alni", "/tmp" });
   srcs.push_back({ "pstat", "-f" });

   srcs.push_back({ "ps", "-elf" });
   srcs.push_back({ "ps", "aux" });

   srcs.push_back({ "lsof", "-n" });
   srcs.push_back({ "sar", "-A" });

   return srcs;
   }

}
