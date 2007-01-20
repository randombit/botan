/*************************************************
* EGD EntropySource Source File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/es_egd.h>
#include <botan/config.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>
#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef PF_LOCAL
  #define PF_LOCAL PF_UNIX
#endif

namespace Botan {

/*************************************************
* EGD_EntropySource Constructor                  *
*************************************************/
EGD_EntropySource::EGD_EntropySource(const std::string& egd_paths)
   {
   std::vector<std::string> path_list = split_on(egd_paths, ':');
   std::vector<std::string> defaults =
      global_config().option_as_list("rng/egd_path");

   for(u32bit j = 0; j != path_list.size(); j++)
      paths.push_back(path_list[j]);
   for(u32bit j = 0; j != defaults.size(); j++)
      paths.push_back(defaults[j]);
   }

/*************************************************
* Gather Entropy from EGD                        *
*************************************************/
u32bit EGD_EntropySource::do_poll(byte output[], u32bit length,
                                  const std::string& path) const
   {
   if(length > 128)
      length = 128;

   sockaddr_un addr;
   std::memset(&addr, 0, sizeof(addr));
   addr.sun_family = PF_LOCAL;

   if(sizeof(addr.sun_path) < path.length() + 1)
      throw Exception("EGD_EntropySource: Socket path is too long");
   std::strcpy(addr.sun_path, path.c_str());

   int fd = socket(addr.sun_family, SOCK_STREAM, 0);
   if(fd == -1) return 0;

   int len = sizeof(addr.sun_family) + std::strlen(addr.sun_path) + 1;
   if(connect(fd, (struct sockaddr*)&addr, len))
      { close(fd); return 0; }

   byte buffer[2];
   buffer[0] = 1;
   buffer[1] = (byte)length;

   if(write(fd, buffer, 2) != 2) { close(fd); return 0; }
   if(read(fd, buffer, 1) != 1)  { close(fd); return 0; }

   ssize_t count = read(fd, output, buffer[0]);

   if(count == -1) { close(fd); return 0; }

   close(fd);

   return count;
   }

/*************************************************
* Gather Entropy from EGD                        *
*************************************************/
u32bit EGD_EntropySource::slow_poll(byte output[], u32bit length)
   {
   for(u32bit j = 0; j != paths.size(); j++)
      {
      u32bit got = do_poll(output, length, paths[j]);
      if(got)
         return got;
      }
   return 0;
   }

}
