/*************************************************
* Device EntropySource Source File               *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/es_dev.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <unistd.h>

namespace Botan {

/**
Close the device, if open
*/
void Device_EntropySource::Device_Reader::close()
   {
   if(fd > 0) { ::close(fd); fd = -1; }
   }

/**
Read bytes from a device file
*/
u32bit Device_EntropySource::Device_Reader::get(byte out[], u32bit length,
                                                u32bit ms_wait_time)
   {
   if(fd < 0)
      return 0;

   if(fd >= FD_SETSIZE)
      return 0;

   fd_set read_set;
   FD_ZERO(&read_set);
   FD_SET(fd, &read_set);

   struct ::timeval timeout;
   timeout.tv_sec = 0;
   timeout.tv_usec = ms_wait_time * 1000;

   if(::select(fd + 1, &read_set, 0, 0, &timeout) < 0)
      return 0;

   if(!(FD_ISSET(fd, &read_set)))
      return 0;

   const ssize_t got = ::read(fd, out, length);
   if(got <= 0)
      return 0;

   const u32bit ret = static_cast<u32bit>(got);

   if(ret > length)
      return 0;

   return ret;
   }

/**
Attempt to open a device
*/
Device_EntropySource::Device_Reader::fd_type
Device_EntropySource::Device_Reader::open(const std::string& pathname)
   {
#ifndef O_NONBLOCK
  #define O_NONBLOCK 0
#endif

#ifndef O_NOCTTY
  #define O_NOCTTY 0
#endif

   const int flags = O_RDONLY | O_NONBLOCK | O_NOCTTY;
   return ::open(pathname.c_str(), flags);
   }

/**
Device_EntropySource constructor
*/
Device_EntropySource::Device_EntropySource(
   const std::vector<std::string>& fsnames)
   {
   for(u32bit i = 0; i != fsnames.size(); ++i)
      {
      Device_Reader::fd_type fd = Device_Reader::open(fsnames[i]);
      if(fd > 0)
         devices.push_back(Device_Reader(fd));
      }
   }

/**
* Gather entropy from a RNG device
*/
u32bit Device_EntropySource::slow_poll(byte output[], u32bit length)
   {
   for(size_t i = 0; i != devices.size(); ++i)
      {
      const u32bit got = devices[i].get(output, length, 20);

      if(got)
         return got;
      }

   return 0;
   }

/**
* Fast poll: try limit to 10 ms wait
*/
u32bit Device_EntropySource::fast_poll(byte output[], u32bit length)
   {
   for(size_t i = 0; i != devices.size(); ++i)
      {
      const u32bit got = devices[i].get(output, length, 5);

      if(got)
         return got;
      }

   return 0;
   }

Device_EntropySource::~Device_EntropySource()
   {
   for(size_t i = 0; i != devices.size(); ++i)
      devices[i].close();
   }

}
