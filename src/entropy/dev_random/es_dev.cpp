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
Device_EntropySource::Device_Reader::~Device_Reader()
   {
   if(fd > 0) { ::close(fd); }
   }

/**
Read bytes from a device file
*/
u32bit Device_EntropySource::Device_Reader::get(byte out[], u32bit length)
   {
   if(fd < 0)
      return 0;

   if(fd >= FD_SETSIZE)
      return 0;

   const u32bit READ_WAIT_MS = 3;

   fd_set read_set;
   FD_ZERO(&read_set);
   FD_SET(fd, &read_set);

   struct ::timeval timeout;
   timeout.tv_sec = 0;
   timeout.tv_usec = READ_WAIT_MS * 1000;

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
int Device_EntropySource::Device_Reader::open(const std::string& pathname)
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
Device_EntropySource::Device_EntropySource(const std::vector<std::string>& fsnames)
   {
   for(u32bit i = 0; i != fsnames.size(); ++i)
      devices.push_back(Device_Reader(Device_Reader::open(fsnames[i])));
   }

/**
* Gather entropy from a RNG device
*/
u32bit Device_EntropySource::slow_poll(byte output[], u32bit length)
   {
   u32bit read = 0;

   for(size_t i = 0; i != devices.size(); ++i)
      {
      read += devices[i].get(output + read, length - read);

      if(read == length)
         break;
      }

   return read;
   }

/**
* Fast /dev/random and co poll: limit output to 64 bytes
*/
u32bit Device_EntropySource::fast_poll(byte output[], u32bit length)
   {
   return slow_poll(output, std::min<u32bit>(length, 64));
   }

}
