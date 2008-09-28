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

namespace {

/*************************************************
* A class handling reading from a device         *
*************************************************/
class Device_Reader
   {
   public:
      typedef int fd_type;

      Device_Reader(fd_type device_fd) : fd(device_fd) {}
      ~Device_Reader() { if(fd > 0) { ::close(fd); } }
      u32bit get(byte out[], u32bit length);

      static fd_type open(const std::string& pathname);
   private:
      fd_type fd;
   };

/*************************************************
* Read from a device file                        *
*************************************************/
u32bit Device_Reader::get(byte out[], u32bit length)
   {
   if(fd < 0)
      return 0;

   if(fd >= FD_SETSIZE)
      return 0;

   const u32bit READ_WAIT_MS = 10;

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

/*************************************************
* Attempt to open a device                       *
*************************************************/
int Device_Reader::open(const std::string& pathname)
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

}

/*************************************************
* Gather entropy from a RNG device               *
*************************************************/
u32bit Device_EntropySource::slow_poll(byte output[], u32bit length)
   {
   u32bit read = 0;

   for(size_t j = 0; j != fsnames.size(); ++j)
      {
      Device_Reader reader(Device_Reader::open(fsnames[j]));

      read += reader.get(output + read, length - read);

      if(read == length)
         break;
      }

   return read;
   }

}
