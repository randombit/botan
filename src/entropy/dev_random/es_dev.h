/*************************************************
* Device EntropySource Header File               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ENTROPY_SRC_DEVICE_H__
#define BOTAN_ENTROPY_SRC_DEVICE_H__

#include <botan/entropy_src.h>
#include <vector>
#include <string>

namespace Botan {

/*************************************************
* Device Based Entropy Source                    *
*************************************************/
class BOTAN_DLL Device_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "RNG Device Reader"; }

      Device_EntropySource(const std::vector<std::string>& fsnames);
      ~Device_EntropySource();

      u32bit slow_poll(byte[], u32bit);
      u32bit fast_poll(byte[], u32bit);
   private:

      /**
      A class handling reading from a Unix character device
      */
      class Device_Reader
         {
         public:
            typedef int fd_type;

            // Does not own fd, a transient class
            Device_Reader(fd_type device_fd) : fd(device_fd) {}

            void close();

            u32bit get(byte out[], u32bit length, u32bit ms_wait_time);

            static fd_type open(const std::string& pathname);
         private:
            fd_type fd;
         };

      std::vector<Device_Reader> devices;
   };

}

#endif
