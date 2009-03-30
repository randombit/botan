/*
* /dev/random EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENTROPY_SRC_DEVICE_H__
#define BOTAN_ENTROPY_SRC_DEVICE_H__

#include <botan/entropy_src.h>
#include <vector>
#include <string>

namespace Botan {

class BOTAN_DLL Device_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "RNG Device Reader"; }

      void poll(Entropy_Accumulator& accum);

      Device_EntropySource(const std::vector<std::string>& fsnames);
      ~Device_EntropySource();
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
