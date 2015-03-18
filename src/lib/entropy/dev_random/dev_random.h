/*
* /dev/random EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_DEVICE_H__
#define BOTAN_ENTROPY_SRC_DEVICE_H__

#include <botan/entropy_src.h>
#include <vector>
#include <string>

namespace Botan {

/**
* Entropy source reading from kernel devices like /dev/random
*/
class Device_EntropySource : public EntropySource
   {
   public:
      std::string name() const { return "RNG Device Reader"; }

      void poll(Entropy_Accumulator& accum);

      Device_EntropySource(const std::vector<std::string>& fsnames);
      ~Device_EntropySource();
   private:
      typedef int fd_type;

      secure_vector<byte> m_buf;
      std::vector<fd_type> m_devices;
   };

}

#endif
