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
class Device_EntropySource final : public Entropy_Source
   {
   public:
      std::string name() const override { return "dev_random"; }

      size_t poll(RandomNumberGenerator& rng) override;

      Device_EntropySource(const std::vector<std::string>& fsnames);

      ~Device_EntropySource();
   private:
      std::vector<int> m_dev_fds;
      int m_max_fd;
   };

}

#endif
