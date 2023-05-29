/*
* Win32 EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_WIN32_H_
#define BOTAN_ENTROPY_SRC_WIN32_H_

#include <botan/entropy_src.h>

namespace Botan {

/**
* Win32 Entropy Source
*/
class Win32_EntropySource final : public Entropy_Source {
   public:
      std::string name() const override { return "system_stats"; }

      size_t poll(RandomNumberGenerator& rng) override;
};

}  // namespace Botan

#endif
