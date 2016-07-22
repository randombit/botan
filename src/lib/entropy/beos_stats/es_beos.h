/*
* BeOS EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_BEOS_H__
#define BOTAN_ENTROPY_SRC_BEOS_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* BeOS Entropy Source
*/
class BeOS_EntropySource final : public Entropy_Source
   {
   private:
      std::string name() const override { return "system_stats"; }

      size_t poll(RandomNumberGenerator& rng) override;
   };

}

#endif
