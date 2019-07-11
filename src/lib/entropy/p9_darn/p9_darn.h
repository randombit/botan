/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_DARN_H_
#define BOTAN_ENTROPY_SRC_DARN_H_

#include <botan/entropy_src.h>

namespace Botan {

class POWER9_DARN final : public Entropy_Source
   {
   public:
      std::string name() const override { return "p9_darn"; }
      size_t poll(RandomNumberGenerator& rng) override;
   };

}

#endif
