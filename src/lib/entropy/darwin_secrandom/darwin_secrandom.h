/*
* Darwin SecRandomCopyBytes EntropySource
* (C) 2015 Daniel Seither (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_DARWIN_SECRANDOM_H__
#define BOTAN_ENTROPY_SRC_DARWIN_SECRANDOM_H__

#include <botan/entropy_src.h>

namespace Botan {

/**
* Entropy source using SecRandomCopyBytes from Darwin's Security.framework
*/
class Darwin_SecRandom final : public Entropy_Source
   {
   public:
      std::string name() const override { return "darwin_secrandom"; }

      size_t poll(RandomNumberGenerator& rng) override;
   };

}

#endif
