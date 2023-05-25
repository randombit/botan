/*
* Entropy Source Using OpenBSD getentropy(2) system call
* (C) 2017 Alexander Bluhm (genua GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ENTROPY_SRC_GETENTROPY_H_
#define BOTAN_ENTROPY_SRC_GETENTROPY_H_

#include <botan/entropy_src.h>

namespace Botan {

/**
* Entropy source using the getentropy(2) system call first introduced in
* OpenBSD 5.6 and added to Solaris 11.3.
*/
class Getentropy final : public Entropy_Source {
   public:
      std::string name() const override { return "getentropy"; }

      size_t poll(RandomNumberGenerator& rng) override;
};

}  // namespace Botan

#endif
