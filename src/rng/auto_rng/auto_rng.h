/*
* Auto Seeded RNG
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_AUTO_SEEDING_RNG_H__
#define BOTAN_AUTO_SEEDING_RNG_H__

#include <botan/rng.h>
#include <botan/libstate.h>
#include <string>

namespace Botan {

/**
* An automatically seeded PRNG
*/
class BOTAN_DLL AutoSeeded_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte out[], size_t len)
         { rng->randomize(out, len); }

      bool is_seeded() const { return rng->is_seeded(); }

      void clear() { rng->clear(); }

      std::string name() const { return rng->name(); }

      void reseed(size_t poll_bits = 256) { rng->reseed(poll_bits); }

      void add_entropy_source(EntropySource* es)
         { rng->add_entropy_source(es); }

      void add_entropy(const byte in[], size_t len)
         { rng->add_entropy(in, len); }

      AutoSeeded_RNG() { rng = &global_state().global_rng(); }
   private:
      RandomNumberGenerator* rng;
   };

}

#endif
