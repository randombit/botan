/*************************************************
* Auto Seeded RNG Header File                    *
* (C) 2008 Jack Lloyd                            *
*************************************************/

#ifndef BOTAN_AUTO_SEEDING_RNG_H__
#define BOTAN_AUTO_SEEDING_RNG_H__

#include <botan/rng.h>
#include <string>

namespace Botan {

/**
* RNG that attempts to seed itself
*/
class BOTAN_DLL AutoSeeded_RNG : public RandomNumberGenerator
   {
   public:
      void randomize(byte out[], u32bit len)
         { rng->randomize(out, len); }
      bool is_seeded() const
         { return rng->is_seeded(); }
      void clear() throw() { rng->clear(); }
      std::string name() const
         { return "AutoSeeded(" + rng->name() + ")"; }

      void reseed(u32bit poll_bits) { rng->reseed(poll_bits); }
      void add_entropy_source(EntropySource* es)
         { rng->add_entropy_source(es); }
      void add_entropy(const byte in[], u32bit len)
         { rng->add_entropy(in, len); }

      AutoSeeded_RNG(u32bit poll_bits = 256);
      ~AutoSeeded_RNG() { delete rng; }
   private:
      RandomNumberGenerator* rng;
   };

}

#endif
