/*
* Auto Seeded RNG
* (C) 2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AUTO_SEEDING_RNG_H__
#define BOTAN_AUTO_SEEDING_RNG_H__

#include <botan/rng.h>
#include <string>

namespace Botan {

/**
* A userspace RNG seeded from the default entropy sources
*/
class BOTAN_DLL AutoSeeded_RNG : public RandomNumberGenerator
   {
   public:
      AutoSeeded_RNG(size_t max_bytes_before_reseed = BOTAN_RNG_RESEED_POLL_BITS);

      void randomize(byte out[], size_t len) override;

      bool is_seeded() const override { return m_rng->is_seeded(); }

      void clear() override { m_rng->clear(); }

      std::string name() const override { return m_rng->name(); }

      size_t reseed_with_sources(Entropy_Sources& srcs,
                               size_t poll_bits,
                               std::chrono::milliseconds poll_timeout) override
         {
         return m_rng->reseed_with_sources(srcs, poll_bits, poll_timeout);
         }

      void add_entropy(const byte in[], size_t len) override
         { m_rng->add_entropy(in, len); }

   private:
      std::unique_ptr<Stateful_RNG> m_rng;
      uint32_t m_counter = 0;
   };

}

#endif
