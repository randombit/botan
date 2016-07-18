/*
* Auto Seeded RNG
* (C) 2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_AUTO_SEEDING_RNG_H__
#define BOTAN_AUTO_SEEDING_RNG_H__

#include <botan/rng.h>

namespace Botan {

class BOTAN_DLL AutoSeeded_RNG final : public RandomNumberGenerator
   {
   public:
      void randomize(byte out[], size_t len) override;

      void randomize_with_input(byte output[], size_t output_len,
                                const byte input[], size_t input_len) override;

      bool is_seeded() const override { return m_rng->is_seeded(); }

      void clear() override { m_rng->clear(); m_counter = 0; }

      std::string name() const override { return m_rng->name(); }

      size_t reseed_with_sources(Entropy_Sources& srcs,
                               size_t poll_bits,
                               std::chrono::milliseconds poll_timeout) override
         {
         return m_rng->reseed_with_sources(srcs, poll_bits, poll_timeout);
         }

      void add_entropy(const byte in[], size_t len) override
         { m_rng->add_entropy(in, len); }

      AutoSeeded_RNG(size_t max_output_before_reseed = BOTAN_RNG_DEFAULT_MAX_OUTPUT_BEFORE_RESEED);
   private:
      std::unique_ptr<RandomNumberGenerator> m_rng;
      uint32_t m_counter = 0;
   };

}

#endif
