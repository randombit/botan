/*
* Tempest_RNG
* (C) 2026 Bolt & Tempest Project
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEMPEST_RNG_H_
#define BOTAN_TEMPEST_RNG_H_

#include <botan/stateful_rng.h>

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) Tempest_RNG final : public Stateful_RNG {
   public:
      Tempest_RNG();
      Tempest_RNG(std::span<const uint8_t> seed);
      Tempest_RNG(RandomNumberGenerator& underlying_rng,
                  size_t reseed_interval = BOTAN_RNG_RESEED_DEFAULT_PERIOD);
      Tempest_RNG(Entropy_Sources& entropy_sources,
                  size_t reseed_interval = BOTAN_RNG_RESEED_DEFAULT_PERIOD);
      Tempest_RNG(RandomNumberGenerator& underlying_rng,
                  Entropy_Sources& entropy_sources,
                  size_t reseed_interval = BOTAN_RNG_RESEED_DEFAULT_PERIOD);

      std::string name() const override { return "Tempest_RNG"; }
      void clear_state() override;
      void generate_output(std::span<uint8_t> output,
                           std::span<const uint8_t> input) override;
      size_t security_level() const override { return 128; }

   private:
      uint64_t m_u, m_v, m_w, m_z, m_rounds, m_weyl;
      static constexpr uint64_t WEYL_GOLDEN = 0x9E3779B97F4A7C15;

      static inline uint64_t rotl(uint64_t x, int r) {
         return (x << r) | (x >> (64 - r));
      }
      static inline uint64_t cmul_hl(uint64_t a, uint64_t b) {
         return static_cast<uint64_t>(static_cast<uint32_t>(a >> 32)) *
                static_cast<uint64_t>(static_cast<uint32_t>(b));
      }
      static inline uint64_t cmul_lh(uint64_t a, uint64_t b) {
         return static_cast<uint64_t>(static_cast<uint32_t>(a)) *
                static_cast<uint64_t>(static_cast<uint32_t>(b >> 32));
      }

      static uint64_t make_output(uint64_t u, uint64_t v, uint64_t w, uint64_t z);
      void round();
      uint64_t next_u64();
      void next_u64x2(uint64_t out[2]);
      void mix_state(const uint64_t data[4]);
      void init_from_key(const uint64_t key[4], const uint64_t nonce[2]);
};

}  // namespace Botan

#endif
