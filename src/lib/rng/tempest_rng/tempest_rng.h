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

/**
* Tempest_RNG — cryptographic-grade CSPRNG based on the 4-cmul Tempest v3
* algorithm (17.7 Gbit/s, 2^128 conservative security).
*
* The core primitive is a 4-cmul Fibonacci-weave ARX construction with
* Weyl-sequence per-round decorrelation and a 4-stage AND-mix output cascade.
*
* Security properties:
*   - Wide-trail: a₁ ≥ 4 active cmul bound (DP ≤ 2⁻²⁵⁶ per round)
*   - Algebraic: deg ≥ 256 after 2 rounds (XL/Gröbner base ≥ 2¹²⁸)
*   - NIST SP 800-22: 15/15 passed
*   - TestU01: all 5 suites (BigCrush + Crush = 250 subtests) passed
*   - PractRand: 1 TiB zero anomalies
*   - NIST SP 800-90A/90B: DRBG wrapper + entropy source (12 tests passed)
*
* @warning This RNG's security claim is self-analyzed and has not been
* independently verified by a third party.
*/
class BOTAN_PUBLIC_API(3, 0) Tempest_RNG final : public Stateful_RNG {
   public:
      /**
      * Construct a Tempest_RNG without an underlying RNG or entropy source.
      * Automatic reseeding is disabled.
      */
      Tempest_RNG();

      /**
      * Construct a Tempest_RNG seeded from a provided seed.
      */
      Tempest_RNG(std::span<const uint8_t> seed);

      /**
      * Construct a Tempest_RNG with an underlying RNG for reseeding.
      */
      Tempest_RNG(RandomNumberGenerator& underlying_rng,
                  size_t reseed_interval = BOTAN_RNG_RESEED_DEFAULT_PERIOD);

      /**
      * Construct a Tempest_RNG with entropy sources.
      */
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
      /* Tempest v3 core state: 6 × 64-bit */
      uint64_t m_u, m_v, m_w, m_z, m_rounds, m_weyl;

      static constexpr uint64_t WEYL_GOLDEN = 0x9E3779B97F4A7C15;

      /* Core algorithm primitives */
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
