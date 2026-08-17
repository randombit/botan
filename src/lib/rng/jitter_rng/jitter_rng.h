/*
* CPU Jitter Random Number Generator
* (C) 2024 Planck Security S.A.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_JITTER_RNG_H_
#define BOTAN_JITTER_RNG_H_

#include <botan/rng.h>
#include <memory>
#include <string>

namespace Botan {

class Jitter_RNG_Internal;

/**
* RNG using jitterentropy (https://github.com/smuellerDD/jitterentropy-library)
*/
class BOTAN_PUBLIC_API(3, 6) Jitter_RNG final : public RandomNumberGenerator {
   public:
      /**
      * The compliance mode requested from the underlying jitterentropy library
      */
      enum class Mode : uint8_t {
         /**
         * Leave the library at its defaults. The SP800-90B health tests are
         * then only enforced if the system itself runs in FIPS mode.
         */
         Default,

         /**
         * Force full SP800-90B compliance, including the online health tests,
         * regardless of the state of the system (``JENT_FORCE_FIPS``).
         */
         FIPS,

         /**
         * Request AIS 20/31 NTG.1 compliance (``JENT_NTG1``). This implies
         * FIPS mode and additionally disables the internal timer, so it is not
         * available on platforms which have no usable high resolution timer.
         *
         * Requires jitterentropy 3.7.0 or later, both at build and at run
         * time; the constructor throws Not_Implemented otherwise. See
         * ntg1_supported().
         */
         NTG1,
      };

      /**
      * Let jitterentropy pick the oversampling rate
      */
      static constexpr size_t default_osr = 0;

      /**
      * @return true if the linked jitterentropy supports Mode::NTG1
      */
      static bool ntg1_supported();

      /**
      * Create a Jitter_RNG, throwing if jitterentropy cannot be initialized
      *
      * @param mode the compliance mode to request from jitterentropy
      * @param osr the oversampling rate to use. Higher values collect more
      * timing samples per output bit, which is slower but more conservative.
      * The default lets the library apply its own (minimal) rate. Values the
      * library considers out of range cause the constructor to throw.
      */
      explicit Jitter_RNG(Mode mode = Mode::Default, size_t osr = default_osr);

      ~Jitter_RNG() override;

      Jitter_RNG(const Jitter_RNG& other) = delete;
      /**
      * Move constructor
      */
      Jitter_RNG(Jitter_RNG&& other) = default;
      Jitter_RNG& operator=(const Jitter_RNG& other) = delete;
      Jitter_RNG& operator=(Jitter_RNG&& other) = delete;

      /**
      * Return the name of this RNG type
      * @return the name of this RNG type
      */
      std::string name() const override { return "JitterRNG"; }

      /**
      * Test whether this RNG has been seeded
      * @return true if this RNG is seeded and ready for use
      */
      bool is_seeded() const override { return true; }

      /**
      * Test whether this RNG accepts externally provided input
      * @return false if this RNG is known to ignore provided inputs
      */
      bool accepts_input() const override { return false; }

      /**
      * Clear all internally held values of this RNG
      */
      void clear() override;

   private:
      void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) override;

      std::unique_ptr<Jitter_RNG_Internal> m_jitter;
};

}  // namespace Botan

#endif
