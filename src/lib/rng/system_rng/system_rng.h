/*
* System RNG interface
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SYSTEM_RNG_H_
#define BOTAN_SYSTEM_RNG_H_

#include <botan/rng.h>

namespace Botan {

/**
* Return a shared reference to a global PRNG instance provided by the
* operating system. For instance might be instantiated by /dev/urandom
* or CryptGenRandom.
*/
BOTAN_PUBLIC_API(2, 0) RandomNumberGenerator& system_rng();

/**
* Instantiable reference to the system RNG.
*/
class BOTAN_PUBLIC_API(2, 0) System_RNG final : public RandomNumberGenerator {
   public:
      /**
      * Return the name of this RNG type
      * @return the name of this RNG type
      */
      std::string name() const override { return system_rng().name(); }

      /**
      * Test whether this RNG has been seeded
      * @return true if this RNG is seeded and ready for use
      */
      bool is_seeded() const override { return system_rng().is_seeded(); }

      /**
      * Test whether this RNG accepts externally provided input
      * @return false if this RNG is known to ignore provided inputs
      */
      bool accepts_input() const override { return system_rng().accepts_input(); }

      /**
      * Clear all internally held values of this RNG
      */
      void clear() override { system_rng().clear(); }

   protected:
      /**
      * Fill the output buffer, first incorporating the provided input
      * @param out the buffer to fill
      * @param in additional input to incorporate
      */
      void fill_bytes_with_input(std::span<uint8_t> out, std::span<const uint8_t> in) override {
         system_rng().randomize_with_input(out, in);
      }
};

}  // namespace Botan

#endif
