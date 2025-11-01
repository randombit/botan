/*
* Keccak Permutation
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
* (C) 2023,2025 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KECCAK_PERM_H_
#define BOTAN_KECCAK_PERM_H_

#include <botan/internal/sponge.h>
#include <span>
#include <string>

namespace Botan {

struct KeccakPadding {
      uint64_t padding;  /// The padding bits in little-endian order
      uint8_t bit_len;   /// The number of relevant bits in 'padding'

      /// NIST FIPS 202 Section 6.1
      static constexpr KeccakPadding sha3() { return {.padding = 0b10 /* little-endian */, .bit_len = 2}; }

      /// NIST FIPS 202 Section 6.2
      static constexpr KeccakPadding shake() { return {.padding = 0b1111, .bit_len = 4}; }

      /// NIST SP.800-185 Section 3.3
      static constexpr KeccakPadding cshake() { return {.padding = 0b00, .bit_len = 2}; }

      /// Keccak submission, prior to the introduction of an algorithm specific padding
      static constexpr KeccakPadding keccak1600() { return {.padding = 0, .bit_len = 0}; }
};

/**
* KECCAK FIPS
*
* This file implements Keccak[c] which is specified by NIST FIPS 202 [1], where
* "c" is the variable capacity of this hash primitive. Keccak[c] is not  a
* general purpose hash function, but used as the basic primitive for algorithms
* such as SHA-3 and KMAC. This is not to be confused with the "informal" general purpose hash
* function which is referred to as "Keccak" and apparently refers to the final
* submission version of the Keccak submission in the SHA-3 contest, possibly
* what is released by NIST under the name "KECCAK - Final Algorithm Package" [2].
* See also the file keccak.h for the details how the keccak hash function is defined
* in terms of the Keccak[c] – a detail which cannot be found in [1].
*
*
*
* [1] FIPS PUB 202 – FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION – SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
*       https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=28
* [2] https://csrc.nist.gov/projects/hash-functions/sha-3-project
*/
class Keccak_Permutation final : public Sponge<25, uint64_t> {
   public:
      struct Config {
            size_t capacity_bits;
            KeccakPadding padding;
      };

   public:
      /**
        * @brief Instantiate a Keccak permutation
        *
        * @param config Keccak parameter configuration
        */
      constexpr explicit Keccak_Permutation(Config config) :
            Sponge({.bit_rate = state_bits() - config.capacity_bits, .initial_state = {}}), m_padding(config.padding) {}

      void clear();
      std::string provider() const;

      /**
      * @brief Absorb input data into the Keccak sponge
      *
      * This method can be called multiple times with arbitrary-length buffers.
      *
      * @param input the input data
      */
      void absorb(std::span<const uint8_t> input);

      /**
      * @brief Expand output data from the current Keccak state
      *
      * This method can be called multiple times with arbitrary-length buffers.
      *
      * @param output the designated output memory
      */
      void squeeze(std::span<uint8_t> output);

      /**
      * @brief Add final padding (as provided in the constructor) and permute
      */
      void finish();

      /**
       * The Keccak permutation function
       */
      void permute();

   private:
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
      void permute_bmi2();
#endif

   private:
      KeccakPadding m_padding;
};

}  // namespace Botan

#endif
