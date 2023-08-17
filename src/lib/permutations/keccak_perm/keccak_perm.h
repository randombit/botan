/*
* Keccak-FIPS
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KECCAK_PERM_H_
#define BOTAN_KECCAK_PERM_H_

#include <botan/secmem.h>
#include <string>

namespace Botan {

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

class Keccak_Permutation final {
   public:
      /**
      * @param output_bits the size of the hash output; must be one of
      *                    224, 256, 384, or 512
      */
      explicit Keccak_Permutation(size_t output_bits, size_t capacity_bits, uint64_t custom_padd, uint8_t custom_padd_bit_len);

      size_t hash_block_size() const { return m_bitrate / 8; }

      size_t output_length() const { return m_output_bits / 8; }

      size_t output_bits() const { return m_output_bits; }

      size_t capacity() const { return m_capacity; }

      uint32_t bit_rate() const { return m_bitrate; }

      void clear();
      std::string provider() const;

      secure_vector<uint64_t>& internal_state() { return m_S; }

      const secure_vector<uint64_t>& internal_state() const { return m_S; }

      void set_internal_pos(uint32_t pos) { m_S_pos = pos; }

      uint32_t internal_pos() const { return m_S_pos; }

      // Static functions for internal usage

      /**
      * Absorb data into the provided state
      * @param bitrate the bitrate to absorb into the sponge
      * @param S the sponge state
      * @param S_pos where to begin absorbing into S
      * @param input the input data
      */
      static uint32_t absorb(size_t bitrate, secure_vector<uint64_t>& S, size_t S_pos, std::span<const uint8_t> input);

      void absorb(std::span<const uint8_t> input);

      /**
      * Add final padding and permute. The padding is assumed to be
      * init_pad || 00... || fini_pad
      *
      * @param bitrate the bitrate to absorb into the sponge
      * @param S the sponge state
      * @param S_pos where to begin absorbing into S
      * @param custom_padd the custom padding bits used by the primitive derived from Keccak_Permutation
      * @param custom_padd_bit_len the bit length of the custom padding
      */

      static void finish(
         size_t bitrate, secure_vector<uint64_t>& S, size_t S_pos, uint64_t custom_padd, uint8_t custom_padd_bit_len);

      void finish();

      /**
      * Expand from provided state
      * @param bitrate sponge parameter
      * @param S the state
      * @param output the designated output memory
      */
      static void expand(size_t bitrate, secure_vector<uint64_t>& S, std::span<uint8_t> output);

      void expand(std::span<uint8_t> output);

      /**
      * The bare Keccak[c] permutation
      */
      static void permute(uint64_t A[25]);
      void permute();

   private:
#if defined(BOTAN_HAS_KECCAK_PERM_BMI2)
      static void permute_bmi2(uint64_t A[25]);
#endif

      size_t m_output_bits;
      uint32_t m_capacity;
      uint32_t m_bitrate;
      uint64_t m_custom_padd;
      uint8_t m_custom_padd_bit_len;
      secure_vector<uint64_t> m_S;
      uint32_t m_S_pos;
};

}  // namespace Botan

#endif
