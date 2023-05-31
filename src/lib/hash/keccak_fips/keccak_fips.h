/*
* Keccak-FIPS
* (C) 2010,2016 Jack Lloyd
* (C) 2023 Falko Strenzke
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KECCAK_FIPS_H_
#define BOTAN_KECCAK_FIPS_H_

#include <botan/hash.h>
#include <botan/secmem.h>
#include <string>

namespace Botan {

/**
* KECCAK FIPS
*
* This file implements Keccak[c] which is specified by NIST FIPS 202 [1], where
* "c" is the variable capacity of this hash primitive. Keccak[c] is not  a
* general purpose hash function, but used as the basic primitive for algorithms
* such as SHA-3 and KMAC. This is not be confused with the "informal" general purpose hash
* function which is referred to as "Keccak" and apparently refers to the final
* submission version of the Keccak submission in the SHA-3 contest, possibly
* what is released by NIST under the name "KECCAK - Final Algorithm Package" [2].
*
*
*
* [1] FIPS PUB 202 – FEDERAL INFORMATION PROCESSING STANDARDS PUBLICATION – SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
*       https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=28 
* [2] https://csrc.nist.gov/projects/hash-functions/sha-3-project
*/

class Keccak_FIPS : public HashFunction
   {
   public:
      virtual ~Keccak_FIPS();
      /**
      * @param output_bits the size of the hash output; must be one of
      *                    224, 256, 384, or 512
      */
      explicit Keccak_FIPS(std::string const& base_name, size_t output_bits, size_t capacity_bits,
                                   uint64_t custom_padd,
                                   uint8_t custom_padd_bit_len);

      size_t hash_block_size() const override { return m_bitrate / 8; }
      size_t output_length() const override { return m_output_bits / 8; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string name() const override;
      void clear() override;
      std::string provider() const override;

      // Static functions for internal usage

      /**
      * Absorb data into the provided state
      * @param bitrate the bitrate to absorb into the sponge
      * @param S the sponge state
      * @param S_pos where to begin absorbing into S
      * @param input the input data
      * @param length size of input in bytes
      */
      static size_t absorb(size_t bitrate,
                           secure_vector<uint64_t>& S, size_t S_pos,
                           const uint8_t input[], size_t length);

      /**
      * Add final padding and permute. The padding is assumed to be
      * init_pad || 00... || fini_pad
      *
      * @param bitrate the bitrate to absorb into the sponge
      * @param S the sponge state
      * @param S_pos where to begin absorbing into S
      * @param custom_pad the custom padding bits used by the primitive derived from Keccak_FIPS
      * @param custom_padd_bit_len the bit length of the custom padding
      */
      static void finish(size_t bitrate,
                         secure_vector<uint64_t>& S, size_t S_pos, uint64_t custom_padd, uint8_t custom_padd_bit_len
                        );

      /**
      * Expand from provided state
      * @param bitrate sponge parameter
      * @param S the state
      * @param output the output buffer
      * @param output_length the size of output in bytes
      */
      static void expand(size_t bitrate,
                         secure_vector<uint64_t>& S,
                         uint8_t output[], size_t output_length);

      /**
      * The bare Keccak-1600 permutation
      */
      static void permute(uint64_t A[25]);

   protected:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t out[]) override;

#if defined(BOTAN_HAS_KECCAK_FIPS_BMI2)
      static void permute_bmi2(uint64_t A[25]);
#endif

      size_t m_output_bits, m_bitrate, m_capacity;
      uint64_t m_custom_padd;
      uint8_t m_custom_padd_bit_len;
      std::string m_base_name;
      secure_vector<uint64_t> m_S;
      size_t m_S_pos;
   };

class Keccak_FIPS_256: public Keccak_FIPS
   {
   public:
      Keccak_FIPS_256(size_t output_bits);
   };
class Keccak_FIPS_512: public Keccak_FIPS
   {
   public:
      Keccak_FIPS_512(size_t output_bits);
   };



}

#endif
