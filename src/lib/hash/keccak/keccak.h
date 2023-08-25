/*
* Keccak
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_KECCAK_H_
#define BOTAN_KECCAK_H_

#include <botan/hash.h>
#include <botan/secmem.h>
#include <botan/internal/keccak_perm.h>
#include <string>

namespace Botan {

/**
* Keccak[1600], the SHA-3 submission without any final bit padding. Not an official NIST SHA-3-derived hash function.
*
* In the terminology of the official SHA-3 specification [1],
* the instantiations of this hash function
* (with the output bit size in brackets) are given as
*
* Keccak1600[224](M) = KECCAK[448] (M, 224)
* Keccak1600[256](M) = KECCAK[512] (M, 256)
* Keccak1600[384](M) = KECCAK[768] (M, 384)
* Keccak1600[512](M) = KECCAK[1024] (M, 512)
*
* i.e., as raw Keccak[c] without any additional final bit padding.
*
* [1] https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=28
*
*/
class Keccak_1600 final : public HashFunction {
   public:
      /**
      * @param output_bits the size of the hash output; must be one of
      *                    224, 256, 384, or 512
      */
      explicit Keccak_1600(size_t output_bits = 512);

      size_t hash_block_size() const override { return m_keccak.byte_rate(); }

      size_t output_length() const override { return m_output_length; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string name() const override;
      void clear() override;
      std::string provider() const override;

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> out) override;

   private:
      Keccak_Permutation m_keccak;
      size_t m_output_length;
};

}  // namespace Botan

#endif
