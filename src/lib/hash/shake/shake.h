/*
* SHAKE hash functions
* (C) 2010,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHAKE_HASH_H_
#define BOTAN_SHAKE_HASH_H_

#include <botan/hash.h>
#include <botan/internal/keccak_perm.h>

#include <string>

namespace Botan {

/**
* SHAKE-128
*/
class SHAKE_128 final : public HashFunction {
   public:
      /**
      * @param output_bits the desired output size in bits
      * must be a multiple of 8
      */
      explicit SHAKE_128(size_t output_bits);

      size_t hash_block_size() const override { return m_keccak.byte_rate(); }

      size_t output_length() const override { return m_output_bits / 8; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string name() const override;

      void clear() override { m_keccak.clear(); }

      std::string provider() const override { return m_keccak.provider(); }

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> out) override;

      Keccak_Permutation m_keccak;
      size_t m_output_bits;
};

/**
* SHAKE-256
*/
class SHAKE_256 final : public HashFunction {
   public:
      /**
      * @param output_bits the desired output size in bits
      * must be a multiple of 8
      */
      explicit SHAKE_256(size_t output_bits);

      size_t hash_block_size() const override { return m_keccak.byte_rate(); }

      size_t output_length() const override { return m_output_bits / 8; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;
      std::string name() const override;

      void clear() override { m_keccak.clear(); }

      std::string provider() const override { return m_keccak.provider(); }

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> out) override;

      Keccak_Permutation m_keccak;
      size_t m_output_bits;
};

}  // namespace Botan

#endif
