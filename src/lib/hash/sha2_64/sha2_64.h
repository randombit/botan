/*
* SHA-{384,512}
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA_64BIT_H_
#define BOTAN_SHA_64BIT_H_

#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* SHA-384
*/
class SHA_384 final : public HashFunction {
   public:
      using digest_type = secure_vector<uint64_t>;

      static constexpr MD_Endian byte_endianness = MD_Endian::Big;
      static constexpr MD_Endian bit_endianness = MD_Endian::Big;
      static constexpr size_t block_bytes = 128;
      static constexpr size_t output_bytes = 48;
      static constexpr size_t ctr_bytes = 16;

      static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks);
      static void init(digest_type& digest);

   public:
      std::string name() const override { return "SHA-384"; }

      size_t output_length() const override { return output_bytes; }

      size_t hash_block_size() const override { return block_bytes; }

      std::unique_ptr<HashFunction> new_object() const override;

      std::unique_ptr<HashFunction> copy_state() const override;

      std::string provider() const override;

      void clear() override { m_md.clear(); }

   private:
      void add_data(std::span<const uint8_t> input) override;

      void final_result(std::span<uint8_t> output) override;

   private:
      MerkleDamgard_Hash<SHA_384> m_md;
};

/**
* SHA-512
*/
class SHA_512 final : public HashFunction {
   public:
      using digest_type = secure_vector<uint64_t>;

      static constexpr MD_Endian byte_endianness = MD_Endian::Big;
      static constexpr MD_Endian bit_endianness = MD_Endian::Big;
      static constexpr size_t block_bytes = 128;
      static constexpr size_t output_bytes = 64;
      static constexpr size_t ctr_bytes = 16;

      static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks);
      static void init(digest_type& digest);

   public:
      std::string name() const override { return "SHA-512"; }

      size_t output_length() const override { return output_bytes; }

      size_t hash_block_size() const override { return block_bytes; }

      std::unique_ptr<HashFunction> new_object() const override;

      std::unique_ptr<HashFunction> copy_state() const override;

      std::string provider() const override;

      void clear() override { m_md.clear(); }

   public:
      static void compress_digest(digest_type& digest, std::span<const uint8_t> input, size_t blocks);

#if defined(BOTAN_HAS_SHA2_64_BMI2)
      static void compress_digest_bmi2(digest_type& digest, std::span<const uint8_t> input, size_t blocks);
#endif

#if defined(BOTAN_HAS_SHA2_64_ARMV8)
      static void compress_digest_armv8(digest_type& digest, std::span<const uint8_t> input, size_t blocks);
#endif

   private:
      void add_data(std::span<const uint8_t> input) override;

      void final_result(std::span<uint8_t> output) override;

   private:
      MerkleDamgard_Hash<SHA_512> m_md;
};

/**
* SHA-512/256
*/
class SHA_512_256 final : public HashFunction {
   public:
      using digest_type = secure_vector<uint64_t>;

      static constexpr MD_Endian byte_endianness = MD_Endian::Big;
      static constexpr MD_Endian bit_endianness = MD_Endian::Big;
      static constexpr size_t block_bytes = 128;
      static constexpr size_t output_bytes = 32;
      static constexpr size_t ctr_bytes = 16;

      static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks);
      static void init(digest_type& digest);

   public:
      std::string name() const override { return "SHA-512-256"; }

      size_t output_length() const override { return output_bytes; }

      size_t hash_block_size() const override { return block_bytes; }

      std::unique_ptr<HashFunction> new_object() const override;

      std::unique_ptr<HashFunction> copy_state() const override;

      std::string provider() const override;

      void clear() override { m_md.clear(); }

   private:
      void add_data(std::span<const uint8_t> input) override;

      void final_result(std::span<uint8_t> output) override;

   private:
      MerkleDamgard_Hash<SHA_512_256> m_md;
};

}  // namespace Botan

#endif
