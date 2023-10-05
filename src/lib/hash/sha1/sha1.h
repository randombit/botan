/*
* SHA-1
* (C) 1999-2007,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA1_H_
#define BOTAN_SHA1_H_

#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* NIST's SHA-1
*/
class SHA_1 final : public HashFunction {
   public:
      using digest_type = secure_vector<uint32_t>;

      static constexpr MD_Endian byte_endianness = MD_Endian::Big;
      static constexpr MD_Endian bit_endianness = MD_Endian::Big;
      static constexpr size_t block_bytes = 64;
      static constexpr size_t output_bytes = 20;
      static constexpr size_t ctr_bytes = 8;

      static void compress_n(digest_type& digest, std::span<const uint8_t> input, size_t blocks);
      static void init(digest_type& digest);

   public:
      std::string name() const override { return "SHA-1"; }

      size_t output_length() const override { return 20; }

      size_t hash_block_size() const override { return block_bytes; }

      std::unique_ptr<HashFunction> new_object() const override;

      std::unique_ptr<HashFunction> copy_state() const override;

      std::string provider() const override;

      void clear() override { m_md.clear(); }

#if defined(BOTAN_HAS_SHA1_ARMV8)
      static void sha1_armv8_compress_n(digest_type& digest, std::span<const uint8_t> blocks, size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
      static void sse2_compress_n(digest_type& digest, std::span<const uint8_t> blocks, size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
      // Using x86 SHA instructions in Intel Goldmont and Cannonlake
      static void sha1_compress_x86(digest_type& digest, std::span<const uint8_t> blocks, size_t block_count);
#endif

   private:
      void add_data(std::span<const uint8_t> input) override;

      void final_result(std::span<uint8_t> output) override;

   private:
      MerkleDamgard_Hash<SHA_1> m_md;
};

}  // namespace Botan

#endif
