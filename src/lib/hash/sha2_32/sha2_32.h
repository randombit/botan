/*
* SHA-{224,256}
* (C) 1999-2011 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA_224_256_H_
#define BOTAN_SHA_224_256_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* SHA-256
*/
class SHA_256 final : public HashFunction
   {
   public:
      SHA_256() : m_md() {}

      std::string name() const override { return "SHA-256"; }
      size_t output_length() const override { return 32; }
      size_t hash_block_size() const override { return 64; }
      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      std::string provider() const override;

   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

   public:
      using digest_type = std::array<uint32_t, 8>;
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = sizeof(digest_type);
      static constexpr size_t CTR_BYTES = 8;

      /*
      * Perform a SHA-256 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);

   private:

#if defined(BOTAN_HAS_SHA2_32_ARMV8)
      static void compress_digest_armv8(uint32_t digest[8],
                                        const uint8_t input[],
                                        size_t blocks);
#endif

#if defined(BOTAN_HAS_SHA2_32_X86_BMI2)
      static void compress_digest_x86_bmi2(uint32_t digest[8],
                                           const uint8_t input[],
                                           size_t blocks);
#endif

#if defined(BOTAN_HAS_SHA2_32_X86)
      static void compress_digest_x86(uint32_t digest[8],
                                      const uint8_t input[],
                                      size_t blocks);
#endif

      MD_Hash<SHA_256> m_md;
   };

/**
* SHA-224
*/
class SHA_224 final : public HashFunction
   {
   public:
      SHA_224() : m_md() {}

      std::string name() const override { return "SHA-224"; }
      size_t output_length() const override { return 28; }
      size_t hash_block_size() const override { return 64; }
      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      std::string provider() const override;
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

   public:
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = 28;
      static constexpr size_t CTR_BYTES = 8;
      using digest_type = std::array<uint32_t, 8>;

      /*
      * Perform a SHA-256 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks)
         { SHA_256::compress_n(digest, input, blocks); }
      static void init(digest_type& digest);

   private:
      MD_Hash<SHA_224> m_md;
   };

}

#endif
