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
class SHA_256_Impl final
   {
   public:
      using digest_type = std::array<uint32_t, 8>;
      static constexpr const char* NAME = "SHA-256";
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
   };

/**
* SHA-224
*/
class SHA_224_Impl final
   {
   public:
      using digest_type = SHA_256_Impl::digest_type;
      static constexpr const char* NAME = "SHA-224";
      static constexpr MD_Endian ENDIAN = SHA_256_Impl::ENDIAN;
      static constexpr size_t BLOCK_BYTES = SHA_256_Impl::BLOCK_BYTES;
      static constexpr size_t FINAL_DIGEST_BYTES = 28;
      static constexpr size_t CTR_BYTES = 8;

      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks)
         { SHA_256_Impl::compress_n(digest, input, blocks); }
      static void init(digest_type& digest);
   };

class SHA_256 final : public MD_Hash_Adapter<SHA_256, SHA_256_Impl>
   {
   public:
      std::string provider() const override;
   };

class SHA_224 final : public MD_Hash_Adapter<SHA_224, SHA_224_Impl>
   {
   public:
      std::string provider() const override;
   };

}

#endif
