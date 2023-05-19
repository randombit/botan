/*
* SHA-{384,512}
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA_64BIT_H_
#define BOTAN_SHA_64BIT_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* SHA-512
*/
class SHA_512_Impl final
   {
   public:
      using digest_type = std::array<uint64_t, 8>;
      static constexpr const char* NAME = "SHA-512";
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 128;
      static constexpr size_t FINAL_DIGEST_BYTES = 64;
      static constexpr size_t CTR_BYTES = 16;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);

   private:
      static const uint64_t K[80];

#if defined(BOTAN_HAS_SHA2_64_BMI2)
      static void compress_digest_bmi2(uint64_t digest[8],
                                       const uint8_t input[],
                                       size_t blocks);
#endif
   };

/**
* SHA-384
*/
class SHA_384_Impl final
   {
   public:
      using digest_type = SHA_512_Impl::digest_type;
      static constexpr const char* NAME = "SHA-384";
      static constexpr MD_Endian ENDIAN = SHA_512_Impl::ENDIAN;
      static constexpr size_t BLOCK_BYTES = SHA_512_Impl::BLOCK_BYTES;
      static constexpr size_t FINAL_DIGEST_BYTES = 48;
      static constexpr size_t CTR_BYTES = SHA_512_Impl::CTR_BYTES;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks)
         { SHA_512_Impl::compress_n(digest, input, blocks); }
      static void init(digest_type& digest);
   };

/**
* SHA-512/256
*/
class SHA_512_256_Impl final
   {
   public:
      using digest_type = SHA_512_Impl::digest_type;
      static constexpr const char* NAME = "SHA-512-256";
      static constexpr MD_Endian ENDIAN = SHA_512_Impl::ENDIAN;
      static constexpr size_t BLOCK_BYTES = SHA_512_Impl::BLOCK_BYTES;
      static constexpr size_t FINAL_DIGEST_BYTES = 32;
      static constexpr size_t CTR_BYTES = SHA_512_Impl::CTR_BYTES;

      /*
      * Perform a SHA-512 compression. For internal use
      */
      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks)
         { SHA_512_Impl::compress_n(digest, input, blocks); }
      static void init(digest_type& digest);
   };

class SHA_512 final : public MD_Hash_Adapter<SHA_512, SHA_512_Impl>
   {
   public:
      std::string provider() const override;
   };

class SHA_384 final : public MD_Hash_Adapter<SHA_384, SHA_384_Impl>
   {
   public:
      std::string provider() const override;
   };

class SHA_512_256 final : public MD_Hash_Adapter<SHA_512_256, SHA_512_256_Impl>
   {
   public:
      std::string provider() const override;
   };

}

#endif
