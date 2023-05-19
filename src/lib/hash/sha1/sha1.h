/*
* SHA-1
* (C) 1999-2007,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA1_H_
#define BOTAN_SHA1_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* NIST's SHA-1
*/
class SHA_1_Impl final
   {
   public:
      using digest_type = std::array<uint32_t, 5>;
      static constexpr const char* NAME = "SHA-1";
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = sizeof(digest_type);
      static constexpr size_t CTR_BYTES = 8;

      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);

   private:

#if defined(BOTAN_HAS_SHA1_ARMV8)
      static void sha1_armv8_compress_n(uint32_t digest[5],
                                        const uint8_t blocks[],
                                        size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_SSE2)
      static void sse2_compress_n(uint32_t digest[5],
                                  const uint8_t blocks[],
                                  size_t block_count);
#endif

#if defined(BOTAN_HAS_SHA1_X86_SHA_NI)
      // Using x86 SHA instructions in Intel Goldmont and Cannonlake
      static void sha1_compress_x86(uint32_t digest[5],
                                    const uint8_t blocks[],
                                    size_t block_count);
#endif
   };

class SHA_1 final : public MD_Hash_Adapter<SHA_1, SHA_1_Impl>
   {
   public:
      std::string provider() const override;
   };

}

#endif
