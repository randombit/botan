/*
* RIPEMD-160
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RIPEMD_160_H_
#define BOTAN_RIPEMD_160_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* RIPEMD-160
*/
class RIPEMD_160_Impl final
   {
   public:
      using digest_type = std::array<uint32_t, 5>;
      static constexpr const char* NAME = "RIPEMD-160";
      static constexpr MD_Endian ENDIAN = MD_Endian::Little;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = sizeof(digest_type);
      static constexpr size_t CTR_BYTES = 8;

      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);
   };

class RIPEMD_160 final : public MD_Hash_Adapter<RIPEMD_160, RIPEMD_160_Impl> {};

}

#endif
