/*
* SM3
* (C) 2017 Ribose Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SM3_H_
#define BOTAN_SM3_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* SM3
*/
class SM3_Impl final
   {
   public:
      using digest_type = std::array<uint32_t, 8>;
      static constexpr const char* NAME = "SM3";
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = sizeof(digest_type);
      static constexpr size_t CTR_BYTES = 8;

      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);
   };

class SM3 final : public MD_Hash_Adapter<SM3, SM3_Impl> {};

}

#endif
