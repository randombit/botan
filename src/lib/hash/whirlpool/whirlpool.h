/*
* Whirlpool
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WHIRLPOOL_H_
#define BOTAN_WHIRLPOOL_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* Whirlpool
*/
class Whirlpool_Impl final
   {
   public:
      using digest_type = std::array<uint64_t, 8>;
      static constexpr const char* NAME = "Whirlpool";
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = 64;
      static constexpr size_t CTR_BYTES = 32;

      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);
   };

class Whirlpool final : public MD_Hash_Adapter<Whirlpool, Whirlpool_Impl> {};

}

#endif
