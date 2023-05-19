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
class Whirlpool final : public HashFunction
   {
   public:
      Whirlpool() {}

      std::string name() const override { return "Whirlpool"; }
      size_t output_length() const override { return 64; }
      size_t hash_block_size() const override { return 64; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

   public:
      using digest_type = std::array<uint64_t, 8>;
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = 64;
      static constexpr size_t CTR_BYTES = 32;

      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);

      MD_Hash<Whirlpool> m_md;
   };

}

#endif
