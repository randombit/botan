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
class SM3 final : public HashFunction
   {
   public:
      SM3() {}

      std::string name() const override { return "SM3"; }
      size_t output_length() const override { return 32; }
      size_t hash_block_size() const override { return 64; }

      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

   public:
      using digest_type = std::array<uint32_t, 8>;
      static constexpr MD_Endian ENDIAN = MD_Endian::Big;
      static constexpr size_t BLOCK_BYTES = 64;
      static constexpr size_t FINAL_DIGEST_BYTES = sizeof(digest_type);
      static constexpr size_t CTR_BYTES = 8;

      static void compress_n(digest_type& digest, const uint8_t input[], size_t blocks);
      static void init(digest_type& digest);

      MD_Hash<SM3> m_md;
   };

}

#endif
