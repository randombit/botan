/*
* MD4
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MD4_H_
#define BOTAN_MD4_H_

#include <botan/hash.h>
#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* MD4
*/
class MD4 final : public HashFunction
   {
   public:
      MD4() {}

      std::string name() const override { return "MD4"; }
      size_t output_length() const override { return 16; }
      size_t hash_block_size() const override { return 64; }
      std::unique_ptr<HashFunction> new_object() const override;
      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;
   private:
      void add_data(const uint8_t input[], size_t length) override;
      void final_result(uint8_t output[]) override;

      static void compress_n(uint32_t digest[4], const uint8_t input[], size_t blocks);
      static void init(uint32_t digest[4]);

      MD_Hash<MD_Endian::Little, uint32_t, 4, MD4::init, MD4::compress_n> m_md;
   };

}

#endif
