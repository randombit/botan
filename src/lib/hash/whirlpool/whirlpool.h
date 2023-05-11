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

      static void compress_n(uint64_t digest[8], const uint8_t input[], size_t blocks);
      static void init(uint64_t digest[8]);

      MD_Hash<MD_Endian::Big, uint64_t, 8,
              Whirlpool::init, Whirlpool::compress_n, 64, 64, 32> m_md;
   };

}

#endif
