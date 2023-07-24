/*
* Whirlpool
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_WHIRLPOOL_H_
#define BOTAN_WHIRLPOOL_H_

#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* Whirlpool
*/
class Whirlpool final : public MDx_HashFunction {
   public:
      std::string name() const override { return "Whirlpool"; }

      size_t output_length() const override { return 64; }

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<Whirlpool>(); }

      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      Whirlpool() : MDx_HashFunction(64, true, true, 32), m_digest(8) { clear(); }

   private:
      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      secure_vector<uint64_t> m_digest;
};

}  // namespace Botan

#endif
