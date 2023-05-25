/*
* SM3
* (C) 2017 Ribose Inc.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SM3_H_
#define BOTAN_SM3_H_

#include <botan/internal/mdx_hash.h>

namespace Botan {

/**
* SM3
*/
class SM3 final : public MDx_HashFunction {
   public:
      std::string name() const override { return "SM3"; }

      size_t output_length() const override { return 32; }

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<SM3>(); }

      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override;

      SM3() : MDx_HashFunction(64, true, true), m_digest(32) { clear(); }

   private:
      void compress_n(const uint8_t[], size_t blocks) override;
      void copy_out(uint8_t[]) override;

      /**
      * The digest value
      */
      secure_vector<uint32_t> m_digest;
};

}  // namespace Botan

#endif
