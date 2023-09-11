/*
* Adler32
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ADLER32_H_
#define BOTAN_ADLER32_H_

#include <botan/hash.h>

namespace Botan {

/**
* The Adler32 checksum, used in zlib
*/
class Adler32 final : public HashFunction {
   public:
      std::string name() const override { return "Adler32"; }

      size_t output_length() const override { return 4; }

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<Adler32>(); }

      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override {
         m_S1 = 1;
         m_S2 = 0;
      }

      Adler32() { clear(); }

      ~Adler32() override { clear(); }

   private:
      void add_data(std::span<const uint8_t>) override;
      void final_result(std::span<uint8_t>) override;
      uint16_t m_S1, m_S2;
};

}  // namespace Botan

#endif
