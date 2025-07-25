/*
* CRC32
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CRC32_H_
#define BOTAN_CRC32_H_

#include <botan/hash.h>

namespace Botan {

/**
* 32-bit cyclic redundancy check
*/
class CRC32 final : public HashFunction {
   public:
      std::string name() const override { return "CRC32"; }

      size_t output_length() const override { return 4; }

      std::unique_ptr<HashFunction> new_object() const override { return std::make_unique<CRC32>(); }

      std::unique_ptr<HashFunction> copy_state() const override;

      void clear() override { m_crc = 0xFFFFFFFF; }

   private:
      void add_data(std::span<const uint8_t> input) override;
      void final_result(std::span<uint8_t> output) override;
      uint32_t m_crc = 0xFFFFFFFF;
};

}  // namespace Botan

#endif
