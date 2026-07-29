/*
* CRC32
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/crc32.h>

#include <botan/internal/loadstor.h>
#include <array>

namespace Botan {

namespace {

// Sarwate's byte-at-a-time table for the reflected CRC32 polynomial
consteval std::array<uint32_t, 256> crc32_table() noexcept {
   std::array<uint32_t, 256> table = {};
   for(size_t i = 0; i != 256; ++i) {
      uint32_t crc = static_cast<uint32_t>(i);
      for(size_t j = 0; j != 8; ++j) {
         crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xEDB88320 : 0);
      }
      table[i] = crc;
   }
   return table;
}

alignas(256) constexpr auto CRC32_T0 = crc32_table();

}  // namespace

/*
* Update a CRC32 Checksum
*/
void CRC32::add_data(std::span<const uint8_t> input) {
   uint32_t crc = m_crc;
   for(; input.size() >= 16; input = input.last(input.size() - 16)) {
      crc = CRC32_T0[(crc ^ input[0]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[1]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[2]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[3]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[4]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[5]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[6]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[7]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[8]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[9]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[10]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[11]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[12]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[13]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[14]) & 0xFF] ^ (crc >> 8);
      crc = CRC32_T0[(crc ^ input[15]) & 0xFF] ^ (crc >> 8);
   }

   for(const uint8_t b : input) {
      crc = CRC32_T0[(crc ^ b) & 0xFF] ^ (crc >> 8);
   }

   m_crc = crc;
}

/*
* Finalize a CRC32 Checksum
*/
void CRC32::final_result(std::span<uint8_t> output) {
   m_crc ^= 0xFFFFFFFF;
   store_be(m_crc, output.data());
   clear();
}

std::unique_ptr<HashFunction> CRC32::copy_state() const {
   return std::make_unique<CRC32>(*this);
}

}  // namespace Botan
