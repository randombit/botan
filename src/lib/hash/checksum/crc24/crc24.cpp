/*
* CRC24
* (C) 1999-2007 Jack Lloyd
* (C) 2017 [Ribose Inc](https://www.ribose.com). Performed by Krzysztof Kwiatkowski.
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/crc24.h>

#include <botan/internal/loadstor.h>
#include <array>

namespace Botan {

namespace {

/*
* The tables are computed same way as in a method proposed
* by D. Sarwate (1988), for the OpenPGP CRC24 polynomial 0x864CFB.
*
* Each entry is stored with its bytes reversed, since the CRC state is
* kept byte-reversed (see the initial value 0xCE04B7), allowing the
* update loop to use little-endian loads and right shifts.
*/
consteval std::array<uint32_t, 256> crc24_sarwate_table() noexcept {
   std::array<uint32_t, 256> table = {};
   for(size_t i = 0; i != 256; ++i) {
      uint32_t crc = static_cast<uint32_t>(i) << 16;
      for(size_t j = 0; j != 8; ++j) {
         crc = ((crc << 1) & 0xFFFFFF) ^ ((crc & 0x800000) != 0 ? 0x864CFB : 0);
      }
      table[i] = ((crc & 0xFF) << 16) | (crc & 0xFF00) | (crc >> 16);
   }
   return table;
}

/*
* Derives the T1, T2 and T3 tables used by the Slicing-by-N algorithm:
*
*    T1[j] = (T0[j] >> 8) ^ T0[ T0[j] & 0xFF ]
*    T2[j] = (T1[j] >> 8) ^ T0[ T1[j] & 0xFF ]
*    T3[j] = (T2[j] >> 8) ^ T0[ T2[j] & 0xFF ]
*/
consteval std::array<uint32_t, 256> crc24_slicing_table(const std::array<uint32_t, 256>& prev,
                                                        const std::array<uint32_t, 256>& t0) noexcept {
   std::array<uint32_t, 256> table = {};
   for(size_t i = 0; i != 256; ++i) {
      table[i] = (prev[i] >> 8) ^ t0[prev[i] & 0xFF];
   }
   return table;
}

alignas(256) constexpr auto CRC24_T0 = crc24_sarwate_table();
alignas(256) constexpr auto CRC24_T1 = crc24_slicing_table(CRC24_T0, CRC24_T0);
alignas(256) constexpr auto CRC24_T2 = crc24_slicing_table(CRC24_T1, CRC24_T0);
alignas(256) constexpr auto CRC24_T3 = crc24_slicing_table(CRC24_T2, CRC24_T0);

inline uint32_t process8(uint32_t crc, uint8_t data) {
   return (crc >> 8) ^ CRC24_T0[get_byte<3>(crc) ^ data];
}

inline uint32_t process32(uint32_t crc, uint32_t word) {
   const uint32_t sum = crc ^ word;

   return CRC24_T3[get_byte<3>(sum)] ^ CRC24_T2[get_byte<2>(sum)] ^ CRC24_T1[get_byte<1>(sum)] ^
          CRC24_T0[get_byte<0>(sum)];
}
}  // namespace

std::unique_ptr<HashFunction> CRC24::copy_state() const {
   return std::make_unique<CRC24>(*this);
}

/*
* Update a CRC24 Checksum
*
* Implementation uses Slicing-by-N algorithm described in
* "Novel Table Lookup-Based Algorithms for High-Performance
* CRC Generation", by M.Kounavis.
*
* This algorithm uses the 4 look-up tables T0, T1, T2 and T3
* computed above.
*/
void CRC24::add_data(std::span<const uint8_t> input) {
   uint32_t tmp = m_crc;

   // Input is word aligned if WA & input == 0
   static const uint8_t WA = sizeof(size_t) - 1;

   // Ensure input is word aligned before processing in parallel
   for(; !input.empty() && (reinterpret_cast<uintptr_t>(input.data()) & WA) > 0; input = input.last(input.size() - 1)) {
      tmp = process8(tmp, input.front());
   }

   while(input.size() >= 16) {
      uint32_t d[4];
      load_le(d, input.data(), 4);
      tmp = process32(tmp, d[0]);
      tmp = process32(tmp, d[1]);
      tmp = process32(tmp, d[2]);
      tmp = process32(tmp, d[3]);

      input = input.last(input.size() - 16);
   }

   for(; !input.empty(); input = input.last(input.size() - 1)) {
      tmp = process8(tmp, input.front());
   }

   m_crc = tmp;
}

/*
* Finalize a CRC24 Checksum
*/
void CRC24::final_result(std::span<uint8_t> output) {
   output[0] = get_byte<3>(m_crc);
   output[1] = get_byte<2>(m_crc);
   output[2] = get_byte<1>(m_crc);
   clear();
}

}  // namespace Botan
