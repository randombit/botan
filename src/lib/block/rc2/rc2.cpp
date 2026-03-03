/*
* RC2 Block Cipher
* (C) 2026 Botan Project
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rc2.h>

#include <botan/exceptn.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

namespace Botan {

namespace {

// RC2 PITABLE - permutation used in key expansion
const uint8_t RC2_PITABLE[256] = {
   0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED, 0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
   0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E, 0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
   0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13, 0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
   0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B, 0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
   0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C, 0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
   0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1, 0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
   0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57, 0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
   0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7, 0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
   0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7, 0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
   0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74, 0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
   0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC, 0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
   0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A, 0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
   0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE, 0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
   0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C, 0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
   0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0, 0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
   0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77, 0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD};

}  // namespace

RC2::RC2(size_t effective_key_bits) : m_effective_key_bits(effective_key_bits) {
   if(effective_key_bits < 1 || effective_key_bits > 1024) {
      throw Invalid_Argument("RC2: effective key bits must be 1-1024");
   }
}

std::string RC2::name() const {
   if(m_effective_key_bits == 1024) {
      return "RC2";
   }
   return "RC2(" + std::to_string(m_effective_key_bits) + ")";
}

bool RC2::has_keying_material() const {
   return !m_K.empty();
}

void RC2::clear() {
   zap(m_K);
}

void RC2::key_schedule(std::span<const uint8_t> key) {
   const size_t key_len = key.size();

   // T = number of bytes in effective key
   const size_t T = (m_effective_key_bits + 7) / 8;
   // TM = mask for last byte
   const uint8_t TM = static_cast<uint8_t>(0xFF >> (8 * T - m_effective_key_bits));

   // Expand key to 128 bytes
   secure_vector<uint8_t> L(128);
   copy_mem(L.data(), key.data(), key_len);

   // Phase 1: Expand key using PITABLE
   for(size_t i = key_len; i < 128; ++i) {
      L[i] = RC2_PITABLE[(L[i - 1] + L[i - key_len]) & 0xFF];
   }

   // Phase 2: Apply effective key bits limitation
   L[128 - T] = RC2_PITABLE[L[128 - T] & TM];
   for(size_t i = 127 - T; i < 128; --i) {
      L[i] = RC2_PITABLE[L[i + 1] ^ L[i + T]];
   }

   // Convert to 16-bit words (little-endian)
   m_K.resize(64);
   for(size_t i = 0; i < 64; ++i) {
      m_K[i] = load_le<uint16_t>(L.data(), i);
   }
}

void RC2::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   for(size_t b = 0; b < blocks; ++b) {
      uint16_t R0 = load_le<uint16_t>(in, 0);
      uint16_t R1 = load_le<uint16_t>(in, 1);
      uint16_t R2 = load_le<uint16_t>(in, 2);
      uint16_t R3 = load_le<uint16_t>(in, 3);

      size_t j = 0;

      // 5 mixing rounds
      for(size_t i = 0; i < 5; ++i) {
         R0 = static_cast<uint16_t>(R0 + m_K[j++] + (R3 & R2) + (~R3 & R1));
         R0 = rotl<1>(R0);
         R1 = static_cast<uint16_t>(R1 + m_K[j++] + (R0 & R3) + (~R0 & R2));
         R1 = rotl<2>(R1);
         R2 = static_cast<uint16_t>(R2 + m_K[j++] + (R1 & R0) + (~R1 & R3));
         R2 = rotl<3>(R2);
         R3 = static_cast<uint16_t>(R3 + m_K[j++] + (R2 & R1) + (~R2 & R0));
         R3 = rotl<5>(R3);
      }

      // 1 mashing round
      R0 = static_cast<uint16_t>(R0 + m_K[R3 & 63]);
      R1 = static_cast<uint16_t>(R1 + m_K[R0 & 63]);
      R2 = static_cast<uint16_t>(R2 + m_K[R1 & 63]);
      R3 = static_cast<uint16_t>(R3 + m_K[R2 & 63]);

      // 6 mixing rounds
      for(size_t i = 0; i < 6; ++i) {
         R0 = static_cast<uint16_t>(R0 + m_K[j++] + (R3 & R2) + (~R3 & R1));
         R0 = rotl<1>(R0);
         R1 = static_cast<uint16_t>(R1 + m_K[j++] + (R0 & R3) + (~R0 & R2));
         R1 = rotl<2>(R1);
         R2 = static_cast<uint16_t>(R2 + m_K[j++] + (R1 & R0) + (~R1 & R3));
         R2 = rotl<3>(R2);
         R3 = static_cast<uint16_t>(R3 + m_K[j++] + (R2 & R1) + (~R2 & R0));
         R3 = rotl<5>(R3);
      }

      // 1 mashing round
      R0 = static_cast<uint16_t>(R0 + m_K[R3 & 63]);
      R1 = static_cast<uint16_t>(R1 + m_K[R0 & 63]);
      R2 = static_cast<uint16_t>(R2 + m_K[R1 & 63]);
      R3 = static_cast<uint16_t>(R3 + m_K[R2 & 63]);

      // 5 mixing rounds
      for(size_t i = 0; i < 5; ++i) {
         R0 = static_cast<uint16_t>(R0 + m_K[j++] + (R3 & R2) + (~R3 & R1));
         R0 = rotl<1>(R0);
         R1 = static_cast<uint16_t>(R1 + m_K[j++] + (R0 & R3) + (~R0 & R2));
         R1 = rotl<2>(R1);
         R2 = static_cast<uint16_t>(R2 + m_K[j++] + (R1 & R0) + (~R1 & R3));
         R2 = rotl<3>(R2);
         R3 = static_cast<uint16_t>(R3 + m_K[j++] + (R2 & R1) + (~R2 & R0));
         R3 = rotl<5>(R3);
      }

      store_le(out, R0, R1, R2, R3);

      in += 8;
      out += 8;
   }
}

void RC2::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   for(size_t b = 0; b < blocks; ++b) {
      uint16_t R0 = load_le<uint16_t>(in, 0);
      uint16_t R1 = load_le<uint16_t>(in, 1);
      uint16_t R2 = load_le<uint16_t>(in, 2);
      uint16_t R3 = load_le<uint16_t>(in, 3);

      size_t j = 63;

      // 5 r-mixing rounds
      for(size_t i = 0; i < 5; ++i) {
         R3 = rotr<5>(R3);
         R3 = static_cast<uint16_t>(R3 - m_K[j--] - (R2 & R1) - (~R2 & R0));
         R2 = rotr<3>(R2);
         R2 = static_cast<uint16_t>(R2 - m_K[j--] - (R1 & R0) - (~R1 & R3));
         R1 = rotr<2>(R1);
         R1 = static_cast<uint16_t>(R1 - m_K[j--] - (R0 & R3) - (~R0 & R2));
         R0 = rotr<1>(R0);
         R0 = static_cast<uint16_t>(R0 - m_K[j--] - (R3 & R2) - (~R3 & R1));
      }

      // 1 r-mashing round
      R3 = static_cast<uint16_t>(R3 - m_K[R2 & 63]);
      R2 = static_cast<uint16_t>(R2 - m_K[R1 & 63]);
      R1 = static_cast<uint16_t>(R1 - m_K[R0 & 63]);
      R0 = static_cast<uint16_t>(R0 - m_K[R3 & 63]);

      // 6 r-mixing rounds
      for(size_t i = 0; i < 6; ++i) {
         R3 = rotr<5>(R3);
         R3 = static_cast<uint16_t>(R3 - m_K[j--] - (R2 & R1) - (~R2 & R0));
         R2 = rotr<3>(R2);
         R2 = static_cast<uint16_t>(R2 - m_K[j--] - (R1 & R0) - (~R1 & R3));
         R1 = rotr<2>(R1);
         R1 = static_cast<uint16_t>(R1 - m_K[j--] - (R0 & R3) - (~R0 & R2));
         R0 = rotr<1>(R0);
         R0 = static_cast<uint16_t>(R0 - m_K[j--] - (R3 & R2) - (~R3 & R1));
      }

      // 1 r-mashing round
      R3 = static_cast<uint16_t>(R3 - m_K[R2 & 63]);
      R2 = static_cast<uint16_t>(R2 - m_K[R1 & 63]);
      R1 = static_cast<uint16_t>(R1 - m_K[R0 & 63]);
      R0 = static_cast<uint16_t>(R0 - m_K[R3 & 63]);

      // 5 r-mixing rounds
      for(size_t i = 0; i < 5; ++i) {
         R3 = rotr<5>(R3);
         R3 = static_cast<uint16_t>(R3 - m_K[j--] - (R2 & R1) - (~R2 & R0));
         R2 = rotr<3>(R2);
         R2 = static_cast<uint16_t>(R2 - m_K[j--] - (R1 & R0) - (~R1 & R3));
         R1 = rotr<2>(R1);
         R1 = static_cast<uint16_t>(R1 - m_K[j--] - (R0 & R3) - (~R0 & R2));
         R0 = rotr<1>(R0);
         R0 = static_cast<uint16_t>(R0 - m_K[j--] - (R3 & R2) - (~R3 & R1));
      }

      store_le(out, R0, R1, R2, R3);

      in += 8;
      out += 8;
   }
}

}  // namespace Botan
