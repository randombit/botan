/*
* GOST 28147-89
* (C) 1999-2009,2011 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/gost_28147.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

uint8_t GOST_28147_89_Params::sbox_entry(size_t row, size_t col) const
   {
   const uint8_t x = m_sboxes[4 * col + (row / 2)];
   return (row % 2 == 0) ? (x >> 4) : (x & 0x0F);
   }

uint8_t GOST_28147_89_Params::sbox_pair(size_t row, size_t col) const
   {
   const uint8_t x = m_sboxes[4 * (col % 16) + row];
   const uint8_t y = m_sboxes[4 * (col / 16) + row];
   return (x >> 4) | (y << 4);
   }

GOST_28147_89_Params::GOST_28147_89_Params(const std::string& n) : m_name(n)
   {
   // Encoded in the packed fromat from RFC 4357

   // GostR3411_94_TestParamSet (OID 1.2.643.2.2.31.0)
   static const uint8_t GOST_R_3411_TEST_PARAMS[64] = {
      0x4E, 0x57, 0x64, 0xD1, 0xAB, 0x8D, 0xCB, 0xBF, 0x94, 0x1A, 0x7A,
      0x4D, 0x2C, 0xD1, 0x10, 0x10, 0xD6, 0xA0, 0x57, 0x35, 0x8D, 0x38,
      0xF2, 0xF7, 0x0F, 0x49, 0xD1, 0x5A, 0xEA, 0x2F, 0x8D, 0x94, 0x62,
      0xEE, 0x43, 0x09, 0xB3, 0xF4, 0xA6, 0xA2, 0x18, 0xC6, 0x98, 0xE3,
      0xC1, 0x7C, 0xE5, 0x7E, 0x70, 0x6B, 0x09, 0x66, 0xF7, 0x02, 0x3C,
      0x8B, 0x55, 0x95, 0xBF, 0x28, 0x39, 0xB3, 0x2E, 0xCC };

   // GostR3411-94-CryptoProParamSet (OID 1.2.643.2.2.31.1)
   static const uint8_t GOST_R_3411_CRYPTOPRO_PARAMS[64] = {
      0xA5, 0x74, 0x77, 0xD1, 0x4F, 0xFA, 0x66, 0xE3, 0x54, 0xC7, 0x42,
      0x4A, 0x60, 0xEC, 0xB4, 0x19, 0x82, 0x90, 0x9D, 0x75, 0x1D, 0x4F,
      0xC9, 0x0B, 0x3B, 0x12, 0x2F, 0x54, 0x79, 0x08, 0xA0, 0xAF, 0xD1,
      0x3E, 0x1A, 0x38, 0xC7, 0xB1, 0x81, 0xC6, 0xE6, 0x56, 0x05, 0x87,
      0x03, 0x25, 0xEB, 0xFE, 0x9C, 0x6D, 0xF8, 0x6D, 0x2E, 0xAB, 0xDE,
      0x20, 0xBA, 0x89, 0x3C, 0x92, 0xF8, 0xD3, 0x53, 0xBC };

   if(m_name == "R3411_94_TestParam")
      m_sboxes = GOST_R_3411_TEST_PARAMS;
   else if(m_name == "R3411_CryptoPro")
      m_sboxes = GOST_R_3411_CRYPTOPRO_PARAMS;
   else
      throw Invalid_Argument("GOST_28147_89_Params: Unknown " + m_name);
   }

/*
* GOST Constructor
*/
GOST_28147_89::GOST_28147_89(const GOST_28147_89_Params& param) : m_SBOX(1024)
   {
   // Convert the parallel 4x4 sboxes into larger word-based sboxes

   for(size_t i = 0; i != 256; ++i)
      {
      m_SBOX[i    ] = rotl<11, uint32_t>(param.sbox_pair(0, i));
      m_SBOX[i+256] = rotl<19, uint32_t>(param.sbox_pair(1, i));
      m_SBOX[i+512] = rotl<27, uint32_t>(param.sbox_pair(2, i));
      m_SBOX[i+768] = rotl< 3, uint32_t>(param.sbox_pair(3, i));
      }
   }

std::string GOST_28147_89::name() const
   {
   /*
   'Guess' the right name for the sbox on the basis of the values.
   This would need to be updated if support for other sbox parameters
   is added. Preferably, we would just store the string value in the
   constructor, but can't break binary compat.
   */
   std::string sbox_name = "";
   if(m_SBOX[0] == 0x00072000)
      sbox_name = "R3411_94_TestParam";
   else if(m_SBOX[0] == 0x0002D000)
      sbox_name = "R3411_CryptoPro";
   else
      throw Internal_Error("GOST-28147 unrecognized sbox value");

   return "GOST-28147-89(" + sbox_name + ")";
   }

/*
* Two rounds of GOST
*/
#define GOST_2ROUND(N1, N2, R1, R2)   \
   do {                               \
   uint32_t T0 = N1 + m_EK[R1];           \
   N2 ^= m_SBOX[get_byte(3, T0)] |      \
         m_SBOX[get_byte(2, T0)+256] |  \
         m_SBOX[get_byte(1, T0)+512] |  \
         m_SBOX[get_byte(0, T0)+768];   \
                                      \
   uint32_t T1 = N2 + m_EK[R2];           \
   N1 ^= m_SBOX[get_byte(3, T1)] |      \
         m_SBOX[get_byte(2, T1)+256] |  \
         m_SBOX[get_byte(1, T1)+512] |  \
         m_SBOX[get_byte(0, T1)+768];   \
   } while(0)

/*
* GOST Encryption
*/
void GOST_28147_89::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_EK.empty() == false);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t N1 = load_le<uint32_t>(in, 0);
      uint32_t N2 = load_le<uint32_t>(in, 1);

      for(size_t j = 0; j != 3; ++j)
         {
         GOST_2ROUND(N1, N2, 0, 1);
         GOST_2ROUND(N1, N2, 2, 3);
         GOST_2ROUND(N1, N2, 4, 5);
         GOST_2ROUND(N1, N2, 6, 7);
         }

      GOST_2ROUND(N1, N2, 7, 6);
      GOST_2ROUND(N1, N2, 5, 4);
      GOST_2ROUND(N1, N2, 3, 2);
      GOST_2ROUND(N1, N2, 1, 0);

      store_le(out, N2, N1);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* GOST Decryption
*/
void GOST_28147_89::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_EK.empty() == false);

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t N1 = load_le<uint32_t>(in, 0);
      uint32_t N2 = load_le<uint32_t>(in, 1);

      GOST_2ROUND(N1, N2, 0, 1);
      GOST_2ROUND(N1, N2, 2, 3);
      GOST_2ROUND(N1, N2, 4, 5);
      GOST_2ROUND(N1, N2, 6, 7);

      for(size_t j = 0; j != 3; ++j)
         {
         GOST_2ROUND(N1, N2, 7, 6);
         GOST_2ROUND(N1, N2, 5, 4);
         GOST_2ROUND(N1, N2, 3, 2);
         GOST_2ROUND(N1, N2, 1, 0);
         }

      store_le(out, N2, N1);
      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* GOST Key Schedule
*/
void GOST_28147_89::key_schedule(const uint8_t key[], size_t)
   {
   m_EK.resize(8);
   for(size_t i = 0; i != 8; ++i)
      m_EK[i] = load_le<uint32_t>(key, i);
   }

void GOST_28147_89::clear()
   {
   zap(m_EK);
   }

}
