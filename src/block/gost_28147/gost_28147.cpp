/*
* GOST 28147-89
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/gost_28147.h>
#include <botan/loadstor.h>

namespace Botan {

byte GOST_28147_89_Params::sbox_entry(u32bit row, u32bit col) const
   {
   byte x = sboxes[4 * col + (row / 2)];

   return (row % 2 == 0) ? (x >> 4) : (x & 0x0F);
   }

GOST_28147_89_Params::GOST_28147_89_Params(const std::string& n) : name(n)
   {
   // Encoded in the packed fromat from RFC 4357

   // GostR3411_94_TestParamSet (OID 1.2.643.2.2.31.0)
   static const byte GOST_R_3411_TEST_PARAMS[64] = {
      0x4E, 0x57, 0x64, 0xD1, 0xAB, 0x8D, 0xCB, 0xBF, 0x94, 0x1A, 0x7A,
      0x4D, 0x2C, 0xD1, 0x10, 0x10, 0xD6, 0xA0, 0x57, 0x35, 0x8D, 0x38,
      0xF2, 0xF7, 0x0F, 0x49, 0xD1, 0x5A, 0xEA, 0x2F, 0x8D, 0x94, 0x62,
      0xEE, 0x43, 0x09, 0xB3, 0xF4, 0xA6, 0xA2, 0x18, 0xC6, 0x98, 0xE3,
      0xC1, 0x7C, 0xE5, 0x7E, 0x70, 0x6B, 0x09, 0x66, 0xF7, 0x02, 0x3C,
      0x8B, 0x55, 0x95, 0xBF, 0x28, 0x39, 0xB3, 0x2E, 0xCC };

   // GostR3411-94-CryptoProParamSet (OID 1.2.643.2.2.31.1)
   static const byte GOST_R_3411_CRYPTOPRO_PARAMS[64] = {
      0xA5, 0x74, 0x77, 0xD1, 0x4F, 0xFA, 0x66, 0xE3, 0x54, 0xC7, 0x42,
      0x4A, 0x60, 0xEC, 0xB4, 0x19, 0x82, 0x90, 0x9D, 0x75, 0x1D, 0x4F,
      0xC9, 0x0B, 0x3B, 0x12, 0x2F, 0x54, 0x79, 0x08, 0xA0, 0xAF, 0xD1,
      0x3E, 0x1A, 0x38, 0xC7, 0xB1, 0x81, 0xC6, 0xE6, 0x56, 0x05, 0x87,
      0x03, 0x25, 0xEB, 0xFE, 0x9C, 0x6D, 0xF8, 0x6D, 0x2E, 0xAB, 0xDE,
      0x20, 0xBA, 0x89, 0x3C, 0x92, 0xF8, 0xD3, 0x53, 0xBC };

   if(name == "R3411_94_TestParam")
      sboxes = GOST_R_3411_TEST_PARAMS;
   else if(name == "R3411_CryptoPro")
      sboxes = GOST_R_3411_CRYPTOPRO_PARAMS;
   else
      throw Invalid_Argument("GOST_28147_89_Params: Unknown " + name);
   }

/*
* GOST Constructor
*/
GOST_28147_89::GOST_28147_89(const GOST_28147_89_Params& gost_sbox) :
   BlockCipher(8, 32)
   {
   // Convert the parallel 4x4 sboxes into larger word-based sboxes
   for(size_t i = 0; i != 4; ++i)
      for(size_t j = 0; j != 256; ++j)
         {
         u32bit T = (gost_sbox.sbox_entry(2*i  , j % 16)) |
                    (gost_sbox.sbox_entry(2*i+1, j / 16) << 4);
         SBOX[256*i+j] = rotate_left(T, (11+8*i) % 32);
         }
   }

/*
* Two rounds of GOST
*/
#define GOST_2ROUND(N1, N2, R1, R2)   \
   do {                               \
   u32bit T0 = N1 + EK[R1];           \
   N2 ^= SBOX[get_byte(3, T0)] |      \
         SBOX[get_byte(2, T0)+256] |  \
         SBOX[get_byte(1, T0)+512] |  \
         SBOX[get_byte(0, T0)+768];   \
                                      \
   u32bit T1 = N2 + EK[R2];           \
   N1 ^= SBOX[get_byte(3, T1)] |      \
         SBOX[get_byte(2, T1)+256] |  \
         SBOX[get_byte(1, T1)+512] |  \
         SBOX[get_byte(0, T1)+768];   \
   } while(0)

/*
* GOST Encryption
*/
void GOST_28147_89::enc(const byte in[], byte out[]) const
   {
   u32bit N1 = load_le<u32bit>(in, 0), N2 = load_le<u32bit>(in, 1);

   for(size_t i = 0; i != 3; ++i)
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
   }

/*
* GOST Decryption
*/
void GOST_28147_89::dec(const byte in[], byte out[]) const
   {
   u32bit N1 = load_le<u32bit>(in, 0), N2 = load_le<u32bit>(in, 1);

   GOST_2ROUND(N1, N2, 0, 1);
   GOST_2ROUND(N1, N2, 2, 3);
   GOST_2ROUND(N1, N2, 4, 5);
   GOST_2ROUND(N1, N2, 6, 7);

   for(size_t i = 0; i != 3; ++i)
      {
      GOST_2ROUND(N1, N2, 7, 6);
      GOST_2ROUND(N1, N2, 5, 4);
      GOST_2ROUND(N1, N2, 3, 2);
      GOST_2ROUND(N1, N2, 1, 0);
      }

   store_le(out, N2, N1);
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
   if(SBOX[0] == 0x00072000)
      sbox_name = "R3411_94_TestParam";
   else if(SBOX[0] == 0x0002D000)
      sbox_name = "R3411_CryptoPro";
   else
      throw Internal_Error("GOST-28147 unrecognized sbox value");

   return "GOST-28147-89(" + sbox_name + ")";
   }

/*
* GOST Key Schedule
*/
void GOST_28147_89::key_schedule(const byte key[], u32bit)
   {
   for(u32bit j = 0; j != 8; ++j)
      EK[j] = load_le<u32bit>(key, j);
   }

}
