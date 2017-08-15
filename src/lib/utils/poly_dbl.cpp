/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/poly_dbl.h>
#include <botan/loadstor.h>
#include <botan/exceptn.h>

namespace Botan {

void poly_double_n(uint8_t b[], size_t n)
   {
   if(n == 8)
      return poly_double_8(b);
   else if(n == 16)
      return poly_double_16(b);
   else if(n == 24)
      return poly_double_24(b);
   else if(n == 32)
      return poly_double_32(b);
   else if(n == 64)
      return poly_double_64(b);
   else
      throw Invalid_Argument("Unsupported size for poly_double_n");
   }

void poly_double_8(uint8_t b[8])
   {
   const uint64_t poly = 0x1B;
   uint64_t b0 = load_be<uint64_t>(b, 0);
   const uint64_t carry0 = (b0 >> 63);
   b0 = (b0 << 1) ^ (carry0 * poly);
   store_be(b0, b);
   }

void poly_double_16(uint8_t b[16])
   {
   const uint64_t poly = 0x87;

   uint64_t b0 = load_be<uint64_t>(b, 0);
   uint64_t b1 = load_be<uint64_t>(b, 1);

   const uint64_t carry0 = (b0 >> 63);

   b0 = (b0 << 1) ^ (b1 >> 63);
   b1 = (b1 << 1) ^ (carry0 * poly);

   store_be(b0, b);
   store_be(b1, b+8);
   }

void poly_double_24(uint8_t b[24])
   {
   const uint64_t poly = 0x87;

   uint64_t b0 = load_be<uint64_t>(b, 0);
   uint64_t b1 = load_be<uint64_t>(b, 1);
   uint64_t b2 = load_be<uint64_t>(b, 2);

   const uint64_t carry0 = (b0 >> 63);

   b0 = (b0 << 1) ^ (b1 >> 63);
   b1 = (b1 << 1) ^ (b2 >> 63);
   b2 = (b2 << 1) ^ (carry0 * poly);

   store_be(b0, b);
   store_be(b1, b+8);
   store_be(b2, b+16);
   }

void poly_double_32(uint8_t b[32])
   {
   const uint64_t poly = 0x425;

   uint64_t b0 = load_be<uint64_t>(b, 0);
   uint64_t b1 = load_be<uint64_t>(b, 1);
   uint64_t b2 = load_be<uint64_t>(b, 2);
   uint64_t b3 = load_be<uint64_t>(b, 3);

   const uint64_t carry0 = (b0 >> 63);

   b0 = (b0 << 1) ^ (b1 >> 63);
   b1 = (b1 << 1) ^ (b2 >> 63);
   b2 = (b2 << 1) ^ (b3 >> 63);
   b3 = (b3 << 1) ^ (carry0 * poly);

   store_be(b0, b);
   store_be(b1, b+8);
   store_be(b2, b+16);
   store_be(b3, b+24);
   }

void poly_double_64(uint8_t b[64])
   {
   const uint64_t poly = 0x125;

   uint64_t b0 = load_be<uint64_t>(b, 0);
   uint64_t b1 = load_be<uint64_t>(b, 1);
   uint64_t b2 = load_be<uint64_t>(b, 2);
   uint64_t b3 = load_be<uint64_t>(b, 3);
   uint64_t b4 = load_be<uint64_t>(b, 4);
   uint64_t b5 = load_be<uint64_t>(b, 5);
   uint64_t b6 = load_be<uint64_t>(b, 6);
   uint64_t b7 = load_be<uint64_t>(b, 7);

   const uint64_t carry0 = (b0 >> 63);

   b0 = (b0 << 1) ^ (b1 >> 63);
   b1 = (b1 << 1) ^ (b2 >> 63);
   b2 = (b2 << 1) ^ (b3 >> 63);
   b3 = (b3 << 1) ^ (b4 >> 63);
   b4 = (b4 << 1) ^ (b5 >> 63);
   b5 = (b5 << 1) ^ (b6 >> 63);
   b6 = (b6 << 1) ^ (b7 >> 63);
   b7 = (b7 << 1) ^ (carry0 * poly);

   store_be(b0, b);
   store_be(b1, b+8);
   store_be(b2, b+16);
   store_be(b3, b+24);
   store_be(b4, b+32);
   store_be(b5, b+40);
   store_be(b6, b+48);
   store_be(b7, b+56);
   }

}
