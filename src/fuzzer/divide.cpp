/*
* (C) 2015,2016,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"
#include <botan/divide.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len % 2 == 1 || len > 2*4096/8)
      return;

   // Save on allocations by making these static
   static Botan::BigInt x, y, q, r, ct_q, ct_r, z;

   x = Botan::BigInt::decode(in, len / 2);
   y = Botan::BigInt::decode(in + len / 2, len / 2);

   if(y == 0)
      return;

   Botan::divide(x, y, q, r);

   FUZZER_ASSERT_TRUE(r < y);

   z = q*y + r;

   FUZZER_ASSERT_EQUAL(z, x);

   Botan::ct_divide(x, y, ct_q, ct_r);

   FUZZER_ASSERT_EQUAL(q, ct_q);
   FUZZER_ASSERT_EQUAL(r, ct_r);

   // Now divide by just low byte of y

   y = y.byte_at(0);
   if(y == 0)
      y = 251;
   Botan::divide(x, y, q, r);

   z = q*y + r;
   FUZZER_ASSERT_EQUAL(z, x);

   uint8_t r8;
   Botan::ct_divide_u8(x, y.byte_at(0), ct_q, r8);
   FUZZER_ASSERT_EQUAL(ct_q, q);
   FUZZER_ASSERT_EQUAL(r8, r.byte_at(0));

   }

