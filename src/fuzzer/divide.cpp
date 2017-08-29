/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"
#include <botan/divide.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len % 2 == 1 || len > 2*4096/8)
      return;

   const Botan::BigInt x = Botan::BigInt::decode(in, len / 2);
   const Botan::BigInt y = Botan::BigInt::decode(in + len / 2, len / 2);

   if(y == 0)
      return;

   Botan::BigInt q, r;
   Botan::divide(x, y, q, r);

   FUZZER_ASSERT_TRUE(r < y);

   Botan::BigInt z = q*y + r;

   FUZZER_ASSERT_EQUAL(z, x);
   }

