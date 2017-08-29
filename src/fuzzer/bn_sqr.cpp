/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/bigint.h>
#include <botan/numthry.h>

void fuzz(const uint8_t in[], size_t len)
   {
   if(len > 8192/8)
      return;

   Botan::BigInt x = Botan::BigInt::decode(in, len);

   Botan::BigInt x_sqr = square(x);
   Botan::BigInt x_mul = x * x;

   FUZZER_ASSERT_EQUAL(x_sqr, x_mul);
   }

