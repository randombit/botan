/*
* (C) 2015,2016,2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include <botan/internal/divide.h>

void fuzz(const uint8_t in[], size_t len) {
   if(len > 2 * 4096 / 8) {
      return;
   }

   // Save on allocations by making these static
   static Botan::BigInt x, y, q, r, ct_q, ct_r, z;

   x = Botan::BigInt::decode(in, len / 2);
   y = Botan::BigInt::decode(in + len / 2, len - (len / 2));

   if(y == 0) {
      return;
   }

   Botan::vartime_divide(x, y, q, r);

   FUZZER_ASSERT_TRUE(r < y);

   z = q * y + r;

   FUZZER_ASSERT_EQUAL(z, x);

   Botan::ct_divide(x, y, ct_q, ct_r);

   FUZZER_ASSERT_EQUAL(q, ct_q);
   FUZZER_ASSERT_EQUAL(r, ct_r);

   // Now divide by just low word of y

   y = y.word_at(0);
   if(y == 0) {
      return;
   }

   Botan::vartime_divide(x, y, q, r);

   FUZZER_ASSERT_TRUE(r < y);
   z = q * y + r;
   FUZZER_ASSERT_EQUAL(z, x);

   Botan::word rw;
   Botan::ct_divide_word(x, y.word_at(0), ct_q, rw);
   FUZZER_ASSERT_EQUAL(ct_q, q);
   FUZZER_ASSERT_EQUAL(rw, r.word_at(0));
}
