/*
* (C) 2015,2016,2018,2021 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "fuzzers.h"

#include <botan/internal/divide.h>

void fuzz(std::span<const uint8_t> in) {
   if(in.size() > 2 * 4096 / 8) {
      return;
   }

   // Save on allocations by making these static
   static Botan::BigInt x;
   static Botan::BigInt y;
   static Botan::BigInt q;
   static Botan::BigInt r;
   static Botan::BigInt z;
   static Botan::BigInt ct_q;

   x = Botan::BigInt::from_bytes(in.subspan(0, in.size() / 2));
   y = Botan::BigInt::from_bytes(in.subspan(in.size() / 2, in.size() - in.size() / 2));

   if(y == 0) {
      return;
   }

   Botan::ct_divide(x, y, q, r);

   FUZZER_ASSERT_TRUE(r < y);

   z = q * y + r;

   FUZZER_ASSERT_EQUAL(z, x);

   // Now divide by just low word of y, cross-checking the word division
   // against the general division

   const Botan::word yw = y.word_at(0);
   if(yw == 0) {
      return;
   }

   y = Botan::BigInt::from_word(yw);

   Botan::ct_divide(x, y, q, r);

   FUZZER_ASSERT_TRUE(r < y);
   z = q * y + r;
   FUZZER_ASSERT_EQUAL(z, x);

   Botan::word rw = 0;
   Botan::ct_divide_word(x, yw, ct_q, rw);
   FUZZER_ASSERT_EQUAL(ct_q, q);
   FUZZER_ASSERT_EQUAL(rw, r.word_at(0));
}
