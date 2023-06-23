/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/reducer.h>
#include <botan/internal/curve_nistp.h>

void fuzz(const uint8_t in[], size_t len) {
   if(len > 2 * 384 / 8) {
      return;
   }

   static const Botan::BigInt& prime = Botan::prime_p384();
   static const Botan::BigInt prime_2 = prime * prime;
   static Botan::Modular_Reducer prime_redc(prime);

   Botan::BigInt input = Botan::BigInt::decode(in, len);

   if(input < prime_2) {
      const Botan::BigInt ref = prime_redc.reduce(input);

      Botan::secure_vector<Botan::word> ws;
      Botan::redc_p384(input, ws);

      FUZZER_ASSERT_EQUAL(ref, input);
   }
}
