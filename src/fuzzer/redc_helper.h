/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FUZZ_REDC_HELPERS_H_
#define BOTAN_FUZZ_REDC_HELPERS_H_

#include "fuzzers.h"
#include <botan/reducer.h>
#include <functional>

namespace {

void check_redc(std::function<void (Botan::BigInt&, Botan::secure_vector<Botan::word>&)> redc_fn,
                const Botan::Modular_Reducer& redc,
                const Botan::BigInt& prime,
                const Botan::BigInt& x)
   {
   const Botan::BigInt v1 = x % prime;
   const Botan::BigInt v2 = redc.reduce(x);

   Botan::secure_vector<Botan::word> ws;
   Botan::BigInt v3 = x;
   redc_fn(v3, ws);

   FUZZER_ASSERT_EQUAL(v1, v2);
   FUZZER_ASSERT_EQUAL(v2, v3);
   }

}

#endif
