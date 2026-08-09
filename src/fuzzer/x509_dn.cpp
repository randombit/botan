/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/ber_dec.h>
#include <botan/pkix_types.h>

namespace {

void check_pairwise(const Botan::X509_DN& a, const Botan::X509_DN& b) {
   const bool eq = a == b;
   const bool lt1 = a < b;
   const bool lt2 = b < a;

   if(lt1 == false && lt2 == false) {
      FUZZER_ASSERT_TRUE(eq);
   } else {
      FUZZER_ASSERT_TRUE(!eq);
      FUZZER_ASSERT_TRUE(!lt1 || !lt2);
   }
}

void check_transitivity(const Botan::X509_DN& a, const Botan::X509_DN& b, const Botan::X509_DN& c) {
   const bool ab = a < b;
   const bool ba = b < a;
   const bool bc = b < c;
   const bool cb = c < b;
   const bool ac = a < c;
   const bool ca = c < a;

   // a < b && b < c => a < c
   if(ab && bc) {
      FUZZER_ASSERT_TRUE(ac);
   }
   if(cb && ba) {
      FUZZER_ASSERT_TRUE(ca);
   }
   if(ac && cb) {
      FUZZER_ASSERT_TRUE(ab);
   }

   // equivalence: !(a<b) && !(b<a) means a~b
   // a~b && b<c => a<c
   if(!ab && !ba && bc) {
      FUZZER_ASSERT_TRUE(ac);
   }
   if(!ab && !ba && cb) {
      FUZZER_ASSERT_TRUE(ca);
   }
   if(!bc && !cb && ab) {
      FUZZER_ASSERT_TRUE(ac);
   }
   if(!bc && !cb && ca) {
      FUZZER_ASSERT_TRUE(ba);
   }
}

}  // namespace

void fuzz(std::span<const uint8_t> in) {
   Botan::X509_DN dn1;
   Botan::X509_DN dn2;
   Botan::X509_DN dn3;

   try {
      Botan::BER_Decoder ber(in);
      dn1.decode_from(ber);
      dn2.decode_from(ber);
      dn3.decode_from(ber);
   } catch(...) {
      return;
   }

   // Pairwise consistency of < and ==
   check_pairwise(dn1, dn2);
   check_pairwise(dn1, dn3);
   check_pairwise(dn2, dn3);

   // Transitivity across all three
   check_transitivity(dn1, dn2, dn3);
   check_transitivity(dn1, dn3, dn2);
   check_transitivity(dn2, dn1, dn3);
}
