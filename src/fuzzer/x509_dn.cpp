/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/ber_dec.h>
#include <botan/hex.h>
#include <botan/pkix_types.h>

void fuzz(const uint8_t in[], size_t len) {
   Botan::X509_DN dn1;
   Botan::X509_DN dn2;

   try {
      Botan::BER_Decoder ber(in, len);
      dn1.decode_from(ber);
      dn2.decode_from(ber);
   } catch(...) {
      return;
   }

   const bool eq = dn1 == dn2;
   const bool lt1 = dn1 < dn2;
   const bool lt2 = dn2 < dn1;

   if(lt1 == false && lt2 == false) {
      FUZZER_ASSERT_TRUE(eq);
   } else {
      // one is less than the other
      FUZZER_ASSERT_TRUE(lt1 || lt2);

      // it is not the case that both are less than the other
      FUZZER_ASSERT_TRUE(!lt1 || !lt2);
   }
}
