/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "driver.h"
#include "ecc_helper.h"
#include <botan/curve_nistp.h>

void fuzz(const uint8_t in[], size_t len)
   {
   static const BigInt& prime = Botan::prime_p224();
   static const BigInt prime_2 = prime * prime;
   static Botan::Modular_Reducer prime_redc(prime);

   Botan::BigInt x = Botan::BigInt::decode(in, len);

   if(x < prime_2)
      {
      check_redc(Botan::redc_p224, prime_redc, prime, x);
      }
   }
