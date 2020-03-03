/*
* (C) 2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/divide.h>

void fuzz(const uint8_t in[], size_t len)
   {
   static const size_t max_bits = 4096;

   if(len <= 4)
      return;

   if(len > 2*(max_bits/8))
      return;

   const size_t x_len = 2 * ((len + 2) / 3);

   Botan::BigInt x = Botan::BigInt::decode(in, x_len);
   const Botan::BigInt p = Botan::BigInt::decode(in + x_len, len - x_len);

   if(p.is_zero())
      return;

   const size_t x_bits = x.bits();
   if(x_bits % 8 == 0 && x_bits / 8 == x_len)
      x.flip_sign();

   const Botan::BigInt ref = x % p;

   const Botan::Modular_Reducer mod_p(p);
   const Botan::BigInt z = mod_p.reduce(x);

   const Botan::BigInt ct = ct_modulo(x, p);

   if(ref != z || ref != ct)
      {
      FUZZER_WRITE_AND_CRASH("X = " << x << "\n"
                             << "P = " << p << "\n"
                             << "Barrett = " << z << "\n"
                             << "Ct = " << ct << "\n"
                             << "Ref = " << ref << "\n");
      }
   }
