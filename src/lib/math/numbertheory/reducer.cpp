/*
* Modular Reducer
* (C) 1999-2011,2018,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/reducer.h>

#include <botan/internal/divide.h>

namespace Botan {

Modular_Reducer::Modular_Reducer(const BigInt& mod) {
   if(mod < 0) {
      throw Invalid_Argument("Modular_Reducer: modulus must be positive");
   }

   m_modulus = mod;
}

BigInt Modular_Reducer::reduce(const BigInt& x) const {
   return ct_modulo(x, m_modulus);
}

}  // namespace Botan
