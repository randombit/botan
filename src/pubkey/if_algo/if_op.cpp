/*
* IF (RSA/RW) Operation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/if_op.h>
#include <botan/numthry.h>

namespace Botan {

/*
* Default_IF_Op Constructor
*/
Default_IF_Op::Default_IF_Op(const BigInt& e, const BigInt& n, const BigInt&,
                             const BigInt& p, const BigInt& q,
                             const BigInt& d1, const BigInt& d2,
                             const BigInt& c)
   {
   powermod_e_n = Fixed_Exponent_Power_Mod(e, n);

   if(d1 != 0 && d2 != 0 && p != 0 && q != 0)
      {
      powermod_d1_p = Fixed_Exponent_Power_Mod(d1, p);
      powermod_d2_q = Fixed_Exponent_Power_Mod(d2, q);
      reducer = Modular_Reducer(p);
      this->c = c;
      this->q = q;
      }
   }

/*
* Default IF Private Operation
*/
BigInt Default_IF_Op::private_op(const BigInt& i) const
   {
   if(q == 0)
      throw Internal_Error("Default_IF_Op::private_op: No private key");

   BigInt j1 = powermod_d1_p(i);
   BigInt j2 = powermod_d2_q(i);
   j1 = reducer.reduce(sub_mul(j1, j2, c));
   return mul_add(j1, q, j2);
   }

}
