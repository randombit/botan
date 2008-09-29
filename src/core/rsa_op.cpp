/*************************************************
* IF (RSA/RW) Operation Source File              *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eng_def.h>
#include <botan/pow_mod.h>
#include <botan/numthry.h>
#include <botan/reducer.h>

namespace Botan {

namespace {

/*************************************************
* Default IF Operation                           *
*************************************************/
class Default_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt& i) const
         { return powermod_e_n(i); }
      BigInt private_op(const BigInt&) const;

      IF_Operation* clone() const { return new Default_IF_Op(*this); }

      Default_IF_Op(const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&, const BigInt&,
                    const BigInt&, const BigInt&);
   private:
      Fixed_Exponent_Power_Mod powermod_e_n, powermod_d1_p, powermod_d2_q;
      Modular_Reducer reducer;
      BigInt c, q;
   };

/*************************************************
* Default_IF_Op Constructor                      *
*************************************************/
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

/*************************************************
* Default IF Private Operation                   *
*************************************************/
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

/*************************************************
* Acquire an IF op                               *
*************************************************/
IF_Operation* Default_Engine::if_op(const BigInt& e, const BigInt& n,
                                    const BigInt& d, const BigInt& p,
                                    const BigInt& q, const BigInt& d1,
                                    const BigInt& d2, const BigInt& c) const
   {
   return new Default_IF_Op(e, n, d, p, q, d1, d2, c);
   }

}
