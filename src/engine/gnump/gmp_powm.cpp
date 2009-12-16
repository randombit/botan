/*
* GMP Modular Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/gnump_engine.h>
#include <botan/internal/gmp_wrap.h>

namespace Botan {

namespace {

/*
* GMP Modular Exponentiator
*/
class GMP_Modular_Exponentiator : public Modular_Exponentiator
   {
   public:
      void set_base(const BigInt& b) { base = b; }
      void set_exponent(const BigInt& e) { exp = e; }
      BigInt execute() const;
      Modular_Exponentiator* copy() const
         { return new GMP_Modular_Exponentiator(*this); }

      GMP_Modular_Exponentiator(const BigInt& n) : mod(n) {}
   private:
      GMP_MPZ base, exp, mod;
   };

/*
* Compute the result
*/
BigInt GMP_Modular_Exponentiator::execute() const
   {
   GMP_MPZ r;
   mpz_powm(r.value, base.value, exp.value, mod.value);
   return r.to_bigint();
   }

}

/*
* Return the GMP-based modular exponentiator
*/
Modular_Exponentiator* GMP_Engine::mod_exp(const BigInt& n,
                                           Power_Mod::Usage_Hints) const
   {
   return new GMP_Modular_Exponentiator(n);
   }

}
