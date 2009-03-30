/*
* OpenSSL Modular Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_ossl.h>
#include <botan/bn_wrap.h>

namespace Botan {

namespace {

/*
* OpenSSL Modular Exponentiator
*/
class OpenSSL_Modular_Exponentiator : public Modular_Exponentiator
   {
   public:
      void set_base(const BigInt& b) { base = b; }
      void set_exponent(const BigInt& e) { exp = e; }
      BigInt execute() const;
      Modular_Exponentiator* copy() const
         { return new OpenSSL_Modular_Exponentiator(*this); }

      OpenSSL_Modular_Exponentiator(const BigInt& n) : mod(n) {}
   private:
      OSSL_BN base, exp, mod;
      OSSL_BN_CTX ctx;
   };

/*
* Compute the result
*/
BigInt OpenSSL_Modular_Exponentiator::execute() const
   {
   OSSL_BN r;
   BN_mod_exp(r.value, base.value, exp.value, mod.value, ctx.value);
   return r.to_bigint();
   }

}

/*
* Return the OpenSSL-based modular exponentiator
*/
Modular_Exponentiator* OpenSSL_Engine::mod_exp(const BigInt& n,
                                           Power_Mod::Usage_Hints) const
   {
   return new OpenSSL_Modular_Exponentiator(n);
   }

}
