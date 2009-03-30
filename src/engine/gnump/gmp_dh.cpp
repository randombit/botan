/*
* GMP Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_gmp.h>
#include <botan/gmp_wrap.h>
#include <gmp.h>

namespace Botan {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
namespace {

/*
* GMP DH Operation
*/
class GMP_DH_Op : public DH_Operation
   {
   public:
      BigInt agree(const BigInt& i) const;
      DH_Operation* clone() const { return new GMP_DH_Op(*this); }

      GMP_DH_Op(const DL_Group& group, const BigInt& x_bn) :
         x(x_bn), p(group.get_p()) {}
   private:
      GMP_MPZ x, p;
   };

/*
* GMP DH Key Agreement Operation
*/
BigInt GMP_DH_Op::agree(const BigInt& i_bn) const
   {
   GMP_MPZ i(i_bn);
   mpz_powm(i.value, i.value, x.value, p.value);
   return i.to_bigint();
   }

}

/*
* Acquire a DH op
*/
DH_Operation* GMP_Engine::dh_op(const DL_Group& group, const BigInt& x) const
   {
   return new GMP_DH_Op(group, x);
   }
#endif

}
