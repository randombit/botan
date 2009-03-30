/*
* GMP IF Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_gmp.h>
#include <botan/gmp_wrap.h>
#include <gmp.h>

namespace Botan {

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)

namespace {

/*
* GMP IF Operation
*/
class GMP_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Operation* clone() const { return new GMP_IF_Op(*this); }

      GMP_IF_Op(const BigInt& e_bn, const BigInt& n_bn, const BigInt&,
                const BigInt& p_bn, const BigInt& q_bn, const BigInt& d1_bn,
                const BigInt& d2_bn, const BigInt& c_bn) :
         e(e_bn), n(n_bn), p(p_bn), q(q_bn), d1(d1_bn), d2(d2_bn), c(c_bn) {}
   private:
      const GMP_MPZ e, n, p, q, d1, d2, c;
   };

/*
* GMP IF Public Operation
*/
BigInt GMP_IF_Op::public_op(const BigInt& i_bn) const
   {
   GMP_MPZ i(i_bn);
   mpz_powm(i.value, i.value, e.value, n.value);
   return i.to_bigint();
   }

/*
* GMP IF Private Operation
*/
BigInt GMP_IF_Op::private_op(const BigInt& i_bn) const
   {
   if(mpz_cmp_ui(p.value, 0) == 0)
      throw Internal_Error("GMP_IF_Op::private_op: No private key");

   GMP_MPZ j1, j2, h(i_bn);

   mpz_powm(j1.value, h.value, d1.value, p.value);
   mpz_powm(j2.value, h.value, d2.value, q.value);
   mpz_sub(h.value, j1.value, j2.value);
   mpz_mul(h.value, h.value, c.value);
   mpz_mod(h.value, h.value, p.value);
   mpz_mul(h.value, h.value, q.value);
   mpz_add(h.value, h.value, j2.value);
   return h.to_bigint();
   }

}

/*
* Acquire an IF op
*/
IF_Operation* GMP_Engine::if_op(const BigInt& e, const BigInt& n,
                                const BigInt& d, const BigInt& p,
                                const BigInt& q, const BigInt& d1,
                                const BigInt& d2, const BigInt& c) const
   {
   return new GMP_IF_Op(e, n, d, p, q, d1, d2, c);
   }
#endif

}
