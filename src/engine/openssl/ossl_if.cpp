/*
* OpenSSL IF Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_ossl.h>
#include <botan/bn_wrap.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x0090700F
  #error Your OpenSSL install is too old, upgrade to 0.9.7 or later
#endif

namespace Botan {

#if defined(BOTAN_HAS_IF_PUBLIC_KEY_FAMILY)

namespace {

/*
* OpenSSL IF Operation
*/
class OpenSSL_IF_Op : public IF_Operation
   {
   public:
      BigInt public_op(const BigInt&) const;
      BigInt private_op(const BigInt&) const;

      IF_Operation* clone() const { return new OpenSSL_IF_Op(*this); }

      OpenSSL_IF_Op(const BigInt& e_bn, const BigInt& n_bn, const BigInt&,
                const BigInt& p_bn, const BigInt& q_bn, const BigInt& d1_bn,
                const BigInt& d2_bn, const BigInt& c_bn) :
         e(e_bn), n(n_bn), p(p_bn), q(q_bn), d1(d1_bn), d2(d2_bn), c(c_bn) {}
   private:
      const OSSL_BN e, n, p, q, d1, d2, c;
      OSSL_BN_CTX ctx;
   };

/*
* OpenSSL IF Public Operation
*/
BigInt OpenSSL_IF_Op::public_op(const BigInt& i_bn) const
   {
   OSSL_BN i(i_bn), r;
   BN_mod_exp(r.value, i.value, e.value, n.value, ctx.value);
   return r.to_bigint();
   }

/*
* OpenSSL IF Private Operation
*/
BigInt OpenSSL_IF_Op::private_op(const BigInt& i_bn) const
   {
   if(BN_is_zero(p.value))
      throw Internal_Error("OpenSSL_IF_Op::private_op: No private key");

   OSSL_BN j1, j2, h(i_bn);

   BN_mod_exp(j1.value, h.value, d1.value, p.value, ctx.value);
   BN_mod_exp(j2.value, h.value, d2.value, q.value, ctx.value);
   BN_sub(h.value, j1.value, j2.value);
   BN_mod_mul(h.value, h.value, c.value, p.value, ctx.value);
   BN_mul(h.value, h.value, q.value, ctx.value);
   BN_add(h.value, h.value, j2.value);
   return h.to_bigint();
   }

}

/*
* Acquire an IF op
*/
IF_Operation* OpenSSL_Engine::if_op(const BigInt& e, const BigInt& n,
                                    const BigInt& d, const BigInt& p,
                                    const BigInt& q, const BigInt& d1,
                                    const BigInt& d2, const BigInt& c) const
   {
   return new OpenSSL_IF_Op(e, n, d, p, q, d1, d2, c);
   }
#endif

}
