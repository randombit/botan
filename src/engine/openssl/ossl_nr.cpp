/*
* OpenSSL NR Engine
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

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)

namespace {

/*
* OpenSSL NR Operation
*/
class OpenSSL_NR_Op : public NR_Operation
   {
   public:
      SecureVector<byte> verify(const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      NR_Operation* clone() const { return new OpenSSL_NR_Op(*this); }

      OpenSSL_NR_Op(const DL_Group& group, const BigInt& y1,
                    const BigInt& x1) :
         x(x1), y(y1), p(group.get_p()), q(group.get_q()), g(group.get_g()) {}
   private:
      const OSSL_BN x, y, p, q, g;
      OSSL_BN_CTX ctx;
   };

/*
* OpenSSL NR Verify Operation
*/
SecureVector<byte> OpenSSL_NR_Op::verify(const byte sig[],
                                         u32bit sig_len) const
   {
   const u32bit q_bytes = q.bytes();

   if(sig_len != 2*q_bytes)
      return false;

   OSSL_BN c(sig, q_bytes);
   OSSL_BN d(sig + q_bytes, q_bytes);

   if(BN_is_zero(c.value) || BN_cmp(c.value, q.value) >= 0 ||
                             BN_cmp(d.value, q.value) >= 0)
      throw Invalid_Argument("OpenSSL_NR_Op::verify: Invalid signature");

   OSSL_BN i1, i2;
   BN_mod_exp(i1.value, g.value, d.value, p.value, ctx.value);
   BN_mod_exp(i2.value, y.value, c.value, p.value, ctx.value);
   BN_mod_mul(i1.value, i1.value, i2.value, p.value, ctx.value);
   BN_sub(i1.value, c.value, i1.value);
   BN_nnmod(i1.value, i1.value, q.value, ctx.value);
   return BigInt::encode(i1.to_bigint());
   }

/*
* OpenSSL NR Sign Operation
*/
SecureVector<byte> OpenSSL_NR_Op::sign(const byte in[], u32bit length,
                                       const BigInt& k_bn) const
   {
   if(BN_is_zero(x.value))
      throw Internal_Error("OpenSSL_NR_Op::sign: No private key");

   OSSL_BN f(in, length);
   OSSL_BN k(k_bn);

   if(BN_cmp(f.value, q.value) >= 0)
      throw Invalid_Argument("OpenSSL_NR_Op::sign: Input is out of range");

   OSSL_BN c, d;
   BN_mod_exp(c.value, g.value, k.value, p.value, ctx.value);
   BN_add(c.value, c.value, f.value);
   BN_nnmod(c.value, c.value, q.value, ctx.value);
   BN_mul(d.value, x.value, c.value, ctx.value);
   BN_sub(d.value, k.value, d.value);
   BN_nnmod(d.value, d.value, q.value, ctx.value);

   if(BN_is_zero(c.value))
      throw Internal_Error("Default_NR_Op::sign: c was zero");

   const u32bit q_bytes = q.bytes();
   SecureVector<byte> output(2*q_bytes);
   c.encode(output, q_bytes);
   d.encode(output + q_bytes, q_bytes);
   return output;
   }

}

/*
* Acquire a NR op
*/
NR_Operation* OpenSSL_Engine::nr_op(const DL_Group& group, const BigInt& y,
                                    const BigInt& x) const
   {
   return new OpenSSL_NR_Op(group, y, x);
   }
#endif

}
