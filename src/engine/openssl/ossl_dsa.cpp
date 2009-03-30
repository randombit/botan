/*
* OpenSSL DSA Engine
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

#if defined(BOTAN_HAS_DSA)

namespace {

/*
* OpenSSL DSA Operation
*/
class OpenSSL_DSA_Op : public DSA_Operation
   {
   public:
      bool verify(const byte[], u32bit, const byte[], u32bit) const;
      SecureVector<byte> sign(const byte[], u32bit, const BigInt&) const;

      DSA_Operation* clone() const { return new OpenSSL_DSA_Op(*this); }

      OpenSSL_DSA_Op(const DL_Group& group, const BigInt& y1,
                     const BigInt& x1) :
         x(x1), y(y1), p(group.get_p()), q(group.get_q()), g(group.get_g()) {}
   private:
      const OSSL_BN x, y, p, q, g;
      OSSL_BN_CTX ctx;
   };

/*
* OpenSSL DSA Verify Operation
*/
bool OpenSSL_DSA_Op::verify(const byte msg[], u32bit msg_len,
                            const byte sig[], u32bit sig_len) const
   {
   const u32bit q_bytes = q.bytes();

   if(sig_len != 2*q_bytes || msg_len > q_bytes)
      return false;

   OSSL_BN r(sig, q_bytes);
   OSSL_BN s(sig + q_bytes, q_bytes);
   OSSL_BN i(msg, msg_len);

   if(BN_is_zero(r.value) || BN_cmp(r.value, q.value) >= 0)
      return false;
   if(BN_is_zero(s.value) || BN_cmp(s.value, q.value) >= 0)
      return false;

   if(BN_mod_inverse(s.value, s.value, q.value, ctx.value) == 0)
      return false;

   OSSL_BN si;
   BN_mod_mul(si.value, s.value, i.value, q.value, ctx.value);
   BN_mod_exp(si.value, g.value, si.value, p.value, ctx.value);

   OSSL_BN sr;
   BN_mod_mul(sr.value, s.value, r.value, q.value, ctx.value);
   BN_mod_exp(sr.value, y.value, sr.value, p.value, ctx.value);

   BN_mod_mul(si.value, si.value, sr.value, p.value, ctx.value);
   BN_nnmod(si.value, si.value, q.value, ctx.value);

   if(BN_cmp(si.value, r.value) == 0)
      return true;
   return false;
   }

/*
* OpenSSL DSA Sign Operation
*/
SecureVector<byte> OpenSSL_DSA_Op::sign(const byte in[], u32bit length,
                                        const BigInt& k_bn) const
   {
   if(BN_is_zero(x.value))
      throw Internal_Error("OpenSSL_DSA_Op::sign: No private key");

   OSSL_BN i(in, length);
   OSSL_BN k(k_bn);

   OSSL_BN r;
   BN_mod_exp(r.value, g.value, k.value, p.value, ctx.value);
   BN_nnmod(r.value, r.value, q.value, ctx.value);

   BN_mod_inverse(k.value, k.value, q.value, ctx.value);

   OSSL_BN s;
   BN_mul(s.value, x.value, r.value, ctx.value);
   BN_add(s.value, s.value, i.value);
   BN_mod_mul(s.value, s.value, k.value, q.value, ctx.value);

   if(BN_is_zero(r.value) || BN_is_zero(s.value))
      throw Internal_Error("OpenSSL_DSA_Op::sign: r or s was zero");

   const u32bit q_bytes = q.bytes();

   SecureVector<byte> output(2*q_bytes);
   r.encode(output, q_bytes);
   s.encode(output + q_bytes, q_bytes);
   return output;
   }

}

/*
* Acquire a DSA op
*/
DSA_Operation* OpenSSL_Engine::dsa_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new OpenSSL_DSA_Op(group, y, x);
   }
#endif

}
