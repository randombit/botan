/*
* OpenSSL Engine
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

#if defined(BOTAN_HAS_ELGAMAL)

namespace {

/*
* OpenSSL ElGamal Operation
*/
class OpenSSL_ELG_Op : public ELG_Operation
   {
   public:
      SecureVector<byte> encrypt(const byte[], u32bit, const BigInt&) const;
      BigInt decrypt(const BigInt&, const BigInt&) const;

      ELG_Operation* clone() const { return new OpenSSL_ELG_Op(*this); }
      OpenSSL_ELG_Op(const DL_Group& group, const BigInt& y1,
                     const BigInt& x1) :
         x(x1), y(y1), g(group.get_g()), p(group.get_p()) {}
   private:
      OSSL_BN x, y, g, p;
      OSSL_BN_CTX ctx;
   };

/*
* OpenSSL ElGamal Encrypt Operation
*/
SecureVector<byte> OpenSSL_ELG_Op::encrypt(const byte in[], u32bit length,
                                           const BigInt& k_bn) const
   {
   OSSL_BN i(in, length);

   if(BN_cmp(i.value, p.value) >= 0)
      throw Invalid_Argument("OpenSSL_ELG_Op: Input is too large");

   OSSL_BN a, b, k(k_bn);

   BN_mod_exp(a.value, g.value, k.value, p.value, ctx.value);
   BN_mod_exp(b.value, y.value, k.value, p.value, ctx.value);
   BN_mod_mul(b.value, b.value, i.value, p.value, ctx.value);

   const u32bit p_bytes = p.bytes();
   SecureVector<byte> output(2*p_bytes);
   a.encode(output, p_bytes);
   b.encode(output + p_bytes, p_bytes);
   return output;
   }

/*
* OpenSSL ElGamal Decrypt Operation
*/
BigInt OpenSSL_ELG_Op::decrypt(const BigInt& a_bn, const BigInt& b_bn) const
   {
   if(BN_is_zero(x.value))
      throw Internal_Error("OpenSSL_ELG_Op::decrypt: No private key");

   OSSL_BN a(a_bn), b(b_bn), t;

   if(BN_cmp(a.value, p.value) >= 0 || BN_cmp(b.value, p.value) >= 0)
      throw Invalid_Argument("OpenSSL_ELG_Op: Invalid message");

   BN_mod_exp(t.value, a.value, x.value, p.value, ctx.value);
   BN_mod_inverse(a.value, t.value, p.value, ctx.value);
   BN_mod_mul(a.value, a.value, b.value, p.value, ctx.value);
   return a.to_bigint();
   }

}

/*
* Acquire an ElGamal op
*/
ELG_Operation* OpenSSL_Engine::elg_op(const DL_Group& group, const BigInt& y,
                                      const BigInt& x) const
   {
   return new OpenSSL_ELG_Op(group, y, x);
   }
#endif

}
