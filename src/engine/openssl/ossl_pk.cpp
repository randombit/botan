/*
* OpenSSL PK operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/openssl_engine.h>
#include <botan/internal/bn_wrap.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>

  #include <openssl/evp.h>

#if !defined(OPENSSL_NO_ECDSA)
  #include <openssl/ecdsa.h>
#endif

#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
class OSSL_DH_KA_Operation : public PK_Ops::Key_Agreement
   {
   public:
      OSSL_DH_KA_Operation(const DH_PrivateKey& dh) :
         x(dh.get_x()), p(dh.group_p()) {}

      SecureVector<byte> agree(const byte w[], size_t w_len)
         {
         OSSL_BN i(w, w_len), r;
         BN_mod_exp(r.value, i.value, x.value, p.value, ctx.value);
         return r.to_bytes();
         }

   private:
      const OSSL_BN x, p;
      OSSL_BN_CTX ctx;
   };
#endif

#if defined(BOTAN_HAS_DSA)

class OSSL_DSA_Signature_Operation : public PK_Ops::Signature
   {
   public:
      OSSL_DSA_Signature_Operation(const DSA_PrivateKey& dsa) :
         x(dsa.get_x()),
         p(dsa.group_p()),
         q(dsa.group_q()),
         g(dsa.group_g()),
         q_bits(dsa.group_q().bits()) {}

      size_t message_parts() const { return 2; }
      size_t message_part_size() const { return (q_bits + 7) / 8; }
      size_t max_input_bits() const { return q_bits; }

      SecureVector<byte> sign(const byte msg[], size_t msg_len,
                              RandomNumberGenerator& rng);
   private:
      const OSSL_BN x, p, q, g;
      const OSSL_BN_CTX ctx;
      size_t q_bits;
   };

SecureVector<byte>
OSSL_DSA_Signature_Operation::sign(const byte msg[], size_t msg_len,
                                  RandomNumberGenerator& rng)
   {
   const size_t q_bytes = (q_bits + 7) / 8;

   rng.add_entropy(msg, msg_len);

   BigInt k_bn;
   do
      k_bn.randomize(rng, q_bits);
   while(k_bn >= q.to_bigint());

   OSSL_BN i(msg, msg_len);
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

   SecureVector<byte> output(2*q_bytes);
   r.encode(output, q_bytes);
   s.encode(output + q_bytes, q_bytes);
   return output;
   }

class OSSL_DSA_Verification_Operation : public PK_Ops::Verification
   {
   public:
      OSSL_DSA_Verification_Operation(const DSA_PublicKey& dsa) :
         y(dsa.get_y()),
         p(dsa.group_p()),
         q(dsa.group_q()),
         g(dsa.group_g()),
         q_bits(dsa.group_q().bits()) {}

      size_t message_parts() const { return 2; }
      size_t message_part_size() const { return (q_bits + 7) / 8; }
      size_t max_input_bits() const { return q_bits; }

      bool with_recovery() const { return false; }

      bool verify(const byte msg[], size_t msg_len,
                  const byte sig[], size_t sig_len);
   private:
      const OSSL_BN y, p, q, g;
      const OSSL_BN_CTX ctx;
      size_t q_bits;
   };

bool OSSL_DSA_Verification_Operation::verify(const byte msg[], size_t msg_len,
                                            const byte sig[], size_t sig_len)
   {
   const size_t q_bytes = q.bytes();

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

   return false;
   }

#endif

#if defined(BOTAN_HAS_RSA)

class OSSL_RSA_Private_Operation : public PK_Ops::Signature,
                                   public PK_Ops::Decryption
   {
   public:
      OSSL_RSA_Private_Operation(const RSA_PrivateKey& rsa) :
         mod(rsa.get_n()),
         p(rsa.get_p()),
         q(rsa.get_q()),
         d1(rsa.get_d1()),
         d2(rsa.get_d2()),
         c(rsa.get_c()),
         n_bits(rsa.get_n().bits())
         {}

      size_t max_input_bits() const { return (n_bits - 1); }

      SecureVector<byte> sign(const byte msg[], size_t msg_len,
                              RandomNumberGenerator&)
         {
         BigInt m(msg, msg_len);
         BigInt x = private_op(m);
         return BigInt::encode_1363(x, (n_bits + 7) / 8);
         }

      SecureVector<byte> decrypt(const byte msg[], size_t msg_len)
         {
         BigInt m(msg, msg_len);
         return BigInt::encode(private_op(m));
         }

   private:
      BigInt private_op(const BigInt& m) const;

      const OSSL_BN mod, p, q, d1, d2, c;
      const OSSL_BN_CTX ctx;
      size_t n_bits;
   };

BigInt OSSL_RSA_Private_Operation::private_op(const BigInt& m) const
   {
   OSSL_BN j1, j2, h(m);

   BN_mod_exp(j1.value, h.value, d1.value, p.value, ctx.value);
   BN_mod_exp(j2.value, h.value, d2.value, q.value, ctx.value);
   BN_sub(h.value, j1.value, j2.value);
   BN_mod_mul(h.value, h.value, c.value, p.value, ctx.value);
   BN_mul(h.value, h.value, q.value, ctx.value);
   BN_add(h.value, h.value, j2.value);
   return h.to_bigint();
   }

class OSSL_RSA_Public_Operation : public PK_Ops::Verification,
                                  public PK_Ops::Encryption
   {
   public:
      OSSL_RSA_Public_Operation(const RSA_PublicKey& rsa) :
         n(rsa.get_n()), e(rsa.get_e()), mod(rsa.get_n())
         {}

      size_t max_input_bits() const { return (n.bits() - 1); }
      bool with_recovery() const { return true; }

      SecureVector<byte> encrypt(const byte msg[], size_t msg_len,
                                 RandomNumberGenerator&)
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_1363(public_op(m), n.bytes());
         }

      SecureVector<byte> verify_mr(const byte msg[], size_t msg_len)
         {
         BigInt m(msg, msg_len);
         return BigInt::encode(public_op(m));
         }

   private:
      BigInt public_op(const BigInt& m) const
         {
         if(m >= n)
            throw Invalid_Argument("RSA public op - input is too large");

         OSSL_BN m_bn(m), r;
         BN_mod_exp(r.value, m_bn.value, e.value, mod.value, ctx.value);
         return r.to_bigint();
         }

      const BigInt& n;
      const OSSL_BN e, mod;
      const OSSL_BN_CTX ctx;
   };

#endif

}

PK_Ops::Key_Agreement*
OpenSSL_Engine::get_key_agreement_op(const Private_Key& key) const
   {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(const DH_PrivateKey* dh = dynamic_cast<const DH_PrivateKey*>(&key))
      return new OSSL_DH_KA_Operation(*dh);
#endif

   return 0;
   }

PK_Ops::Signature*
OpenSSL_Engine::get_signature_op(const Private_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PrivateKey* s = dynamic_cast<const RSA_PrivateKey*>(&key))
      return new OSSL_RSA_Private_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
   if(const DSA_PrivateKey* s = dynamic_cast<const DSA_PrivateKey*>(&key))
      return new OSSL_DSA_Signature_Operation(*s);
#endif

   return 0;
   }

PK_Ops::Verification*
OpenSSL_Engine::get_verify_op(const Public_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PublicKey* s = dynamic_cast<const RSA_PublicKey*>(&key))
      return new OSSL_RSA_Public_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
   if(const DSA_PublicKey* s = dynamic_cast<const DSA_PublicKey*>(&key))
      return new OSSL_DSA_Verification_Operation(*s);
#endif

   return 0;
   }

PK_Ops::Encryption*
OpenSSL_Engine::get_encryption_op(const Public_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PublicKey* s = dynamic_cast<const RSA_PublicKey*>(&key))
      return new OSSL_RSA_Public_Operation(*s);
#endif

   return 0;
   }

PK_Ops::Decryption*
OpenSSL_Engine::get_decryption_op(const Private_Key& key) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PrivateKey* s = dynamic_cast<const RSA_PrivateKey*>(&key))
      return new OSSL_RSA_Private_Operation(*s);
#endif

   return 0;
   }

}
