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

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
  #include <openssl/ecdsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
class OSSL_DH_KA_Operation : public PK_Ops::Key_Agreement
   {
   public:
      OSSL_DH_KA_Operation(const DH_PrivateKey& dh) :
         x(dh.get_x()), p(dh.group_p()) {}

      secure_vector<byte> agree(const byte w[], size_t w_len)
         {
         OSSL_BN i(w, w_len), r;
         BN_mod_exp(r.ptr(), i.ptr(), x.ptr(), p.ptr(), ctx.ptr());
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

      secure_vector<byte> sign(const byte msg[], size_t msg_len,
                              RandomNumberGenerator& rng);
   private:
      const OSSL_BN x, p, q, g;
      const OSSL_BN_CTX ctx;
      size_t q_bits;
   };

secure_vector<byte>
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
   BN_mod_exp(r.ptr(), g.ptr(), k.ptr(), p.ptr(), ctx.ptr());
   BN_nnmod(r.ptr(), r.ptr(), q.ptr(), ctx.ptr());

   BN_mod_inverse(k.ptr(), k.ptr(), q.ptr(), ctx.ptr());

   OSSL_BN s;
   BN_mul(s.ptr(), x.ptr(), r.ptr(), ctx.ptr());
   BN_add(s.ptr(), s.ptr(), i.ptr());
   BN_mod_mul(s.ptr(), s.ptr(), k.ptr(), q.ptr(), ctx.ptr());

   if(BN_is_zero(r.ptr()) || BN_is_zero(s.ptr()))
      throw Internal_Error("OpenSSL_DSA_Op::sign: r or s was zero");

   secure_vector<byte> output(2*q_bytes);
   r.encode(&output[0], q_bytes);
   s.encode(&output[q_bytes], q_bytes);
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

   if(BN_is_zero(r.ptr()) || BN_cmp(r.ptr(), q.ptr()) >= 0)
      return false;
   if(BN_is_zero(s.ptr()) || BN_cmp(s.ptr(), q.ptr()) >= 0)
      return false;

   if(BN_mod_inverse(s.ptr(), s.ptr(), q.ptr(), ctx.ptr()) == 0)
      return false;

   OSSL_BN si;
   BN_mod_mul(si.ptr(), s.ptr(), i.ptr(), q.ptr(), ctx.ptr());
   BN_mod_exp(si.ptr(), g.ptr(), si.ptr(), p.ptr(), ctx.ptr());

   OSSL_BN sr;
   BN_mod_mul(sr.ptr(), s.ptr(), r.ptr(), q.ptr(), ctx.ptr());
   BN_mod_exp(sr.ptr(), y.ptr(), sr.ptr(), p.ptr(), ctx.ptr());

   BN_mod_mul(si.ptr(), si.ptr(), sr.ptr(), p.ptr(), ctx.ptr());
   BN_nnmod(si.ptr(), si.ptr(), q.ptr(), ctx.ptr());

   if(BN_cmp(si.ptr(), r.ptr()) == 0)
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

      secure_vector<byte> sign(const byte msg[], size_t msg_len,
                              RandomNumberGenerator&)
         {
         BigInt m(msg, msg_len);
         BigInt x = private_op(m);
         return BigInt::encode_1363(x, (n_bits + 7) / 8);
         }

      secure_vector<byte> decrypt(const byte msg[], size_t msg_len)
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_locked(private_op(m));
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

   BN_mod_exp(j1.ptr(), h.ptr(), d1.ptr(), p.ptr(), ctx.ptr());
   BN_mod_exp(j2.ptr(), h.ptr(), d2.ptr(), q.ptr(), ctx.ptr());
   BN_sub(h.ptr(), j1.ptr(), j2.ptr());
   BN_mod_mul(h.ptr(), h.ptr(), c.ptr(), p.ptr(), ctx.ptr());
   BN_mul(h.ptr(), h.ptr(), q.ptr(), ctx.ptr());
   BN_add(h.ptr(), h.ptr(), j2.ptr());
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

      secure_vector<byte> encrypt(const byte msg[], size_t msg_len,
                                 RandomNumberGenerator&)
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_1363(public_op(m), n.bytes());
         }

      secure_vector<byte> verify_mr(const byte msg[], size_t msg_len)
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_locked(public_op(m));
         }

   private:
      BigInt public_op(const BigInt& m) const
         {
         if(m >= n)
            throw Invalid_Argument("RSA public op - input is too large");

         OSSL_BN m_bn(m), r;
         BN_mod_exp(r.ptr(), m_bn.ptr(), e.ptr(), mod.ptr(), ctx.ptr());
         return r.to_bigint();
         }

      const BigInt& n;
      const OSSL_BN e, mod;
      const OSSL_BN_CTX ctx;
   };

#endif

}

PK_Ops::Key_Agreement*
OpenSSL_Engine::get_key_agreement_op(const Private_Key& key, RandomNumberGenerator&) const
   {
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   if(const DH_PrivateKey* dh = dynamic_cast<const DH_PrivateKey*>(&key))
      return new OSSL_DH_KA_Operation(*dh);
#endif

   return 0;
   }

PK_Ops::Signature*
OpenSSL_Engine::get_signature_op(const Private_Key& key, const std::string&, RandomNumberGenerator&) const
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
OpenSSL_Engine::get_verify_op(const Public_Key& key, const std::string&, RandomNumberGenerator&) const
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
OpenSSL_Engine::get_encryption_op(const Public_Key& key, RandomNumberGenerator&) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PublicKey* s = dynamic_cast<const RSA_PublicKey*>(&key))
      return new OSSL_RSA_Public_Operation(*s);
#endif

   return 0;
   }

PK_Ops::Decryption*
OpenSSL_Engine::get_decryption_op(const Private_Key& key, RandomNumberGenerator&) const
   {
#if defined(BOTAN_HAS_RSA)
   if(const RSA_PrivateKey* s = dynamic_cast<const RSA_PrivateKey*>(&key))
      return new OSSL_RSA_Private_Operation(*s);
#endif

   return 0;
   }

}
