/*
* RSA
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/rsa.h>
#include <botan/parsing.h>
#include <botan/keypair.h>
#include <botan/blinding.h>
#include <botan/reducer.h>
#include <future>

namespace Botan {

/*
* Create a RSA private key
*/
RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng,
                               size_t bits, size_t exp)
   {
   if(bits < 1024)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             std::to_string(bits) + " bits long");
   if(exp < 3 || exp % 2 == 0)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   m_e = exp;

   do
      {
      m_p = random_prime(rng, (bits + 1) / 2, m_e);
      m_q = random_prime(rng, bits - m_p.bits(), m_e);
      m_n = m_p * m_q;
      } while(m_n.bits() != bits);

   m_d = inverse_mod(m_e, lcm(m_p - 1, m_q - 1));
   m_d1 = m_d % (m_p - 1);
   m_d2 = m_d % (m_q - 1);
   m_c = inverse_mod(m_q, m_p);

   gen_check(rng);
   }

/*
* Check Private RSA Parameters
*/
bool RSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!IF_Scheme_PrivateKey::check_key(rng, strong))
      return false;

   if(!strong)
      return true;

   if((m_e * m_d) % lcm(m_p - 1, m_q - 1) != 1)
      return false;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA4(SHA-256)");
   }

namespace {

/**
* RSA private (decrypt/sign) operation
*/
class RSA_Private_Operation
   {
   protected:
      size_t get_max_input_bits() const { return (m_n.bits() - 1); }

      explicit RSA_Private_Operation(const RSA_PrivateKey& rsa) :
         m_n(rsa.get_n()),
         m_q(rsa.get_q()),
         m_c(rsa.get_c()),
         m_powermod_e_n(rsa.get_e(), rsa.get_n()),
         m_powermod_d1_p(rsa.get_d1(), rsa.get_p()),
         m_powermod_d2_q(rsa.get_d2(), rsa.get_q()),
         m_mod_p(rsa.get_p()),
         m_blinder(m_n,
                   [this](const BigInt& k) { return m_powermod_e_n(k); },
                   [this](const BigInt& k) { return inverse_mod(k, m_n); })
         {
         }

      BigInt blinded_private_op(const BigInt& m) const
         {
         if(m >= m_n)
            throw Invalid_Argument("RSA private op - input is too large");

         return m_blinder.unblind(private_op(m_blinder.blind(m)));
         }

      BigInt private_op(const BigInt& m) const
         {
         auto future_j1 = std::async(std::launch::async, m_powermod_d1_p, m);
         BigInt j2 = m_powermod_d2_q(m);
         BigInt j1 = future_j1.get();

         j1 = m_mod_p.reduce(sub_mul(j1, j2, m_c));

         return mul_add(j1, m_q, j2);
         }

      const BigInt& m_n;
      const BigInt& m_q;
      const BigInt& m_c;
      Fixed_Exponent_Power_Mod m_powermod_e_n, m_powermod_d1_p, m_powermod_d2_q;
      Modular_Reducer m_mod_p;
      Blinder m_blinder;
   };

class RSA_Signature_Operation : public PK_Ops::Signature_with_EMSA,
                                private RSA_Private_Operation
   {
   public:
      typedef RSA_PrivateKey Key_Type;

      size_t max_input_bits() const override { return get_max_input_bits(); };

      RSA_Signature_Operation(const RSA_PrivateKey& rsa, const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         RSA_Private_Operation(rsa)
         {
         }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator&) override
         {
         const BigInt m(msg, msg_len);
         const BigInt x = blinded_private_op(m);
         const BigInt c = m_powermod_e_n(x);
         BOTAN_ASSERT(m == c, "RSA sign consistency check");
         return BigInt::encode_1363(x, m_n.bytes());
         }
   };

class RSA_Decryption_Operation : public PK_Ops::Decryption_with_EME,
                                 private RSA_Private_Operation
   {
   public:
      typedef RSA_PrivateKey Key_Type;

      size_t max_raw_input_bits() const override { return get_max_input_bits(); };

      RSA_Decryption_Operation(const RSA_PrivateKey& rsa, const std::string& eme) :
         PK_Ops::Decryption_with_EME(eme),
         RSA_Private_Operation(rsa)
         {
         }

      secure_vector<byte> raw_decrypt(const byte msg[], size_t msg_len) override
         {
         const BigInt m(msg, msg_len);
         const BigInt x = blinded_private_op(m);
         const BigInt c = m_powermod_e_n(x);
         BOTAN_ASSERT(m == c, "RSA decrypt consistency check");
         return BigInt::encode_1363(x, m_n.bytes());
         }
   };

class RSA_KEM_Decryption_Operation : public PK_Ops::KEM_Decryption_with_KDF,
                                     private RSA_Private_Operation
   {
   public:
      typedef RSA_PrivateKey Key_Type;

      RSA_KEM_Decryption_Operation(const RSA_PrivateKey& key,
                                   const std::string& kdf) :
         PK_Ops::KEM_Decryption_with_KDF(kdf),
         RSA_Private_Operation(key)
         {}

      secure_vector<byte>
      raw_kem_decrypt(const byte encap_key[], size_t len) override
         {
         const BigInt m(encap_key, len);
         const BigInt x = blinded_private_op(m);
         const BigInt c = m_powermod_e_n(x);
         BOTAN_ASSERT(m == c, "RSA KEM consistency check");
         return BigInt::encode_1363(x, m_n.bytes());
         }
   };

/**
* RSA public (encrypt/verify) operation
*/
class RSA_Public_Operation
   {
   public:
      explicit RSA_Public_Operation(const RSA_PublicKey& rsa) :
         m_n(rsa.get_n()), m_powermod_e_n(rsa.get_e(), rsa.get_n())
         {}

      size_t get_max_input_bits() const { return (m_n.bits() - 1); }

   protected:
      BigInt public_op(const BigInt& m) const
         {
         if(m >= m_n)
            throw Invalid_Argument("RSA public op - input is too large");
         return m_powermod_e_n(m);
         }

      const BigInt& get_n() const { return m_n; }

      const BigInt& m_n;
      Fixed_Exponent_Power_Mod m_powermod_e_n;
   };

class RSA_Encryption_Operation : public PK_Ops::Encryption_with_EME,
                                 private RSA_Public_Operation
   {
   public:
      typedef RSA_PublicKey Key_Type;

      RSA_Encryption_Operation(const RSA_PublicKey& rsa, const std::string& eme) :
         PK_Ops::Encryption_with_EME(eme),
         RSA_Public_Operation(rsa)
         {
         }

      size_t max_raw_input_bits() const override { return get_max_input_bits(); };

      secure_vector<byte> raw_encrypt(const byte msg[], size_t msg_len,
                                      RandomNumberGenerator&) override
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_1363(public_op(m), m_n.bytes());
         }
   };

class RSA_Verify_Operation : public PK_Ops::Verification_with_EMSA,
                             private RSA_Public_Operation
   {
   public:
      typedef RSA_PublicKey Key_Type;

      size_t max_input_bits() const override { return get_max_input_bits(); };

      RSA_Verify_Operation(const RSA_PublicKey& rsa, const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         RSA_Public_Operation(rsa)
         {
         }

      bool with_recovery() const override { return true; }

      secure_vector<byte> verify_mr(const byte msg[], size_t msg_len) override
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_locked(public_op(m));
         }
   };

class RSA_KEM_Encryption_Operation : public PK_Ops::KEM_Encryption_with_KDF,
                                     private RSA_Public_Operation
   {
   public:
      typedef RSA_PublicKey Key_Type;

      RSA_KEM_Encryption_Operation(const RSA_PublicKey& key,
                                   const std::string& kdf) :
         PK_Ops::KEM_Encryption_with_KDF(kdf),
         RSA_Public_Operation(key) {}

   private:
      void raw_kem_encrypt(secure_vector<byte>& out_encapsulated_key,
                           secure_vector<byte>& raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override
         {
         const BigInt r = BigInt::random_integer(rng, 1, get_n());
         const BigInt c = public_op(r);

         out_encapsulated_key = BigInt::encode_locked(c);
         raw_shared_key = BigInt::encode_locked(r);
         }
   };


BOTAN_REGISTER_PK_ENCRYPTION_OP("RSA", RSA_Encryption_Operation);
BOTAN_REGISTER_PK_DECRYPTION_OP("RSA", RSA_Decryption_Operation);

BOTAN_REGISTER_PK_SIGNATURE_OP("RSA", RSA_Signature_Operation);
BOTAN_REGISTER_PK_VERIFY_OP("RSA", RSA_Verify_Operation);

BOTAN_REGISTER_PK_KEM_ENCRYPTION_OP("RSA", RSA_KEM_Encryption_Operation);
BOTAN_REGISTER_PK_KEM_DECRYPTION_OP("RSA", RSA_KEM_Decryption_Operation);

}

}
