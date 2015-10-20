/*
* RSA
* (C) 1999-2010 Jack Lloyd
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

   e = exp;

   do
      {
      p = random_prime(rng, (bits + 1) / 2, e);
      q = random_prime(rng, bits - p.bits(), e);
      n = p * q;
      } while(n.bits() != bits);

   d = inverse_mod(e, lcm(p - 1, q - 1));
   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

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

   if((e * d) % lcm(p - 1, q - 1) != 1)
      return false;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA4(SHA-1)");
   }

namespace {

/**
* RSA private (decrypt/sign) operation
*/
class RSA_Private_Operation
   {
   protected:
      size_t get_max_input_bits() const { return (n.bits() - 1); }

      RSA_Private_Operation(const RSA_PrivateKey& rsa) :
         n(rsa.get_n()),
         q(rsa.get_q()),
         c(rsa.get_c()),
         m_powermod_e_n(rsa.get_e(), rsa.get_n()),
         m_powermod_d1_p(rsa.get_d1(), rsa.get_p()),
         m_powermod_d2_q(rsa.get_d2(), rsa.get_q()),
         m_mod_p(rsa.get_p()),
         m_blinder(n,
                   [this](const BigInt& k) { return m_powermod_e_n(k); },
                   [this](const BigInt& k) { return inverse_mod(k, n); })
         {
         }

      BigInt blinded_private_op(const BigInt& m) const
         {
         if(m >= n)
            throw Invalid_Argument("RSA private op - input is too large");

         return m_blinder.unblind(private_op(m_blinder.blind(m)));
         }

      BigInt private_op(const BigInt& m) const
         {
         auto future_j1 = std::async(std::launch::async, m_powermod_d1_p, m);
         BigInt j2 = m_powermod_d2_q(m);
         BigInt j1 = future_j1.get();

         j1 = m_mod_p.reduce(sub_mul(j1, j2, c));

         return mul_add(j1, q, j2);
         }

      const BigInt& n;
      const BigInt& q;
      const BigInt& c;
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
         return BigInt::encode_1363(x, n.bytes());
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
         BOTAN_ASSERT(m == c, "RSA sign consistency check");
         return BigInt::encode_locked(x);
         }
   };

/**
* RSA public (encrypt/verify) operation
*/
class RSA_Public_Operation
   {
   public:
      RSA_Public_Operation(const RSA_PublicKey& rsa) :
         n(rsa.get_n()), powermod_e_n(rsa.get_e(), rsa.get_n())
         {}

      size_t get_max_input_bits() const { return (n.bits() - 1); }

   protected:
      BigInt public_op(const BigInt& m) const
         {
         if(m >= n)
            throw Invalid_Argument("RSA public op - input is too large");
         return powermod_e_n(m);
         }

      const BigInt& n;
      Fixed_Exponent_Power_Mod powermod_e_n;
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
         return BigInt::encode_1363(public_op(m), n.bytes());
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

BOTAN_REGISTER_PK_ENCRYPTION_OP("RSA", RSA_Encryption_Operation);
BOTAN_REGISTER_PK_DECRYPTION_OP("RSA", RSA_Decryption_Operation);
BOTAN_REGISTER_PK_SIGNATURE_OP("RSA", RSA_Signature_Operation);
BOTAN_REGISTER_PK_VERIFY_OP("RSA", RSA_Verify_Operation);

}

}
