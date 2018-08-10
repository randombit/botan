/*
* RSA
* (C) 1999-2010,2015,2016,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rsa.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/keypair.h>
#include <botan/blinding.h>
#include <botan/reducer.h>
#include <botan/workfactor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pow_mod.h>
#include <botan/monty.h>
#include <botan/internal/monty_exp.h>

#if defined(BOTAN_HAS_OPENSSL)
  #include <botan/internal/openssl.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
  #include <future>
#endif

namespace Botan {

size_t RSA_PublicKey::key_length() const
   {
   return m_n.bits();
   }

size_t RSA_PublicKey::estimated_strength() const
   {
   return if_work_factor(key_length());
   }

AlgorithmIdentifier RSA_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(),
                              AlgorithmIdentifier::USE_NULL_PARAM);
   }

std::vector<uint8_t> RSA_PublicKey::public_key_bits() const
   {
   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_cons(SEQUENCE)
         .encode(m_n)
         .encode(m_e)
      .end_cons();

   return output;
   }

RSA_PublicKey::RSA_PublicKey(const AlgorithmIdentifier&,
                             const std::vector<uint8_t>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
        .decode(m_n)
        .decode(m_e)
      .end_cons();
   }

/*
* Check RSA Public Parameters
*/
bool RSA_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   if(m_n < 35 || m_n.is_even() || m_e < 3 || m_e.is_even())
      return false;
   return true;
   }

secure_vector<uint8_t> RSA_PrivateKey::private_key_bits() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(0))
         .encode(m_n)
         .encode(m_e)
         .encode(m_d)
         .encode(m_p)
         .encode(m_q)
         .encode(m_d1)
         .encode(m_d2)
         .encode(m_c)
      .end_cons()
   .get_contents();
   }

RSA_PrivateKey::RSA_PrivateKey(const AlgorithmIdentifier&,
                               const secure_vector<uint8_t>& key_bits)
   {
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode_and_check<size_t>(0, "Unknown PKCS #1 key format version")
         .decode(m_n)
         .decode(m_e)
         .decode(m_d)
         .decode(m_p)
         .decode(m_q)
         .decode(m_d1)
         .decode(m_d2)
         .decode(m_c)
      .end_cons();
   }

RSA_PrivateKey::RSA_PrivateKey(const BigInt& prime1,
                               const BigInt& prime2,
                               const BigInt& exp,
                               const BigInt& d_exp,
                               const BigInt& mod) :
   m_d{ d_exp }, m_p{ prime1 }, m_q{ prime2 }, m_d1{}, m_d2{}, m_c{ inverse_mod( m_q, m_p ) }
   {
   m_n = mod.is_nonzero() ? mod : m_p * m_q;
   m_e = exp;

   if(m_d == 0)
      {
      const BigInt phi_n = lcm(m_p - 1, m_q - 1);
      m_d = inverse_mod(m_e, phi_n);
      }

   m_d1 = m_d % (m_p - 1);
   m_d2 = m_d % (m_q - 1);
   }

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

   const size_t p_bits = (bits + 1) / 2;
   const size_t q_bits = bits - p_bits;

   do
      {
      m_p = generate_rsa_prime(rng, rng, p_bits, m_e);
      m_q = generate_rsa_prime(rng, rng, q_bits, m_e);
      m_n = m_p * m_q;
      } while(m_n.bits() != bits);

   // FIXME: lcm calls gcd which is not const time
   const BigInt phi_n = lcm(m_p - 1, m_q - 1);
   // FIXME: this uses binary ext gcd because phi_n is even
   m_d = inverse_mod(m_e, phi_n);
   m_d1 = m_d % (m_p - 1);
   m_d2 = m_d % (m_q - 1);
   m_c = inverse_mod(m_q, m_p);
   }

/*
* Check Private RSA Parameters
*/
bool RSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(m_n < 35 || m_n.is_even() || m_e < 3 || m_e.is_even())
      return false;

   if(m_d < 2 || m_p < 3 || m_q < 3 || m_p*m_q != m_n)
      return false;

   if(m_d1 != m_d % (m_p - 1) || m_d2 != m_d % (m_q - 1) || m_c != inverse_mod(m_q, m_p))
      return false;

   const size_t prob = (strong) ? 128 : 12;

   if(!is_prime(m_p, rng, prob) || !is_prime(m_q, rng, prob))
      return false;

   if(strong)
      {
      if((m_e * m_d) % lcm(m_p - 1, m_q - 1) != 1)
         return false;

      return KeyPair::signature_consistency_check(rng, *this, "EMSA4(SHA-256)");
      }

   return true;
   }

namespace {

/**
* RSA private (decrypt/sign) operation
*/
class RSA_Private_Operation
   {
   protected:
      size_t get_max_input_bits() const { return (m_mod_bits - 1); }

      const size_t exp_blinding_bits = 64;

      explicit RSA_Private_Operation(const RSA_PrivateKey& rsa, RandomNumberGenerator& rng) :
         m_key(rsa),
         m_mod_p(m_key.get_p()),
         m_mod_q(m_key.get_q()),
         m_monty_p(std::make_shared<Montgomery_Params>(m_key.get_p(), m_mod_p)),
         m_monty_q(std::make_shared<Montgomery_Params>(m_key.get_q(), m_mod_q)),
         m_powermod_e_n(m_key.get_e(), m_key.get_n()),
         m_blinder(m_key.get_n(),
                   rng,
                   [this](const BigInt& k) { return m_powermod_e_n(k); },
                   [this](const BigInt& k) { return inverse_mod(k, m_key.get_n()); }),
         m_blinding_bits(64),
         m_mod_bytes(m_key.get_n().bytes()),
         m_mod_bits(m_key.get_n().bits()),
         m_max_d1_bits(m_key.get_p().bits() + m_blinding_bits),
         m_max_d2_bits(m_key.get_q().bits() + m_blinding_bits)
         {
         }

      BigInt blinded_private_op(const BigInt& m) const
         {
         if(m >= m_key.get_n())
            throw Invalid_Argument("RSA private op - input is too large");

         return m_blinder.unblind(private_op(m_blinder.blind(m)));
         }

      BigInt private_op(const BigInt& m) const
         {
         const size_t powm_window = 4;

         const BigInt d1_mask(m_blinder.rng(), m_blinding_bits);

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
         auto future_j1 = std::async(std::launch::async, [this, &m, &d1_mask, powm_window]() {
               const BigInt masked_d1 = m_key.get_d1() + (d1_mask * (m_key.get_p() - 1));
               auto powm_d1_p = monty_precompute(m_monty_p, m, powm_window);
               return monty_execute(*powm_d1_p, masked_d1, m_max_d1_bits);
            });
#else
         const BigInt masked_d1 = m_key.get_d1() + (d1_mask * (m_key.get_p() - 1));
         auto powm_d1_p = monty_precompute(m_monty_p, m, powm_window);
         BigInt j1 = monty_execute(*powm_d1_p, masked_d1, m_max_d1_bits);
#endif

         const BigInt d2_mask(m_blinder.rng(), m_blinding_bits);
         const BigInt masked_d2 = m_key.get_d2() + (d2_mask * (m_key.get_q() - 1));
         auto powm_d2_q = monty_precompute(m_monty_q, m, powm_window);
         const BigInt j2 = monty_execute(*powm_d2_q, masked_d2, m_max_d2_bits);

         /*
         * To recover the final value from the CRT representation (j1,j2)
         * we use Garner's algorithm:
         * c = q^-1 mod p (this is precomputed)
         * h = c*(j1-j2) mod p
         * m = j2 + h*q
         */

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
         BigInt j1 = future_j1.get();
#endif

         /*
         To prevent a side channel that allows detecting case where j1 < j2,
         add p to j1 before reducing [computing c*(p+j1-j2) mod p]
         */
         j1 = m_mod_p.reduce(sub_mul(m_key.get_p() + j1, j2, m_key.get_c()));
         return mul_add(j1, m_key.get_q(), j2);
         }

      const RSA_PrivateKey& m_key;

      // TODO these could all be computed once and stored in the key object
      Modular_Reducer m_mod_p;
      Modular_Reducer m_mod_q;
      std::shared_ptr<const Montgomery_Params> m_monty_p;
      std::shared_ptr<const Montgomery_Params> m_monty_q;

      Fixed_Exponent_Power_Mod m_powermod_e_n;
      Blinder m_blinder;
      const size_t m_blinding_bits;
      const size_t m_mod_bytes;
      const size_t m_mod_bits;
      const size_t m_max_d1_bits;
      const size_t m_max_d2_bits;
   };

class RSA_Signature_Operation final : public PK_Ops::Signature_with_EMSA,
                                private RSA_Private_Operation
   {
   public:

      size_t max_input_bits() const override { return get_max_input_bits(); }

      size_t signature_length() const override { return m_key.get_n().bytes(); }

      RSA_Signature_Operation(const RSA_PrivateKey& rsa, const std::string& emsa, RandomNumberGenerator& rng) :
         PK_Ops::Signature_with_EMSA(emsa),
         RSA_Private_Operation(rsa, rng)
         {
         }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                   RandomNumberGenerator&) override
         {
         const BigInt m(msg, msg_len);
         const BigInt x = blinded_private_op(m);
         const BigInt c = m_powermod_e_n(x);
         BOTAN_ASSERT(m == c, "RSA sign consistency check");
         return BigInt::encode_1363(x, m_mod_bytes);
         }
   };

class RSA_Decryption_Operation final : public PK_Ops::Decryption_with_EME,
                                 private RSA_Private_Operation
   {
   public:

      RSA_Decryption_Operation(const RSA_PrivateKey& rsa, const std::string& eme, RandomNumberGenerator& rng) :
         PK_Ops::Decryption_with_EME(eme),
         RSA_Private_Operation(rsa, rng)
         {
         }

      size_t plaintext_length(size_t) const override { return m_mod_bytes; }

      secure_vector<uint8_t> raw_decrypt(const uint8_t msg[], size_t msg_len) override
         {
         const BigInt m(msg, msg_len);
         const BigInt x = blinded_private_op(m);
         const BigInt c = m_powermod_e_n(x);
         BOTAN_ASSERT(m == c, "RSA decrypt consistency check");
         return BigInt::encode_1363(x, m_mod_bytes);
         }
   };

class RSA_KEM_Decryption_Operation final : public PK_Ops::KEM_Decryption_with_KDF,
                                     private RSA_Private_Operation
   {
   public:

      RSA_KEM_Decryption_Operation(const RSA_PrivateKey& key,
                                   const std::string& kdf,
                                   RandomNumberGenerator& rng) :
         PK_Ops::KEM_Decryption_with_KDF(kdf),
         RSA_Private_Operation(key, rng)
         {}

      secure_vector<uint8_t>
      raw_kem_decrypt(const uint8_t encap_key[], size_t len) override
         {
         const BigInt m(encap_key, len);
         const BigInt x = blinded_private_op(m);
         const BigInt c = m_powermod_e_n(x);
         BOTAN_ASSERT(m == c, "RSA KEM consistency check");
         return BigInt::encode_1363(x, m_mod_bytes);
         }
   };

/**
* RSA public (encrypt/verify) operation
*/
class RSA_Public_Operation
   {
   public:
      explicit RSA_Public_Operation(const RSA_PublicKey& rsa) :
         m_n(rsa.get_n()),
         m_e(rsa.get_e()),
         m_monty_n(std::make_shared<Montgomery_Params>(m_n))
         {}

      size_t get_max_input_bits() const { return (m_n.bits() - 1); }

   protected:
      BigInt public_op(const BigInt& m) const
         {
         if(m >= m_n)
            throw Invalid_Argument("RSA public op - input is too large");

         const size_t powm_window = 1;

         auto powm_m_n = monty_precompute(m_monty_n, m, powm_window, false);
         return monty_execute_vartime(*powm_m_n, m_e);
         }

      const BigInt& get_n() const { return m_n; }

      const BigInt& m_n;
      const BigInt& m_e;
      std::shared_ptr<Montgomery_Params> m_monty_n;
   };

class RSA_Encryption_Operation final : public PK_Ops::Encryption_with_EME,
                                       private RSA_Public_Operation
   {
   public:

      RSA_Encryption_Operation(const RSA_PublicKey& rsa, const std::string& eme) :
         PK_Ops::Encryption_with_EME(eme),
         RSA_Public_Operation(rsa)
         {
         }

      size_t ciphertext_length(size_t) const override { return m_n.bytes(); }

      size_t max_raw_input_bits() const override { return get_max_input_bits(); }

      secure_vector<uint8_t> raw_encrypt(const uint8_t msg[], size_t msg_len,
                                         RandomNumberGenerator&) override
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_1363(public_op(m), m_n.bytes());
         }
   };

class RSA_Verify_Operation final : public PK_Ops::Verification_with_EMSA,
                                   private RSA_Public_Operation
   {
   public:

      size_t max_input_bits() const override { return get_max_input_bits(); }

      RSA_Verify_Operation(const RSA_PublicKey& rsa, const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         RSA_Public_Operation(rsa)
         {
         }

      bool with_recovery() const override { return true; }

      secure_vector<uint8_t> verify_mr(const uint8_t msg[], size_t msg_len) override
         {
         BigInt m(msg, msg_len);
         return BigInt::encode_locked(public_op(m));
         }
   };

class RSA_KEM_Encryption_Operation final : public PK_Ops::KEM_Encryption_with_KDF,
                                           private RSA_Public_Operation
   {
   public:

      RSA_KEM_Encryption_Operation(const RSA_PublicKey& key,
                                   const std::string& kdf) :
         PK_Ops::KEM_Encryption_with_KDF(kdf),
         RSA_Public_Operation(key) {}

   private:
      void raw_kem_encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                           secure_vector<uint8_t>& raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override
         {
         const BigInt r = BigInt::random_integer(rng, 1, get_n());
         const BigInt c = public_op(r);

         out_encapsulated_key = BigInt::encode_locked(c);
         raw_shared_key = BigInt::encode_locked(r);
         }
   };

}

std::unique_ptr<PK_Ops::Encryption>
RSA_PublicKey::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                    const std::string& params,
                                    const std::string& provider) const
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider == "openssl" || provider.empty())
      {
      try
         {
         return make_openssl_rsa_enc_op(*this, params);
         }
      catch(Exception& e)
         {
         /*
         * If OpenSSL for some reason could not handle this (eg due to OAEP params),
         * throw if openssl was specifically requested but otherwise just fall back
         * to the normal version.
         */
         if(provider == "openssl")
            throw Lookup_Error("OpenSSL RSA provider rejected key:" + std::string(e.what()));
         }
      }
#endif

   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Encryption>(new RSA_Encryption_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::KEM_Encryption>
RSA_PublicKey::create_kem_encryption_op(RandomNumberGenerator& /*rng*/,
                                        const std::string& params,
                                        const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::KEM_Encryption>(new RSA_KEM_Encryption_Operation(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Verification>
RSA_PublicKey::create_verification_op(const std::string& params,
                                      const std::string& provider) const
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider == "openssl" || provider.empty())
      {
      std::unique_ptr<PK_Ops::Verification> res = make_openssl_rsa_ver_op(*this, params);
      if(res)
         return res;
      }
#endif

   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Verification>(new RSA_Verify_Operation(*this, params));

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Decryption>
RSA_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                     const std::string& params,
                                     const std::string& provider) const
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider == "openssl" || provider.empty())
      {
      try
         {
         return make_openssl_rsa_dec_op(*this, params);
         }
      catch(Exception& e)
         {
         if(provider == "openssl")
            throw Lookup_Error("OpenSSL RSA provider rejected key:" + std::string(e.what()));
         }
      }
#endif

   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Decryption>(new RSA_Decryption_Operation(*this, params, rng));

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::KEM_Decryption>
RSA_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& rng,
                                         const std::string& params,
                                         const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::KEM_Decryption>(new RSA_KEM_Decryption_Operation(*this, params, rng));

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
RSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                    const std::string& params,
                                    const std::string& provider) const
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider == "openssl" || provider.empty())
      {
      std::unique_ptr<PK_Ops::Signature> res = make_openssl_rsa_sig_op(*this, params);
      if(res)
         return res;
      }
#endif

   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(new RSA_Signature_Operation(*this, params, rng));

   throw Provider_Not_Found(algo_name(), provider);
   }

}
