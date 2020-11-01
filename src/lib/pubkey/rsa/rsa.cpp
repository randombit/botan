/*
* RSA
* (C) 1999-2010,2015,2016,2018,2019 Jack Lloyd
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
#include <botan/monty.h>
#include <botan/divide.h>
#include <botan/internal/monty_exp.h>

#if defined(BOTAN_HAS_OPENSSL)
  #include <botan/internal/openssl.h>
#endif

#if defined(BOTAN_HAS_THREAD_UTILS)
  #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

class RSA_Public_Data final
   {
   public:
      RSA_Public_Data(BigInt&& n, BigInt&& e) :
         m_n(n),
         m_e(e),
         m_monty_n(std::make_shared<Montgomery_Params>(m_n)),
         m_public_modulus_bits(m_n.bits()),
         m_public_modulus_bytes(m_n.bytes())
         {}

      BigInt public_op(const BigInt& m) const
         {
         const size_t powm_window = 1;
         auto powm_m_n = monty_precompute(m_monty_n, m, powm_window, false);
         return monty_execute_vartime(*powm_m_n, m_e);
         }

      const BigInt& get_n() const { return m_n; }
      const BigInt& get_e() const { return m_e; }
      size_t public_modulus_bits() const { return m_public_modulus_bits; }
      size_t public_modulus_bytes() const { return m_public_modulus_bytes; }

   private:
      BigInt m_n;
      BigInt m_e;
      std::shared_ptr<const Montgomery_Params> m_monty_n;
      size_t m_public_modulus_bits;
      size_t m_public_modulus_bytes;
   };

class RSA_Private_Data final
   {
   public:
      RSA_Private_Data(BigInt&& d, BigInt&& p, BigInt&& q,
                       BigInt&& d1, BigInt&& d2, BigInt&& c) :
         m_d(d),
         m_p(p),
         m_q(q),
         m_d1(d1),
         m_d2(d2),
         m_c(c),
         m_mod_p(m_p),
         m_mod_q(m_q),
         m_monty_p(std::make_shared<Montgomery_Params>(m_p, m_mod_p)),
         m_monty_q(std::make_shared<Montgomery_Params>(m_q, m_mod_q)),
         m_p_bits(m_p.bits()),
         m_q_bits(m_q.bits())
         {}

      const BigInt& get_d() const { return m_d; }
      const BigInt& get_p() const { return m_p; }
      const BigInt& get_q() const { return m_q; }
      const BigInt& get_d1() const { return m_d1; }
      const BigInt& get_d2() const { return m_d2; }
      const BigInt& get_c() const { return m_c; }

   //private:
      BigInt m_d;
      BigInt m_p;
      BigInt m_q;
      BigInt m_d1;
      BigInt m_d2;
      BigInt m_c;

      Modular_Reducer m_mod_p;
      Modular_Reducer m_mod_q;
      std::shared_ptr<const Montgomery_Params> m_monty_p;
      std::shared_ptr<const Montgomery_Params> m_monty_q;
      size_t m_p_bits;
      size_t m_q_bits;
   };

std::shared_ptr<const RSA_Public_Data> RSA_PublicKey::public_data() const
   {
   return m_public;
   }

const BigInt& RSA_PublicKey::get_n() const { return m_public->get_n(); }
const BigInt& RSA_PublicKey::get_e() const { return m_public->get_e(); }

void RSA_PublicKey::init(BigInt&& n, BigInt&& e)
   {
   if(n.is_negative() || n.is_even() || e.is_negative() || e.is_even())
      throw Decoding_Error("Invalid RSA public key parameters");
   m_public = std::make_shared<RSA_Public_Data>(std::move(n), std::move(e));
   }

RSA_PublicKey::RSA_PublicKey(const AlgorithmIdentifier&,
                             const std::vector<uint8_t>& key_bits)
   {
   BigInt n, e;
   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
      .decode(n)
      .decode(e)
      .end_cons();

   init(std::move(n), std::move(e));
   }

RSA_PublicKey::RSA_PublicKey(const BigInt& modulus, const BigInt& exponent)
   {
   BigInt n = modulus;
   BigInt e = exponent;
   init(std::move(n), std::move(e));
   }

size_t RSA_PublicKey::key_length() const
   {
   return m_public->public_modulus_bits();
   }

size_t RSA_PublicKey::estimated_strength() const
   {
   return if_work_factor(key_length());
   }

AlgorithmIdentifier RSA_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(), AlgorithmIdentifier::USE_NULL_PARAM);
   }

std::vector<uint8_t> RSA_PublicKey::public_key_bits() const
   {
   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_cons(SEQUENCE)
         .encode(get_n())
         .encode(get_e())
      .end_cons();

   return output;
   }

/*
* Check RSA Public Parameters
*/
bool RSA_PublicKey::check_key(RandomNumberGenerator&, bool) const
   {
   if(get_n() < 35 || get_n().is_even() || get_e() < 3 || get_e().is_even())
      return false;
   return true;
   }

std::shared_ptr<const RSA_Private_Data> RSA_PrivateKey::private_data() const
   {
   return m_private;
   }

secure_vector<uint8_t> RSA_PrivateKey::private_key_bits() const
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(0))
         .encode(get_n())
         .encode(get_e())
         .encode(get_d())
         .encode(get_p())
         .encode(get_q())
         .encode(get_d1())
         .encode(get_d2())
         .encode(get_c())
      .end_cons()
   .get_contents();
   }

const BigInt& RSA_PrivateKey::get_p() const { return m_private->get_p(); }
const BigInt& RSA_PrivateKey::get_q() const { return m_private->get_q(); }
const BigInt& RSA_PrivateKey::get_d() const { return m_private->get_d(); }
const BigInt& RSA_PrivateKey::get_c() const { return m_private->get_c(); }
const BigInt& RSA_PrivateKey::get_d1() const { return m_private->get_d1(); }
const BigInt& RSA_PrivateKey::get_d2() const { return m_private->get_d2(); }

void RSA_PrivateKey::init(BigInt&& d, BigInt&& p, BigInt&& q,
                          BigInt&& d1, BigInt&& d2, BigInt&& c)
   {
   m_private = std::make_shared<RSA_Private_Data>(
      std::move(d), std::move(p), std::move(q), std::move(d1), std::move(d2), std::move(c));
   }

RSA_PrivateKey::RSA_PrivateKey(const AlgorithmIdentifier&,
                               const secure_vector<uint8_t>& key_bits)
   {
   BigInt n, e, d, p, q, d1, d2, c;

   BER_Decoder(key_bits)
      .start_cons(SEQUENCE)
         .decode_and_check<size_t>(0, "Unknown PKCS #1 key format version")
         .decode(n)
         .decode(e)
         .decode(d)
         .decode(p)
         .decode(q)
         .decode(d1)
         .decode(d2)
         .decode(c)
      .end_cons();

   RSA_PublicKey::init(std::move(n), std::move(e));

   RSA_PrivateKey::init(std::move(d), std::move(p), std::move(q),
                        std::move(d1), std::move(d2), std::move(c));
   }

RSA_PrivateKey::RSA_PrivateKey(const BigInt& prime1,
                               const BigInt& prime2,
                               const BigInt& exp,
                               const BigInt& d_exp,
                               const BigInt& mod)
   {
   BigInt p = prime1;
   BigInt q = prime2;
   BigInt n = mod;
   if(n.is_zero())
      n = p * q;

   BigInt e = exp;

   BigInt d = d_exp;

   const BigInt p_minus_1 = p - 1;
   const BigInt q_minus_1 = q - 1;

   if(d.is_zero())
      {
      const BigInt phi_n = lcm(p_minus_1, q_minus_1);
      d = inverse_mod(e, phi_n);
      }

   BigInt d1 = ct_modulo(d, p_minus_1);
   BigInt d2 = ct_modulo(d, q_minus_1);
   BigInt c = inverse_mod(q, p);

   RSA_PublicKey::init(std::move(n), std::move(e));

   RSA_PrivateKey::init(std::move(d), std::move(p), std::move(q),
                        std::move(d1), std::move(d2), std::move(c));
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

   BigInt n, e, d, p, q, d1, d2, c;

   e = exp;

   const size_t p_bits = (bits + 1) / 2;
   const size_t q_bits = bits - p_bits;

   do
      {
      // TODO could generate primes in thread pool
      p = generate_rsa_prime(rng, rng, p_bits, e);
      q = generate_rsa_prime(rng, rng, q_bits, e);

      if(p == q)
         throw Internal_Error("RNG failure during RSA key generation");

      n = p * q;
      } while(n.bits() != bits);

   const BigInt p_minus_1 = p - 1;
   const BigInt q_minus_1 = q - 1;

   const BigInt phi_n = lcm(p_minus_1, q_minus_1);
   d = inverse_mod(e, phi_n);
   d1 = ct_modulo(d, p_minus_1);
   d2 = ct_modulo(d, q_minus_1);
   c = inverse_mod(q, p);

   RSA_PublicKey::init(std::move(n), std::move(e));

   RSA_PrivateKey::init(std::move(d), std::move(p), std::move(q),
                        std::move(d1), std::move(d2), std::move(c));
   }

/*
* Check Private RSA Parameters
*/
bool RSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(get_n() < 35 || get_n().is_even() || get_e() < 3 || get_e().is_even())
      return false;

   if(get_d() < 2 || get_p() < 3 || get_q() < 3)
      return false;

   if(get_p() * get_q() != get_n())
      return false;

   if(get_p() == get_q())
      return false;

   if(get_d1() != ct_modulo(get_d(), get_p() - 1))
      return false;
   if(get_d2() != ct_modulo(get_d(), get_q() - 1))
      return false;
   if(get_c() != inverse_mod(get_q(), get_p()))
      return false;

   const size_t prob = (strong) ? 128 : 12;

   if(!is_prime(get_p(), rng, prob))
      return false;
   if(!is_prime(get_q(), rng, prob))
      return false;

   if(strong)
      {
      if(ct_modulo(get_e() * get_d(), lcm(get_p() - 1, get_q() - 1)) != 1)
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
      size_t public_modulus_bits() const { return m_public->public_modulus_bits(); }
      size_t public_modulus_bytes() const { return m_public->public_modulus_bytes(); }

      explicit RSA_Private_Operation(const RSA_PrivateKey& rsa, RandomNumberGenerator& rng) :
         m_public(rsa.public_data()),
         m_private(rsa.private_data()),
         m_blinder(m_public->get_n(), rng,
                   [this](const BigInt& k) { return m_public->public_op(k); },
                   [this](const BigInt& k) { return inverse_mod(k, m_public->get_n()); }),
         m_blinding_bits(64),
         m_max_d1_bits(m_private->m_p_bits + m_blinding_bits),
         m_max_d2_bits(m_private->m_q_bits + m_blinding_bits)
         {
         }

      secure_vector<uint8_t> raw_op(const uint8_t input[], size_t input_len)
         {
         const BigInt input_bn(input, input_len);
         if(input_bn >= m_public->get_n())
            throw Invalid_Argument("RSA private op - input is too large");

         // TODO: This should be a function on blinder
         // BigInt Blinder::run_blinded_function(std::function<BigInt, BigInt> fn, const BigInt& input);

         const BigInt recovered = m_blinder.unblind(rsa_private_op(m_blinder.blind(input_bn)));
         BOTAN_ASSERT(input_bn == m_public->public_op(recovered), "RSA consistency check");
         return BigInt::encode_1363(recovered, m_public->public_modulus_bytes());
         }

   private:

      BigInt rsa_private_op(const BigInt& m) const
         {
         /*
         TODO
         Consider using Montgomery reduction instead of Barrett, using
         the "Smooth RSA-CRT" method. https://eprint.iacr.org/2007/039.pdf
         */

         static constexpr size_t powm_window = 4;

         // Compute this in main thread to avoid racing on the rng
         const BigInt d1_mask(m_blinder.rng(), m_blinding_bits);

#if defined(BOTAN_HAS_THREAD_UTILS) && !defined(BOTAN_HAS_VALGRIND)
   #define BOTAN_RSA_USE_ASYNC
#endif

#if defined(BOTAN_RSA_USE_ASYNC)
         /*
         * Precompute m.sig_words in the main thread before calling async. Otherwise
         * the two threads race (during Modular_Reducer::reduce) and while the output
         * is correct in both threads, helgrind warns.
         */
         m.sig_words();

         auto future_j1 = Thread_Pool::global_instance().run([this, &m, &d1_mask]() {
#endif
            const BigInt masked_d1 = m_private->get_d1() + (d1_mask * (m_private->get_p() - 1));
            auto powm_d1_p = monty_precompute(m_private->m_monty_p, m_private->m_mod_p.reduce(m), powm_window);
            BigInt j1 = monty_execute(*powm_d1_p, masked_d1, m_max_d1_bits);

#if defined(BOTAN_RSA_USE_ASYNC)
         return j1;
         });
#endif

         const BigInt d2_mask(m_blinder.rng(), m_blinding_bits);
         const BigInt masked_d2 = m_private->get_d2() + (d2_mask * (m_private->get_q() - 1));
         auto powm_d2_q = monty_precompute(m_private->m_monty_q, m_private->m_mod_q.reduce(m), powm_window);
         const BigInt j2 = monty_execute(*powm_d2_q, masked_d2, m_max_d2_bits);

#if defined(BOTAN_RSA_USE_ASYNC)
         BigInt j1 = future_j1.get();
#endif

         /*
         * To recover the final value from the CRT representation (j1,j2)
         * we use Garner's algorithm:
         * c = q^-1 mod p (this is precomputed)
         * h = c*(j1-j2) mod p
         * m = j2 + h*q
         *
         * We must avoid leaking if j1 >= j2 or not, as doing so allows deriving
         * information about the secret prime. Do this by first adding p to j1,
         * which should ensure the subtraction of j2 does not underflow. But
         * this may still underflow if p and q are imbalanced in size.
         */

         j1 = m_private->m_mod_p.multiply(m_private->m_mod_p.reduce((m_private->get_p() + j1) - j2), m_private->get_c());
         return mul_add(j1, m_private->get_q(), j2);
         }

      std::shared_ptr<const RSA_Public_Data> m_public;
      std::shared_ptr<const RSA_Private_Data> m_private;

      // XXX could the blinder starting pair be shared?
      Blinder m_blinder;
      const size_t m_blinding_bits;
      const size_t m_max_d1_bits;
      const size_t m_max_d2_bits;
   };

class RSA_Signature_Operation final : public PK_Ops::Signature_with_EMSA,
                                      private RSA_Private_Operation
   {
   public:
      size_t max_input_bits() const override { return public_modulus_bits() - 1; }

      size_t signature_length() const override { return public_modulus_bytes(); }

      RSA_Signature_Operation(const RSA_PrivateKey& rsa, const std::string& emsa, RandomNumberGenerator& rng) :
         PK_Ops::Signature_with_EMSA(emsa),
         RSA_Private_Operation(rsa, rng)
         {
         }

      secure_vector<uint8_t> raw_sign(const uint8_t input[], size_t input_len,
                                      RandomNumberGenerator&) override
         {
         return raw_op(input, input_len);
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

      size_t plaintext_length(size_t) const override { return public_modulus_bytes(); }

      secure_vector<uint8_t> raw_decrypt(const uint8_t input[], size_t input_len) override
         {
         return raw_op(input, input_len);
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
         return raw_op(encap_key, len);
         }
   };

/**
* RSA public (encrypt/verify) operation
*/
class RSA_Public_Operation
   {
   public:
      explicit RSA_Public_Operation(const RSA_PublicKey& rsa) :
         m_public(rsa.public_data())
         {}

         size_t get_max_input_bits() const
         {
         const size_t n_bits = m_public->public_modulus_bits();

         /*
         Make Coverity happy that n_bits - 1 won't underflow

         5 bit minimum: smallest possible RSA key is 3*5
         */
         BOTAN_ASSERT_NOMSG(n_bits >= 5);
         return n_bits - 1;
         }

   protected:
      BigInt public_op(const BigInt& m) const
         {
         if(m >= m_public->get_n())
            throw Invalid_Argument("RSA public op - input is too large");

         return m_public->public_op(m);
         }

      size_t public_modulus_bytes() const { return m_public->public_modulus_bytes(); }

      const BigInt& get_n() const { return m_public->get_n(); }

      std::shared_ptr<const RSA_Public_Data> m_public;
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

      size_t ciphertext_length(size_t) const override { return public_modulus_bytes(); }

      size_t max_raw_input_bits() const override { return get_max_input_bits(); }

      secure_vector<uint8_t> raw_encrypt(const uint8_t input[], size_t input_len,
                                         RandomNumberGenerator&) override
         {
         BigInt input_bn(input, input_len);
         return BigInt::encode_1363(public_op(input_bn), public_modulus_bytes());
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

      secure_vector<uint8_t> verify_mr(const uint8_t input[], size_t input_len) override
         {
         BigInt input_bn(input, input_len);
         return BigInt::encode_locked(public_op(input_bn));
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
