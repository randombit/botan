/*
* RSA
* (C) 1999-2010,2015,2016,2018,2019,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rsa.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/reducer.h>
#include <botan/internal/blinding.h>
#include <botan/internal/divide.h>
#include <botan/internal/emsa.h>
#include <botan/internal/fmt.h>
#include <botan/internal/keypair.h>
#include <botan/internal/monty.h>
#include <botan/internal/monty_exp.h>
#include <botan/internal/parsing.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/pss_params.h>
#include <botan/internal/scan_name.h>
#include <botan/internal/workfactor.h>

#if defined(BOTAN_HAS_THREAD_UTILS)
   #include <botan/internal/thread_pool.h>
#endif

namespace Botan {

class RSA_Public_Data final {
   public:
      RSA_Public_Data(BigInt&& n, BigInt&& e) :
            m_n(std::move(n)),
            m_e(std::move(e)),
            m_monty_n(std::make_shared<Montgomery_Params>(m_n)),
            m_public_modulus_bits(m_n.bits()),
            m_public_modulus_bytes(m_n.bytes()) {}

      BigInt public_op(const BigInt& m) const {
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

class RSA_Private_Data final {
   public:
      RSA_Private_Data(BigInt&& d, BigInt&& p, BigInt&& q, BigInt&& d1, BigInt&& d2, BigInt&& c) :
            m_d(std::move(d)),
            m_p(std::move(p)),
            m_q(std::move(q)),
            m_d1(std::move(d1)),
            m_d2(std::move(d2)),
            m_c(std::move(c)),
            m_mod_p(m_p),
            m_mod_q(m_q),
            m_monty_p(std::make_shared<Montgomery_Params>(m_p, m_mod_p)),
            m_monty_q(std::make_shared<Montgomery_Params>(m_q, m_mod_q)),
            m_p_bits(m_p.bits()),
            m_q_bits(m_q.bits()) {}

      const BigInt& get_d() const { return m_d; }

      const BigInt& get_p() const { return m_p; }

      const BigInt& get_q() const { return m_q; }

      const BigInt& get_d1() const { return m_d1; }

      const BigInt& get_d2() const { return m_d2; }

      const BigInt& get_c() const { return m_c; }

      const Modular_Reducer& mod_p() const { return m_mod_p; }

      const Modular_Reducer& mod_q() const { return m_mod_q; }

      const std::shared_ptr<const Montgomery_Params>& monty_p() const { return m_monty_p; }

      const std::shared_ptr<const Montgomery_Params>& monty_q() const { return m_monty_q; }

      size_t p_bits() const { return m_p_bits; }

      size_t q_bits() const { return m_q_bits; }

   private:
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

std::shared_ptr<const RSA_Public_Data> RSA_PublicKey::public_data() const {
   return m_public;
}

const BigInt& RSA_PublicKey::get_int_field(std::string_view field) const {
   if(field == "n") {
      return m_public->get_n();
   } else if(field == "e") {
      return m_public->get_e();
   } else {
      return Public_Key::get_int_field(field);
   }
}

std::unique_ptr<Private_Key> RSA_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<RSA_PrivateKey>(rng, m_public->public_modulus_bits(), m_public->get_e().to_u32bit());
}

const BigInt& RSA_PublicKey::get_n() const {
   return m_public->get_n();
}

const BigInt& RSA_PublicKey::get_e() const {
   return m_public->get_e();
}

void RSA_PublicKey::init(BigInt&& n, BigInt&& e) {
   if(n.is_negative() || n.is_even() || n.bits() < 5 /* n >= 3*5 */ || e.is_negative() || e.is_even()) {
      throw Decoding_Error("Invalid RSA public key parameters");
   }
   m_public = std::make_shared<RSA_Public_Data>(std::move(n), std::move(e));
}

RSA_PublicKey::RSA_PublicKey(const AlgorithmIdentifier& /*unused*/, std::span<const uint8_t> key_bits) {
   BigInt n, e;
   BER_Decoder(key_bits).start_sequence().decode(n).decode(e).end_cons();

   init(std::move(n), std::move(e));
}

bool RSA_PublicKey::supports_operation(PublicKeyOperation op) const {
   return op == PublicKeyOperation::Signature || op == PublicKeyOperation::Encryption ||
          op == PublicKeyOperation::KeyEncapsulation;
}

RSA_PublicKey::RSA_PublicKey(const BigInt& modulus, const BigInt& exponent) {
   BigInt n = modulus;
   BigInt e = exponent;
   init(std::move(n), std::move(e));
}

size_t RSA_PublicKey::key_length() const {
   return m_public->public_modulus_bits();
}

size_t RSA_PublicKey::estimated_strength() const {
   return if_work_factor(key_length());
}

AlgorithmIdentifier RSA_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_NULL_PARAM);
}

std::vector<uint8_t> RSA_PublicKey::raw_public_key_bits() const {
   throw Not_Implemented("an RSA public key does not provide a raw binary representation.");
}

std::vector<uint8_t> RSA_PublicKey::public_key_bits() const {
   std::vector<uint8_t> output;
   DER_Encoder der(output);
   der.start_sequence().encode(get_n()).encode(get_e()).end_cons();

   return output;
}

/*
* Check RSA Public Parameters
*/
bool RSA_PublicKey::check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   if(get_n() < 35 || get_n().is_even() || get_e() < 3 || get_e().is_even()) {
      return false;
   }
   return true;
}

std::shared_ptr<const RSA_Private_Data> RSA_PrivateKey::private_data() const {
   return m_private;
}

secure_vector<uint8_t> RSA_PrivateKey::private_key_bits() const {
   return DER_Encoder()
      .start_sequence()
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

const BigInt& RSA_PrivateKey::get_p() const {
   return m_private->get_p();
}

const BigInt& RSA_PrivateKey::get_q() const {
   return m_private->get_q();
}

const BigInt& RSA_PrivateKey::get_d() const {
   return m_private->get_d();
}

const BigInt& RSA_PrivateKey::get_c() const {
   return m_private->get_c();
}

const BigInt& RSA_PrivateKey::get_d1() const {
   return m_private->get_d1();
}

const BigInt& RSA_PrivateKey::get_d2() const {
   return m_private->get_d2();
}

void RSA_PrivateKey::init(BigInt&& d, BigInt&& p, BigInt&& q, BigInt&& d1, BigInt&& d2, BigInt&& c) {
   m_private = std::make_shared<RSA_Private_Data>(
      std::move(d), std::move(p), std::move(q), std::move(d1), std::move(d2), std::move(c));
}

RSA_PrivateKey::RSA_PrivateKey(const AlgorithmIdentifier& /*unused*/, std::span<const uint8_t> key_bits) {
   BigInt n, e, d, p, q, d1, d2, c;

   BER_Decoder(key_bits)
      .start_sequence()
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

   RSA_PrivateKey::init(std::move(d), std::move(p), std::move(q), std::move(d1), std::move(d2), std::move(c));
}

RSA_PrivateKey::RSA_PrivateKey(
   const BigInt& prime1, const BigInt& prime2, const BigInt& exp, const BigInt& d_exp, const BigInt& mod) {
   BigInt p = prime1;
   BigInt q = prime2;
   BigInt n = mod;
   if(n.is_zero()) {
      n = p * q;
   }

   BigInt e = exp;

   BigInt d = d_exp;

   const BigInt p_minus_1 = p - 1;
   const BigInt q_minus_1 = q - 1;

   if(d.is_zero()) {
      const BigInt phi_n = lcm(p_minus_1, q_minus_1);
      d = inverse_mod(e, phi_n);
   }

   BigInt d1 = ct_modulo(d, p_minus_1);
   BigInt d2 = ct_modulo(d, q_minus_1);
   BigInt c = inverse_mod(q, p);

   RSA_PublicKey::init(std::move(n), std::move(e));

   RSA_PrivateKey::init(std::move(d), std::move(p), std::move(q), std::move(d1), std::move(d2), std::move(c));
}

/*
* Create a RSA private key
*/
RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng, size_t bits, size_t exp) {
   if(bits < 1024) {
      throw Invalid_Argument(fmt("Cannot create an RSA key only {} bits long", bits));
   }

   if(exp < 3 || exp % 2 == 0) {
      throw Invalid_Argument("Invalid RSA encryption exponent");
   }

   const size_t p_bits = (bits + 1) / 2;
   const size_t q_bits = bits - p_bits;

   BigInt p, q, n;
   BigInt e = BigInt::from_u64(exp);

   for(size_t attempt = 0;; ++attempt) {
      if(attempt > 10) {
         throw Internal_Error("RNG failure during RSA key generation");
      }

      // TODO could generate primes in thread pool
      p = generate_rsa_prime(rng, rng, p_bits, e);
      q = generate_rsa_prime(rng, rng, q_bits, e);

      const BigInt diff = p - q;
      if(diff.bits() < (bits / 2) - 100) {
         continue;
      }

      n = p * q;

      if(n.bits() != bits) {
         continue;
      }

      break;
   }

   const BigInt p_minus_1 = p - 1;
   const BigInt q_minus_1 = q - 1;

   const BigInt phi_n = lcm(p_minus_1, q_minus_1);
   // This is guaranteed because p,q == 3 mod 4
   BOTAN_DEBUG_ASSERT(low_zero_bits(phi_n) == 1);

   BigInt d = inverse_mod(e, phi_n);
   BigInt d1 = ct_modulo(d, p_minus_1);
   BigInt d2 = ct_modulo(d, q_minus_1);
   BigInt c = inverse_mod(q, p);

   RSA_PublicKey::init(std::move(n), std::move(e));

   RSA_PrivateKey::init(std::move(d), std::move(p), std::move(q), std::move(d1), std::move(d2), std::move(c));
}

const BigInt& RSA_PrivateKey::get_int_field(std::string_view field) const {
   if(field == "p") {
      return m_private->get_p();
   } else if(field == "q") {
      return m_private->get_q();
   } else if(field == "d") {
      return m_private->get_d();
   } else if(field == "c") {
      return m_private->get_c();
   } else if(field == "d1") {
      return m_private->get_d1();
   } else if(field == "d2") {
      return m_private->get_d2();
   } else {
      return RSA_PublicKey::get_int_field(field);
   }
}

std::unique_ptr<Public_Key> RSA_PrivateKey::public_key() const {
   return std::make_unique<RSA_PublicKey>(get_n(), get_e());
}

/*
* Check Private RSA Parameters
*/
bool RSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   if(get_n() < 35 || get_n().is_even() || get_e() < 3 || get_e().is_even()) {
      return false;
   }

   if(get_d() < 2 || get_p() < 3 || get_q() < 3) {
      return false;
   }

   if(get_p() * get_q() != get_n()) {
      return false;
   }

   if(get_p() == get_q()) {
      return false;
   }

   if(get_d1() != ct_modulo(get_d(), get_p() - 1)) {
      return false;
   }
   if(get_d2() != ct_modulo(get_d(), get_q() - 1)) {
      return false;
   }
   if(get_c() != inverse_mod(get_q(), get_p())) {
      return false;
   }

   const size_t prob = (strong) ? 128 : 12;

   if(!is_prime(get_p(), rng, prob)) {
      return false;
   }
   if(!is_prime(get_q(), rng, prob)) {
      return false;
   }

   if(strong) {
      if(ct_modulo(get_e() * get_d(), lcm(get_p() - 1, get_q() - 1)) != 1) {
         return false;
      }

      return KeyPair::signature_consistency_check(rng, *this, "EMSA4(SHA-256)");
   }

   return true;
}

namespace {

/**
* RSA private (decrypt/sign) operation
*/
class RSA_Private_Operation {
   protected:
      size_t public_modulus_bits() const { return m_public->public_modulus_bits(); }

      size_t public_modulus_bytes() const { return m_public->public_modulus_bytes(); }

      explicit RSA_Private_Operation(const RSA_PrivateKey& rsa, RandomNumberGenerator& rng) :
            m_public(rsa.public_data()),
            m_private(rsa.private_data()),
            m_blinder(
               m_public->get_n(),
               rng,
               [this](const BigInt& k) { return m_public->public_op(k); },
               [this](const BigInt& k) { return inverse_mod(k, m_public->get_n()); }),
            m_blinding_bits(64),
            m_max_d1_bits(m_private->p_bits() + m_blinding_bits),
            m_max_d2_bits(m_private->q_bits() + m_blinding_bits) {}

      void raw_op(std::span<uint8_t> out, std::span<const uint8_t> input) {
         if(input.size() > public_modulus_bytes()) {
            throw Decoding_Error("RSA input is too long for this key");
         }
         const BigInt input_bn(input.data(), input.size());
         if(input_bn >= m_public->get_n()) {
            throw Decoding_Error("RSA input is too large for this key");
         }
         // TODO: This should be a function on blinder
         // BigInt Blinder::run_blinded_function(std::function<BigInt, BigInt> fn, const BigInt& input);

         const BigInt recovered = m_blinder.unblind(rsa_private_op(m_blinder.blind(input_bn)));
         BOTAN_ASSERT(input_bn == m_public->public_op(recovered), "RSA consistency check");
         BOTAN_ASSERT(m_public->public_modulus_bytes() == out.size(), "output size check");
         recovered.serialize_to(out);
      }

   private:
      BigInt rsa_private_op(const BigInt& m) const {
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
            auto powm_d1_p = monty_precompute(m_private->monty_p(), m_private->mod_p().reduce(m), powm_window);
            BigInt j1 = monty_execute(*powm_d1_p, masked_d1, m_max_d1_bits);

#if defined(BOTAN_RSA_USE_ASYNC)
            return j1;
         });
#endif

         const BigInt d2_mask(m_blinder.rng(), m_blinding_bits);
         const BigInt masked_d2 = m_private->get_d2() + (d2_mask * (m_private->get_q() - 1));
         auto powm_d2_q = monty_precompute(m_private->monty_q(), m_private->mod_q().reduce(m), powm_window);
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

         j1 =
            m_private->mod_p().multiply(m_private->mod_p().reduce((m_private->get_p() + j1) - j2), m_private->get_c());
         return j1 * m_private->get_q() + j2;
      }

      std::shared_ptr<const RSA_Public_Data> m_public;
      std::shared_ptr<const RSA_Private_Data> m_private;

      // XXX could the blinder starting pair be shared?
      Blinder m_blinder;
      const size_t m_blinding_bits;
      const size_t m_max_d1_bits;
      const size_t m_max_d2_bits;
};

class RSA_Signature_Operation final : public PK_Ops::Signature,
                                      private RSA_Private_Operation {
   public:
      void update(std::span<const uint8_t> msg) override { m_emsa->update(msg.data(), msg.size()); }

      std::vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         const size_t max_input_bits = public_modulus_bits() - 1;
         const auto msg = m_emsa->raw_data();
         const auto padded = m_emsa->encoding_of(msg, max_input_bits, rng);

         std::vector<uint8_t> out(public_modulus_bytes());
         raw_op(out, padded);
         return out;
      }

      size_t signature_length() const override { return public_modulus_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override;

      std::string hash_function() const override { return m_emsa->hash_function(); }

      RSA_Signature_Operation(const RSA_PrivateKey& rsa, PK_Signature_Options& options, RandomNumberGenerator& rng) :
            RSA_Private_Operation(rsa, rng) {
         m_emsa = EMSA::create_or_throw(options);
      }

   private:
      std::unique_ptr<EMSA> m_emsa;
};

AlgorithmIdentifier RSA_Signature_Operation::algorithm_identifier() const {
   const std::string emsa_name = m_emsa->name();

   try {
      const std::string full_name = "RSA/" + emsa_name;
      const OID oid = OID::from_string(full_name);
      return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_EMPTY_PARAM);
   } catch(Lookup_Error&) {}

   if(emsa_name.starts_with("EMSA4(")) {
      auto parameters = PSS_Params::from_emsa_name(m_emsa->name()).serialize();
      return AlgorithmIdentifier("RSA/EMSA4", parameters);
   }

   throw Not_Implemented("No algorithm identifier defined for RSA with " + emsa_name);
}

class RSA_Decryption_Operation final : public PK_Ops::Decryption_with_EME,
                                       private RSA_Private_Operation {
   public:
      RSA_Decryption_Operation(const RSA_PrivateKey& rsa, std::string_view eme, RandomNumberGenerator& rng) :
            PK_Ops::Decryption_with_EME(eme), RSA_Private_Operation(rsa, rng) {}

      size_t plaintext_length(size_t /*ctext_len*/) const override { return public_modulus_bytes(); }

      secure_vector<uint8_t> raw_decrypt(std::span<const uint8_t> input) override {
         secure_vector<uint8_t> out(public_modulus_bytes());
         raw_op(out, input);
         return out;
      }
};

class RSA_KEM_Decryption_Operation final : public PK_Ops::KEM_Decryption_with_KDF,
                                           private RSA_Private_Operation {
   public:
      RSA_KEM_Decryption_Operation(const RSA_PrivateKey& key, std::string_view kdf, RandomNumberGenerator& rng) :
            PK_Ops::KEM_Decryption_with_KDF(kdf), RSA_Private_Operation(key, rng) {}

      size_t raw_kem_shared_key_length() const override { return public_modulus_bytes(); }

      size_t encapsulated_key_length() const override { return public_modulus_bytes(); }

      void raw_kem_decrypt(std::span<uint8_t> out_shared_key, std::span<const uint8_t> encapsulated_key) override {
         raw_op(out_shared_key, encapsulated_key);
      }
};

/**
* RSA public (encrypt/verify) operation
*/
class RSA_Public_Operation {
   public:
      explicit RSA_Public_Operation(const RSA_PublicKey& rsa) : m_public(rsa.public_data()) {}

      size_t public_modulus_bits() const { return m_public->public_modulus_bits(); }

   protected:
      BigInt public_op(const BigInt& m) const {
         if(m >= m_public->get_n()) {
            throw Decoding_Error("RSA public op - input is too large");
         }

         return m_public->public_op(m);
      }

      size_t public_modulus_bytes() const { return m_public->public_modulus_bytes(); }

      const BigInt& get_n() const { return m_public->get_n(); }

   private:
      std::shared_ptr<const RSA_Public_Data> m_public;
};

class RSA_Encryption_Operation final : public PK_Ops::Encryption_with_EME,
                                       private RSA_Public_Operation {
   public:
      RSA_Encryption_Operation(const RSA_PublicKey& rsa, std::string_view eme) :
            PK_Ops::Encryption_with_EME(eme), RSA_Public_Operation(rsa) {}

      size_t ciphertext_length(size_t /*ptext_len*/) const override { return public_modulus_bytes(); }

      size_t max_ptext_input_bits() const override { return public_modulus_bits() - 1; }

      std::vector<uint8_t> raw_encrypt(std::span<const uint8_t> input, RandomNumberGenerator& /*rng*/) override {
         BigInt input_bn(input);
         return public_op(input_bn).serialize(public_modulus_bytes());
      }
};

class RSA_Verify_Operation final : public PK_Ops::Verification,
                                   private RSA_Public_Operation {
   public:
      void update(std::span<const uint8_t> msg) override { m_emsa->update(msg.data(), msg.size()); }

      bool is_valid_signature(std::span<const uint8_t> sig) override {
         const auto msg = m_emsa->raw_data();
         const auto message_repr = recover_message_repr(sig.data(), sig.size());
         return m_emsa->verify(message_repr, msg, public_modulus_bits() - 1);
      }

      RSA_Verify_Operation(const RSA_PublicKey& rsa, PK_Signature_Options& options) :
            RSA_Public_Operation(rsa), m_emsa(EMSA::create_or_throw(options)) {}

      std::string hash_function() const override { return m_emsa->hash_function(); }

   private:
      std::vector<uint8_t> recover_message_repr(const uint8_t input[], size_t input_len) {
         if(input_len > public_modulus_bytes()) {
            throw Decoding_Error("RSA signature too large to be valid for this key");
         }
         BigInt input_bn(input, input_len);
         return public_op(input_bn).serialize();
      }

      std::unique_ptr<EMSA> m_emsa;
};

class RSA_KEM_Encryption_Operation final : public PK_Ops::KEM_Encryption_with_KDF,
                                           private RSA_Public_Operation {
   public:
      RSA_KEM_Encryption_Operation(const RSA_PublicKey& key, std::string_view kdf) :
            PK_Ops::KEM_Encryption_with_KDF(kdf), RSA_Public_Operation(key) {}

   private:
      size_t raw_kem_shared_key_length() const override { return public_modulus_bytes(); }

      size_t encapsulated_key_length() const override { return public_modulus_bytes(); }

      void raw_kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                           std::span<uint8_t> raw_shared_key,
                           RandomNumberGenerator& rng) override {
         const BigInt r = BigInt::random_integer(rng, 1, get_n());
         const BigInt c = public_op(r);

         c.serialize_to(out_encapsulated_key);
         r.serialize_to(raw_shared_key);
      }
};

}  // namespace

std::unique_ptr<PK_Ops::Encryption> RSA_PublicKey::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                                                        std::string_view params,
                                                                        std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<RSA_Encryption_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::KEM_Encryption> RSA_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<RSA_KEM_Encryption_Operation>(*this, params);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> RSA_PublicKey::_create_verification_op(PK_Signature_Options& options) const {
   options.exclude_provider();
   return std::make_unique<RSA_Verify_Operation>(*this, options);
}

namespace {

PK_Signature_Options parse_rsa_signature_algorithm(const AlgorithmIdentifier& alg_id) {
   const auto sig_info = split_on(alg_id.oid().to_formatted_string(), '/');

   if(sig_info.empty() || sig_info.size() != 2 || sig_info[0] != "RSA") {
      throw Decoding_Error("Unknown AlgorithmIdentifier for RSA X.509 signatures");
   }

   const std::string& padding = sig_info[1];

   PK_Verification_Options_Builder opts;

   if(padding == "EMSA4") {
      // "MUST contain RSASSA-PSS-params"
      if(alg_id.parameters().empty()) {
         throw Decoding_Error("PSS params must be provided");
      }

      PSS_Params pss_params(alg_id.parameters());

      // hash_algo must be SHA1, SHA2-224, SHA2-256, SHA2-384 or SHA2-512
      const std::string hash_algo = pss_params.hash_function();
      if(hash_algo != "SHA-1" && hash_algo != "SHA-224" && hash_algo != "SHA-256" && hash_algo != "SHA-384" &&
         hash_algo != "SHA-512") {
         throw Decoding_Error("Unacceptable hash for PSS signatures");
      }

      if(pss_params.mgf_function() != "MGF1") {
         throw Decoding_Error("Unacceptable MGF for PSS signatures");
      }

      // For MGF1, it is strongly RECOMMENDED that the underlying hash
      // function be the same as the one identified by hashAlgorithm
      //
      // Must be SHA1, SHA2-224, SHA2-256, SHA2-384 or SHA2-512
      if(pss_params.hash_algid() != pss_params.mgf_hash_algid()) {
         throw Decoding_Error("Unacceptable MGF hash for PSS signatures");
      }

      if(pss_params.trailer_field() != 1) {
         throw Decoding_Error("Unacceptable trailer field for PSS signatures");
      }

      opts.with_padding("PSS").with_hash(hash_algo).with_salt_size(pss_params.salt_length());
   } else {
      SCAN_Name scan(padding);

      if(scan.algo_name() != "EMSA3") {
         throw Decoding_Error("Unexpected OID for RSA signatures");
      }

      opts.with_padding("PKCS1v15").with_hash(scan.arg(0));
   }

   return opts.commit();
}

}  // namespace

std::unique_ptr<PK_Ops::Verification> RSA_PublicKey::create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                                 std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      auto opts = parse_rsa_signature_algorithm(alg_id);
      return std::make_unique<RSA_Verify_Operation>(*this, opts);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Decryption> RSA_PrivateKey::create_decryption_op(RandomNumberGenerator& rng,
                                                                         std::string_view params,
                                                                         std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<RSA_Decryption_Operation>(*this, params, rng);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::KEM_Decryption> RSA_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                                 std::string_view params,
                                                                                 std::string_view provider) const {
   if(provider == "base" || provider.empty()) {
      return std::make_unique<RSA_KEM_Decryption_Operation>(*this, params, rng);
   }

   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Signature> RSA_PrivateKey::_create_signature_op(RandomNumberGenerator& rng,
                                                                        PK_Signature_Options& options) const {
   options.exclude_provider();
   return std::make_unique<RSA_Signature_Operation>(*this, options, rng);
}

}  // namespace Botan
