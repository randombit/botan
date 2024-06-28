/*
* Crystals Dilithium Digital Signature Algorithms
* Based on the public domain reference implementation by the
* designers (https://github.com/pq-crystals/dilithium)
*
* Further changes
* (C) 2021-2023 Jack Lloyd
* (C) 2021-2022 Manuel Glaser - Rohde & Schwarz Cybersecurity
* (C) 2021-2023 Michael Boric, René Meusel - Rohde & Schwarz Cybersecurity
* (C) 2024      René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/dilithium.h>

#include <botan/exceptn.h>
#include <botan/rng.h>

#include <botan/internal/dilithium_algos.h>
#include <botan/internal/dilithium_symmetric_primitives.h>
#include <botan/internal/dilithium_types.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/stl_util.h>

namespace Botan {
namespace {

DilithiumMode::Mode dilithium_mode_from_string(std::string_view str) {
   if(str == "Dilithium-4x4-r3") {
      return DilithiumMode::Dilithium4x4;
   }
   if(str == "Dilithium-4x4-AES-r3") {
      return DilithiumMode::Dilithium4x4_AES;
   }
   if(str == "Dilithium-6x5-r3") {
      return DilithiumMode::Dilithium6x5;
   }
   if(str == "Dilithium-6x5-AES-r3") {
      return DilithiumMode::Dilithium6x5_AES;
   }
   if(str == "Dilithium-8x7-r3") {
      return DilithiumMode::Dilithium8x7;
   }
   if(str == "Dilithium-8x7-AES-r3") {
      return DilithiumMode::Dilithium8x7_AES;
   }

   throw Invalid_Argument(fmt("'{}' is not a valid Dilithium mode name", str));
}

}  // namespace

DilithiumMode::DilithiumMode(const OID& oid) : m_mode(dilithium_mode_from_string(oid.to_formatted_string())) {}

DilithiumMode::DilithiumMode(std::string_view str) : m_mode(dilithium_mode_from_string(str)) {}

OID DilithiumMode::object_identifier() const {
   return OID::from_string(to_string());
}

std::string DilithiumMode::to_string() const {
   switch(m_mode) {
      case DilithiumMode::Dilithium4x4:
         return "Dilithium-4x4-r3";
      case DilithiumMode::Dilithium4x4_AES:
         return "Dilithium-4x4-AES-r3";
      case DilithiumMode::Dilithium6x5:
         return "Dilithium-6x5-r3";
      case DilithiumMode::Dilithium6x5_AES:
         return "Dilithium-6x5-AES-r3";
      case DilithiumMode::Dilithium8x7:
         return "Dilithium-8x7-r3";
      case DilithiumMode::Dilithium8x7_AES:
         return "Dilithium-8x7-AES-r3";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

class Dilithium_PublicKeyInternal {
   public:
      static std::shared_ptr<Dilithium_PublicKeyInternal> decode(
         DilithiumConstants mode, StrongSpan<const DilithiumSerializedPublicKey> raw_pk) {
         auto [rho, t1] = Dilithium_Algos::decode_public_key(raw_pk, mode);
         return std::make_shared<Dilithium_PublicKeyInternal>(std::move(mode), std::move(rho), std::move(t1));
      }

      Dilithium_PublicKeyInternal(DilithiumConstants mode, DilithiumSeedRho rho, DilithiumPolyVec t1) :
            m_mode(std::move(mode)),
            m_rho(std::move(rho)),
            m_t1(std::move(t1)),
            m_tr(m_mode.symmetric_primitives().H(raw_pk())) {
         BOTAN_ASSERT_NOMSG(!m_rho.empty());
         BOTAN_ASSERT_NOMSG(m_t1.size() > 0);
      }

   public:
      DilithiumSerializedPublicKey raw_pk() const { return Dilithium_Algos::encode_public_key(m_rho, m_t1, m_mode); }

      const DilithiumHashedPublicKey& tr() const { return m_tr; }

      const DilithiumPolyVec& t1() const { return m_t1; }

      const DilithiumSeedRho& rho() const { return m_rho; }

      const DilithiumConstants& mode() const { return m_mode; }

   private:
      const DilithiumConstants m_mode;
      DilithiumSeedRho m_rho;
      DilithiumPolyVec m_t1;
      DilithiumHashedPublicKey m_tr;
};

class Dilithium_PrivateKeyInternal {
   public:
      static std::shared_ptr<Dilithium_PrivateKeyInternal> decode(DilithiumConstants mode,
                                                                  StrongSpan<const DilithiumSerializedPrivateKey> sk) {
         auto [rho, signing_seed, tr, s1, s2, t0] = Dilithium_Algos::decode_private_key(sk, mode);
         return std::make_shared<Dilithium_PrivateKeyInternal>(std::move(mode),
                                                               std::move(rho),
                                                               std::move(signing_seed),
                                                               std::move(tr),
                                                               std::move(s1),
                                                               std::move(s2),
                                                               std::move(t0));
      }

      Dilithium_PrivateKeyInternal(DilithiumConstants mode,
                                   DilithiumSeedRho rho,
                                   DilithiumSigningSeedK signing_seed,
                                   DilithiumHashedPublicKey tr,
                                   DilithiumPolyVec s1,
                                   DilithiumPolyVec s2,
                                   DilithiumPolyVec t0) :
            m_mode(std::move(mode)),
            m_rho(std::move(rho)),
            m_signing_seed(std::move(signing_seed)),
            m_tr(std::move(tr)),
            m_t0(std::move(t0)),
            m_s1(std::move(s1)),
            m_s2(std::move(s2)) {}

   public:
      DilithiumSerializedPrivateKey raw_sk() const {
         return Dilithium_Algos::encode_private_key(m_rho, m_tr, m_signing_seed, m_s1, m_s2, m_t0, m_mode);
      }

      const DilithiumConstants& mode() const { return m_mode; }

      const DilithiumSeedRho& rho() const { return m_rho; }

      const DilithiumSigningSeedK& signing_seed() const { return m_signing_seed; }

      const DilithiumHashedPublicKey& tr() const { return m_tr; }

      const DilithiumPolyVec& s1() const { return m_s1; }

      const DilithiumPolyVec& s2() const { return m_s2; }

      const DilithiumPolyVec& t0() const { return m_t0; }

   private:
      const DilithiumConstants m_mode;
      DilithiumSeedRho m_rho;
      DilithiumSigningSeedK m_signing_seed;
      DilithiumHashedPublicKey m_tr;
      DilithiumPolyVec m_t0;
      DilithiumPolyVec m_s1;
      DilithiumPolyVec m_s2;
};

class Dilithium_Signature_Operation final : public PK_Ops::Signature {
   public:
      Dilithium_Signature_Operation(std::shared_ptr<Dilithium_PrivateKeyInternal> sk, bool randomized) :
            m_priv_key(std::move(sk)),
            m_randomized(randomized),
            m_h(m_priv_key->mode().symmetric_primitives().get_message_hash(m_priv_key->tr())),
            m_s1(ntt(m_priv_key->s1().clone())),
            m_s2(ntt(m_priv_key->s2().clone())),
            m_t0(ntt(m_priv_key->t0().clone())),
            m_A(Dilithium_Algos::expand_A(m_priv_key->rho(), m_priv_key->mode())) {}

      void update(const uint8_t msg[], size_t msg_len) override { m_h.update({msg, msg_len}); }

      /**
       * NIST FIPS 204 IPD, Algorithm 2 (ML-DSA.Sign)
       *
       * Note that the private key decoding is done ahead of time. Also, the
       * matrix expansion of A from 'rho' along with the NTT-transforms of s1,
       * s2 and t0 are done in the constructor of this class, as a 'signature
       * operation' may be used to sign multiple messages.
       */
      secure_vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         const auto mu = m_h.final();
         const auto& mode = m_priv_key->mode();
         const auto& sympri = mode.symmetric_primitives();

         // TODO: ML-DSA generates rhoprime differently, namely
         //       rhoprime = H(K, rnd, mu) with rnd being 32 random bytes or 32 zero bytes
         const auto rhoprime = (m_randomized)
                                  ? rng.random_vec<DilithiumSeedRhoPrime>(DilithiumConstants::SEED_RHOPRIME_BYTES)
                                  : sympri.H(m_priv_key->signing_seed(), mu);

         // Note: nonce (as requested by `polyvecl_uniform_gamma1`) is actually just uint16_t
         //       but to avoid an integer overflow, we use uint32_t as the loop variable.
         for(uint32_t nonce = 0; nonce <= std::numeric_limits<uint16_t>::max(); nonce += mode.l()) {
            const auto y = Dilithium_Algos::expand_mask(rhoprime, static_cast<uint16_t>(nonce), mode);

            auto w_ntt = m_A * ntt(y.clone());
            w_ntt.reduce();
            auto w = inverse_ntt(std::move(w_ntt));
            w.conditional_add_q();

            auto [w1, w0] = Dilithium_Algos::decompose(w, mode);
            const auto ch = sympri.H(mu, Dilithium_Algos::encode_commitment(w1, mode));
            StrongSpan<const DilithiumCommitmentHash> c1(
               std::span<const uint8_t>(ch).first(DilithiumConstants::COMMITMENT_HASH_C1_BYTES));
            const auto c = ntt(Dilithium_Algos::sample_in_ball(c1, mode));
            const auto cs1 = inverse_ntt(c * m_s1);
            auto z = y + cs1;
            z.reduce();
            if(!Dilithium_Algos::infinity_norm_within_bound(z, to_underlying(mode.gamma1()) - mode.beta())) {
               continue;
            }

            const auto cs2 = inverse_ntt(c * m_s2);
            w0 -= cs2;
            w0.reduce();
            if(!Dilithium_Algos::infinity_norm_within_bound(w0, to_underlying(mode.gamma2()) - mode.beta())) {
               continue;
            }

            auto ct0 = inverse_ntt(c * m_t0);
            ct0.reduce();
            if(!Dilithium_Algos::infinity_norm_within_bound(ct0, mode.gamma2())) {
               continue;
            }

            w0 += ct0;
            w0.conditional_add_q();

            const auto hint = Dilithium_Algos::make_hint(w0, w1, mode);
            if(hint.hamming_weight() > mode.omega()) {
               continue;
            }

            return Dilithium_Algos::encode_signature(ch, z, hint, mode).get();
         }

         throw Internal_Error("Dilithium signature loop did not terminate");
      }

      size_t signature_length() const override { return m_priv_key->mode().signature_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override {
         return AlgorithmIdentifier(m_priv_key->mode().mode().object_identifier(),
                                    AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      std::string hash_function() const override { return m_h.name(); }

   private:
      std::shared_ptr<Dilithium_PrivateKeyInternal> m_priv_key;
      bool m_randomized;
      DilithiumMessageHash m_h;

      const DilithiumPolyVecNTT m_s1;
      const DilithiumPolyVecNTT m_s2;
      const DilithiumPolyVecNTT m_t0;
      const DilithiumPolyMatNTT m_A;
};

class Dilithium_Verification_Operation final : public PK_Ops::Verification {
   public:
      Dilithium_Verification_Operation(std::shared_ptr<Dilithium_PublicKeyInternal> pubkey) :
            m_pub_key(std::move(pubkey)),
            m_A(Dilithium_Algos::expand_A(m_pub_key->rho(), m_pub_key->mode())),
            m_t1_ntt_shifted(ntt(m_pub_key->t1() << DilithiumConstants::D)),
            m_h(m_pub_key->mode().symmetric_primitives().get_message_hash(m_pub_key->tr())) {}

      void update(const uint8_t msg[], size_t msg_len) override { m_h.update({msg, msg_len}); }

      /**
       * NIST FIPS 204 IPD, Algorithm 3 (ML-DSA.Verify)
       *
       * Note that the public key decoding is done ahead of time. Also, the
       * matrix A is expanded from 'rho' in the constructor of this class, as
       * a 'verification operation' may be used to verify multiple signatures.
       */
      bool is_valid_signature(const uint8_t* sig, size_t sig_len) override {
         const auto& mode = m_pub_key->mode();
         const auto& sympri = mode.symmetric_primitives();
         StrongSpan<const DilithiumSerializedSignature> sig_bytes({sig, sig_len});

         if(sig_bytes.size() != mode.signature_bytes()) {
            return false;
         }

         const auto mu = m_h.final();

         auto signature = Dilithium_Algos::decode_signature(sig_bytes, mode);
         if(!signature.has_value()) {
            return false;
         }
         auto [ch, z, h] = std::move(signature.value());
         StrongSpan<const DilithiumCommitmentHash> c1(
            std::span<uint8_t>(ch).first(DilithiumConstants::COMMITMENT_HASH_C1_BYTES));

         if(h.hamming_weight() > mode.omega() ||
            !Dilithium_Algos::infinity_norm_within_bound(z, to_underlying(mode.gamma1()) - mode.beta())) {
            return false;
         }

         const auto c_hat = ntt(Dilithium_Algos::sample_in_ball(c1, mode));
         auto w_approx = m_A * ntt(std::move(z));
         w_approx -= c_hat * m_t1_ntt_shifted;
         w_approx.reduce();
         auto w1 = inverse_ntt(std::move(w_approx));
         w1.conditional_add_q();
         Dilithium_Algos::use_hint(w1, h, mode);

         const auto chprime = sympri.H(mu, Dilithium_Algos::encode_commitment(w1, mode));

         BOTAN_ASSERT_NOMSG(ch.size() == chprime.size());
         return std::equal(ch.begin(), ch.end(), chprime.begin());
      }

      std::string hash_function() const override { return m_h.name(); }

   private:
      std::shared_ptr<Dilithium_PublicKeyInternal> m_pub_key;
      DilithiumPolyMatNTT m_A;
      DilithiumPolyVecNTT m_t1_ntt_shifted;
      DilithiumMessageHash m_h;
};

Dilithium_PublicKey::Dilithium_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk) :
      Dilithium_PublicKey(pk, DilithiumMode(alg_id.oid())) {}

Dilithium_PublicKey::Dilithium_PublicKey(std::span<const uint8_t> pk, DilithiumMode m) {
   DilithiumConstants mode(m);
   BOTAN_ARG_CHECK(pk.empty() || pk.size() == mode.public_key_bytes(),
                   "dilithium public key does not have the correct byte count");

   m_public = Dilithium_PublicKeyInternal::decode(std::move(mode), StrongSpan<const DilithiumSerializedPublicKey>(pk));
}

std::string Dilithium_PublicKey::algo_name() const {
   return object_identifier().to_formatted_string();
}

AlgorithmIdentifier Dilithium_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Dilithium_PublicKey::object_identifier() const {
   return m_public->mode().mode().object_identifier();
}

size_t Dilithium_PublicKey::key_length() const {
   return m_public->mode().canonical_parameter_set_identifier();
}

size_t Dilithium_PublicKey::estimated_strength() const {
   return m_public->mode().lambda();
}

std::vector<uint8_t> Dilithium_PublicKey::raw_public_key_bits() const {
   return m_public->raw_pk().get();
}

std::vector<uint8_t> Dilithium_PublicKey::public_key_bits() const {
   // Currently, there isn't a finalized definition of an ASN.1 structure for
   // Dilithium aka ML-DSA public keys. Therefore, we return the raw public key bits.
   return raw_public_key_bits();
}

bool Dilithium_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   return true;  // ???
}

std::unique_ptr<Private_Key> Dilithium_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Dilithium_PrivateKey>(rng, m_public->mode().mode());
}

std::unique_ptr<PK_Ops::Verification> Dilithium_PublicKey::create_verification_op(std::string_view params,
                                                                                  std::string_view provider) const {
   BOTAN_ARG_CHECK(params.empty() || params == "Pure", "Unexpected parameters for verifying with Dilithium");
   if(provider.empty() || provider == "base") {
      return std::make_unique<Dilithium_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> Dilithium_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& alg_id, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for Dilithium X.509 signature");
      }
      return std::make_unique<Dilithium_Verification_Operation>(m_public);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

namespace Dilithium_Algos {

namespace {

std::pair<DilithiumPolyVec, DilithiumPolyVec> compute_t1_and_t0(const DilithiumPolyMatNTT& A,
                                                                const DilithiumPolyVec& s1,
                                                                const DilithiumPolyVec& s2) {
   auto t_hat = A * ntt(s1.clone());
   t_hat.reduce();
   auto t = inverse_ntt(std::move(t_hat));
   t += s2;
   t.conditional_add_q();

   return Dilithium_Algos::power2round(t);
}

}  // namespace

}  // namespace Dilithium_Algos

/**
 * NIST FIPS 204 IPD, Algorithm 1 (ML-DSA.KeyGen)
 */
Dilithium_PrivateKey::Dilithium_PrivateKey(RandomNumberGenerator& rng, DilithiumMode m) {
   DilithiumConstants mode(m);
   const auto& sympriv = mode.symmetric_primitives();

   const auto xi = rng.random_vec<DilithiumSeedRandomness>(DilithiumConstants::SEED_RANDOMNESS_BYTES);
   auto [rho, rhoprime, key] = sympriv.H(xi);

   const auto A = Dilithium_Algos::expand_A(rho, mode);
   auto [s1, s2] = Dilithium_Algos::expand_s(rhoprime, mode);
   auto [t1, t0] = Dilithium_Algos::compute_t1_and_t0(A, s1, s2);

   m_public = std::make_shared<Dilithium_PublicKeyInternal>(mode, rho, std::move(t1));
   m_private = std::make_shared<Dilithium_PrivateKeyInternal>(
      std::move(mode), std::move(rho), std::move(key), m_public->tr(), std::move(s1), std::move(s2), std::move(t0));
}

Dilithium_PrivateKey::Dilithium_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk) :
      Dilithium_PrivateKey(sk, DilithiumMode(alg_id.oid())) {}

Dilithium_PrivateKey::Dilithium_PrivateKey(std::span<const uint8_t> sk, DilithiumMode m) {
   DilithiumConstants mode(m);
   BOTAN_ARG_CHECK(sk.size() == mode.private_key_bytes(), "dilithium private key does not have the correct byte count");
   m_private =
      Dilithium_PrivateKeyInternal::decode(std::move(mode), StrongSpan<const DilithiumSerializedPrivateKey>(sk));

   // Currently, Botan's Private_Key class inherits from Public_Key, forcing us
   // to derive the public key from the private key here.
   const auto A = Dilithium_Algos::expand_A(m_private->rho(), m_private->mode());
   auto [t1, _] = Dilithium_Algos::compute_t1_and_t0(A, m_private->s1(), m_private->s2());
   m_public = std::make_shared<Dilithium_PublicKeyInternal>(m_private->mode(), m_private->rho(), std::move(t1));

   if(m_public->tr() != m_private->tr()) {
      throw Decoding_Error("Calculated dilithium public key hash does not match the one stored in the private key");
   }
}

secure_vector<uint8_t> Dilithium_PrivateKey::raw_private_key_bits() const {
   return this->private_key_bits();
}

secure_vector<uint8_t> Dilithium_PrivateKey::private_key_bits() const {
   return std::move(m_private->raw_sk().get());
}

std::unique_ptr<PK_Ops::Signature> Dilithium_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                             std::string_view params,
                                                                             std::string_view provider) const {
   BOTAN_UNUSED(rng);

   BOTAN_ARG_CHECK(params.empty() || params == "Deterministic" || params == "Randomized",
                   "Unexpected parameters for signing with Dilithium");

   // TODO: ML-DSA uses the randomized (hedged) variant by default.
   //       We might even drop support for the deterministic variant.
   const bool randomized = (params == "Randomized");
   if(provider.empty() || provider == "base") {
      return std::make_unique<Dilithium_Signature_Operation>(m_private, randomized);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<Public_Key> Dilithium_PrivateKey::public_key() const {
   return std::make_unique<Dilithium_PublicKey>(*this);
}
}  // namespace Botan
