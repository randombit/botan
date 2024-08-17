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
#include <botan/internal/dilithium_keys.h>
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
   if(str == "ML-DSA-4x4") {
      return DilithiumMode::ML_DSA_4x4;
   }
   if(str == "ML-DSA-6x5") {
      return DilithiumMode::ML_DSA_6x5;
   }
   if(str == "ML-DSA-8x7") {
      return DilithiumMode::ML_DSA_8x7;
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
      case DilithiumMode::ML_DSA_4x4:
         return "ML-DSA-4x4";
      case DilithiumMode::ML_DSA_6x5:
         return "ML-DSA-6x5";
      case DilithiumMode::ML_DSA_8x7:
         return "ML-DSA-8x7";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

bool DilithiumMode::is_aes() const {
   return m_mode == Dilithium4x4_AES || m_mode == Dilithium6x5_AES || m_mode == Dilithium8x7_AES;
}

bool DilithiumMode::is_modern() const {
   return !is_aes();
}

bool DilithiumMode::is_ml_dsa() const {
   return m_mode == ML_DSA_4x4 || m_mode == ML_DSA_6x5 || m_mode == ML_DSA_8x7;
}

bool DilithiumMode::is_available() const {
#if defined(BOTAN_HAS_DILITHIUM_AES)
   if(is_dilithium_round3() && is_aes()) {
      return true;
   }
#endif
#if defined(BOTAN_HAS_DILITHIUM)
   if(is_dilithium_round3() && is_modern()) {
      return true;
   }
#endif
#if defined(BOTAN_HAS_ML_DSA)
   if(is_ml_dsa()) {
      return true;
   }
#endif
   return false;
}

namespace {

// Return true if randomized signatures were requested
bool check_dilithium_options(const PK_Signature_Options& options) {
   BOTAN_ARG_CHECK(options.hash_function().empty(), "Dilithium does not allow specifying the hash function");
   BOTAN_ARG_CHECK(!options.using_padding(), "Dilithium does not support padding");

   // This is available in ML-DSA and might be supported in the future
   BOTAN_ARG_CHECK(!options.using_prehash(), "Dilithium does not support prehashing");

   // FIPS 204, Section 3.4
   //   By default, this standard specifies the signing algorithm to use both
   //   types of randomness [fresh from the RNG and a value in the private key].
   //   This is referred to as the “hedged” variant of the signing procedure.
   return !options.using_deterministic_signature();
}

class Dilithium_Signature_Operation final : public PK_Ops::Signature {
   public:
      Dilithium_Signature_Operation(DilithiumInternalKeypair keypair, const PK_Signature_Options& options) :
            m_keypair(std::move(keypair)),
            m_randomized(check_dilithium_options(options)),
            m_h(m_keypair.second->mode().symmetric_primitives().get_message_hash(m_keypair.first->tr())),
            m_s1(ntt(m_keypair.second->s1().clone())),
            m_s2(ntt(m_keypair.second->s2().clone())),
            m_t0(ntt(m_keypair.second->t0().clone())),
            m_A(Dilithium_Algos::expand_A(m_keypair.first->rho(), m_keypair.second->mode())) {}

      void update(std::span<const uint8_t> input) override { m_h->update(input); }

      /**
       * NIST FIPS 204, Algorithm 2 (ML-DSA.Sign) and Algorithm 7 (ML-DSA.Sign_internal)
       *
       * Note that the private key decoding is done ahead of time. Also, the
       * matrix expansion of A from 'rho' along with the NTT-transforms of s1,
       * s2 and t0 are done in the constructor of this class, as a 'signature
       * operation' may be used to sign multiple messages.
       *
       * TODO: Implement support for the specified 'ctx' context string which is
       *       application defined and "empty" by default and <= 255 bytes long.
       */
      std::vector<uint8_t> sign(RandomNumberGenerator& rng) override {
         auto scope = CT::scoped_poison(*m_keypair.second);

         const auto mu = m_h->final();
         const auto& mode = m_keypair.second->mode();
         const auto& sympri = mode.symmetric_primitives();

         const auto rhoprime = sympri.H_maybe_randomized(m_keypair.second->signing_seed(), mu, maybe(rng));
         CT::poison(rhoprime);

         for(uint16_t nonce = 0, n = 0; n <= DilithiumConstants::SIGNING_LOOP_BOUND; ++n, nonce += mode.l()) {
            const auto y = Dilithium_Algos::expand_mask(rhoprime, nonce, mode);

            auto w_ntt = m_A * ntt(y.clone());
            w_ntt.reduce();
            auto w = inverse_ntt(std::move(w_ntt));
            w.conditional_add_q();

            auto [w1, w0] = Dilithium_Algos::decompose(w, mode);
            const auto ch = CT::driveby_unpoison(sympri.H(mu, Dilithium_Algos::encode_commitment(w1, mode)));

            const auto c = ntt(Dilithium_Algos::sample_in_ball(ch, mode));
            const auto cs1 = inverse_ntt(c * m_s1);
            auto z = y + cs1;
            z.reduce();

            // We validate the infinity norm of z before proceeding to calculate cs2
            if(!Dilithium_Algos::infinity_norm_within_bound(z, to_underlying(mode.gamma1()) - mode.beta())) {
               continue;
            }
            CT::unpoison(z);  // part of the signature

            const auto cs2 = inverse_ntt(c * m_s2);

            // Note: w0 is used as a scratch space for calculation. We're aliasing
            //       the results to const&'s merely to communicate which value the
            //       intermediate results represent in the specification.
            w0 -= cs2;
            w0.reduce();
            const auto& r0 = w0;
            if(!Dilithium_Algos::infinity_norm_within_bound(r0, to_underlying(mode.gamma2()) - mode.beta())) {
               continue;
            }

            auto ct0 = inverse_ntt(c * m_t0);
            ct0.reduce();
            // We validate the infinity norm of ct0 before proceeding to calculate the hint.
            if(!Dilithium_Algos::infinity_norm_within_bound(ct0, mode.gamma2())) {
               continue;
            }

            w0 += ct0;
            w0.conditional_add_q();
            const auto& w0cs2ct0 = w0;

            const auto hint = Dilithium_Algos::make_hint(w0cs2ct0, w1, mode);
            if(CT::driveby_unpoison(hint.hamming_weight()) > mode.omega()) {
               continue;
            }
            CT::unpoison(hint);  // part of the signature

            return Dilithium_Algos::encode_signature(ch, z, hint, mode).get();
         }

         throw Internal_Error("ML-DSA/Dilithium signature loop did not terminate");
      }

      size_t signature_length() const override { return m_keypair.second->mode().signature_bytes(); }

      AlgorithmIdentifier algorithm_identifier() const override {
         return AlgorithmIdentifier(m_keypair.second->mode().mode().object_identifier(),
                                    AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      std::string hash_function() const override { return m_h->name(); }

   private:
      std::optional<std::reference_wrapper<RandomNumberGenerator>> maybe(RandomNumberGenerator& rng) const {
         if(m_randomized) {
            return rng;
         } else {
            return std::nullopt;
         }
      }

   private:
      DilithiumInternalKeypair m_keypair;
      bool m_randomized;
      std::unique_ptr<DilithiumMessageHash> m_h;

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

      void update(std::span<const uint8_t> input) override { m_h->update(input); }

      /**
       * NIST FIPS 204, Algorithm 3 (ML-DSA.Verify) and 8 (ML-DSA.Verify_internal)
       *
       * Note that the public key decoding is done ahead of time. Also, the
       * matrix A is expanded from 'rho' in the constructor of this class, as
       * a 'verification operation' may be used to verify multiple signatures.
       *
       * TODO: Implement support for the specified 'ctx' context string which is
       *       application defined and "empty" by default and <= 255 bytes long.
       */
      bool is_valid_signature(std::span<const uint8_t> sig) override {
         const auto& mode = m_pub_key->mode();
         const auto& sympri = mode.symmetric_primitives();
         StrongSpan<const DilithiumSerializedSignature> sig_bytes(sig);

         if(sig_bytes.size() != mode.signature_bytes()) {
            return false;
         }

         const auto mu = m_h->final();

         auto signature = Dilithium_Algos::decode_signature(sig_bytes, mode);
         if(!signature.has_value()) {
            return false;
         }
         auto [ch, z, h] = std::move(signature.value());

         // TODO: The first check was removed from the final version of ML-DSA
         if(h.hamming_weight() > mode.omega() ||
            !Dilithium_Algos::infinity_norm_within_bound(z, to_underlying(mode.gamma1()) - mode.beta())) {
            return false;
         }

         const auto c_hat = ntt(Dilithium_Algos::sample_in_ball(ch, mode));
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

      std::string hash_function() const override { return m_h->name(); }

   private:
      std::shared_ptr<Dilithium_PublicKeyInternal> m_pub_key;
      DilithiumPolyMatNTT m_A;
      DilithiumPolyVecNTT m_t1_ntt_shifted;
      std::unique_ptr<DilithiumMessageHash> m_h;
};

}  // namespace

Dilithium_PublicKey::Dilithium_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk) :
      Dilithium_PublicKey(pk, DilithiumMode(alg_id.oid())) {}

Dilithium_PublicKey::Dilithium_PublicKey(std::span<const uint8_t> pk, DilithiumMode m) {
   DilithiumConstants mode(m);
   BOTAN_ARG_CHECK(mode.mode().is_available(), "Dilithium/ML-DSA mode is not available in this build");
   BOTAN_ARG_CHECK(pk.empty() || pk.size() == mode.public_key_bytes(),
                   "dilithium public key does not have the correct byte count");

   m_public = Dilithium_PublicKeyInternal::decode(std::move(mode), StrongSpan<const DilithiumSerializedPublicKey>(pk));
}

std::string Dilithium_PublicKey::algo_name() const {
   // Note: For Dilithium we made the blunder to return the OID's human readable
   //       name, e.g. "Dilithium-4x4-AES". This is inconsistent with the other
   //       public key algorithms which return the generic name only.
   //
   // TODO(Botan4): Fix the inconsistency described above, also considering that
   //               there might be other code locations that identify Dilithium
   //               by std::string::starts_with("Dilithium-").
   //               (Above assumes that Dilithium won't be removed entirely!)
   return (m_public->mode().is_ml_dsa()) ? std::string("ML-DSA") : object_identifier().to_formatted_string();
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

/**
 * NIST FIPS 204, Algorithm 1 (ML-DSA.KeyGen), and 6 (ML-DSA.KeyGen_internal)
 *
 * This integrates the seed generation and the actual key generation into one
 * function. After generation, the relevant components of the key are kept in
 * memory; the key encoding is deferred until explicitly requested.
 *
 * The calculation of (t1, t0) is done in a separate function, as it is also
 * needed for the decoding of a private key.
 */
Dilithium_PrivateKey::Dilithium_PrivateKey(RandomNumberGenerator& rng, DilithiumMode m) {
   DilithiumConstants mode(m);
   BOTAN_ARG_CHECK(mode.mode().is_available(), "Dilithium/ML-DSA mode is not available in this build");
   std::tie(m_public, m_private) = Dilithium_Algos::expand_keypair(
      rng.random_vec<DilithiumSeedRandomness>(DilithiumConstants::SEED_RANDOMNESS_BYTES), std::move(mode));
}

Dilithium_PrivateKey::Dilithium_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk) :
      Dilithium_PrivateKey(sk, DilithiumMode(alg_id.oid())) {}

Dilithium_PrivateKey::Dilithium_PrivateKey(std::span<const uint8_t> sk, DilithiumMode m) {
   DilithiumConstants mode(m);
   auto& codec = mode.keypair_codec();
   std::tie(m_public, m_private) = codec.decode_keypair(sk, std::move(mode));
}

secure_vector<uint8_t> Dilithium_PrivateKey::raw_private_key_bits() const {
   return this->private_key_bits();
}

secure_vector<uint8_t> Dilithium_PrivateKey::private_key_bits() const {
   return m_private->mode().keypair_codec().encode_keypair({m_public, m_private});
}

std::unique_ptr<PK_Ops::Signature> Dilithium_PrivateKey::_create_signature_op(
   RandomNumberGenerator& rng, const PK_Signature_Options& options) const {
   BOTAN_UNUSED(rng);

   if(!options.using_provider()) {
      return std::make_unique<Dilithium_Signature_Operation>(DilithiumInternalKeypair{m_public, m_private}, options);
   }
   throw Provider_Not_Found(algo_name(), options.provider().value());
}

std::unique_ptr<Public_Key> Dilithium_PrivateKey::public_key() const {
   return std::make_unique<Dilithium_PublicKey>(*this);
}
}  // namespace Botan
