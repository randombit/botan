/*
 * Crystals Kyber key encapsulation mechanism
 * Based on the public domain reference implementation by the
 * designers (https://github.com/pq-crystals/kyber)
 *
 * Further changes
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024      René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/kyber.h>

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/secmem.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/kyber_algos.h>
#include <botan/internal/kyber_constants.h>
#include <botan/internal/kyber_keys.h>
#include <botan/internal/kyber_symmetric_primitives.h>
#include <botan/internal/kyber_types.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_KYBER)
   #include <botan/internal/kyber_modern.h>
#endif

#if defined(BOTAN_HAS_KYBER_90S)
   #include <botan/internal/kyber_90s.h>
#endif

#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
   #include <botan/internal/kyber_round3_impl.h>
#endif

#if defined(BOTAN_HAS_ML_KEM)
   #include <botan/internal/ml_kem_impl.h>
#endif

#include <memory>
#include <vector>

namespace Botan {

namespace {

KyberMode::Mode kyber_mode_from_string(std::string_view str) {
   if(str == "Kyber-512-90s-r3") {
      return KyberMode::Kyber512_90s;
   }
   if(str == "Kyber-768-90s-r3") {
      return KyberMode::Kyber768_90s;
   }
   if(str == "Kyber-1024-90s-r3") {
      return KyberMode::Kyber1024_90s;
   }
   if(str == "Kyber-512-r3") {
      return KyberMode::Kyber512_R3;
   }
   if(str == "Kyber-768-r3") {
      return KyberMode::Kyber768_R3;
   }
   if(str == "Kyber-1024-r3") {
      return KyberMode::Kyber1024_R3;
   }
   if(str == "ML-KEM-512") {
      return KyberMode::ML_KEM_512;
   }
   if(str == "ML-KEM-768") {
      return KyberMode::ML_KEM_768;
   }
   if(str == "ML-KEM-1024") {
      return KyberMode::ML_KEM_1024;
   }

   throw Invalid_Argument(fmt("'{}' is not a valid Kyber mode name", str));
}

}  // namespace

KyberMode::KyberMode(Mode mode) : m_mode(mode) {}

KyberMode::KyberMode(const OID& oid) : m_mode(kyber_mode_from_string(oid.to_formatted_string())) {}

KyberMode::KyberMode(std::string_view str) : m_mode(kyber_mode_from_string(str)) {}

OID KyberMode::object_identifier() const {
   return OID::from_string(to_string());
}

std::string KyberMode::to_string() const {
   switch(m_mode) {
      case Kyber512_90s:
         return "Kyber-512-90s-r3";
      case Kyber768_90s:
         return "Kyber-768-90s-r3";
      case Kyber1024_90s:
         return "Kyber-1024-90s-r3";
      case Kyber512_R3:
         return "Kyber-512-r3";
      case Kyber768_R3:
         return "Kyber-768-r3";
      case Kyber1024_R3:
         return "Kyber-1024-r3";
      case ML_KEM_512:
         return "ML-KEM-512";
      case ML_KEM_768:
         return "ML-KEM-768";
      case ML_KEM_1024:
         return "ML-KEM-1024";
   }

   BOTAN_ASSERT_UNREACHABLE();
}

bool KyberMode::is_90s() const {
   return m_mode == Kyber512_90s || m_mode == Kyber768_90s || m_mode == Kyber1024_90s;
}

bool KyberMode::is_modern() const {
   return !is_90s();
}

bool KyberMode::is_ml_kem() const {
   return m_mode == KyberMode::ML_KEM_512 || m_mode == KyberMode::ML_KEM_768 || m_mode == KyberMode::ML_KEM_1024;
}

bool KyberMode::is_kyber_round3() const {
   return m_mode == KyberMode::Kyber512_R3 || m_mode == KyberMode::Kyber768_R3 || m_mode == KyberMode::Kyber1024_R3 ||
          m_mode == KyberMode::Kyber512_90s || m_mode == KyberMode::Kyber768_90s || m_mode == KyberMode::Kyber1024_90s;
}

bool KyberMode::is_available() const {
#if defined(BOTAN_HAS_KYBER)
   if(is_kyber_round3() && is_modern()) {
      return true;
   }
#endif

#if defined(BOTAN_HAS_KYBER_90S)
   if(is_kyber_round3() && is_90s()) {
      return true;
   }
#endif

#if defined(BOTAN_HAS_ML_KEM)
   if(is_ml_kem()) {
      return true;
   }
#endif

   return false;
}

KyberMode Kyber_PublicKey::mode() const {
   return m_public->mode().mode();
}

std::string Kyber_PublicKey::algo_name() const {
   return mode().is_ml_kem() ? "ML-KEM" : "Kyber";
}

AlgorithmIdentifier Kyber_PublicKey::algorithm_identifier() const {
   // draft-ietf-lamps-kyber-certificates-latest (22 July 2024) The
   //    AlgorithmIdentifier for a ML-KEM public key MUST use one of the
   //    id-alg-ml-kem object identifiers [...]. The parameters field of the
   //    AlgorithmIdentifier for the ML-KEM public key MUST be absent.
   return AlgorithmIdentifier(mode().object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Kyber_PublicKey::object_identifier() const {
   return mode().object_identifier();
}

size_t Kyber_PublicKey::estimated_strength() const {
   return m_public->mode().estimated_strength();
}

Kyber_PublicKey::Kyber_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      Kyber_PublicKey(key_bits, KyberMode(alg_id.oid())) {}

Kyber_PublicKey::Kyber_PublicKey(std::span<const uint8_t> pub_key, KyberMode mode) {
   m_public = std::make_shared<Kyber_PublicKeyInternal>(mode, KyberSerializedPublicKey(pub_key));
}

Kyber_PublicKey::Kyber_PublicKey(const Kyber_PublicKey& other) :
      m_public(std::make_shared<Kyber_PublicKeyInternal>(
         other.m_public->mode(), other.m_public->t().clone(), other.m_public->rho())) {}

std::vector<uint8_t> Kyber_PublicKey::raw_public_key_bits() const {
   return m_public->public_key_bits_raw().get();
}

std::vector<uint8_t> Kyber_PublicKey::public_key_bits() const {
   // Currently, there isn't a finalized definition of an ASN.1 structure for
   // Kyber aka ML-KEM public keys. Therefore, we return the raw public key bits.
   return raw_public_key_bits();
}

size_t Kyber_PublicKey::key_length() const {
   return m_public->mode().canonical_parameter_set_identifier();
}

bool Kyber_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   // The length checks described in FIPS 203, Section 7.2 are already performed
   // while decoding the public key. See constructor of Kyber_PublicKeyInternal.
   // The decoding function KyberAlgos::byte_decode() also checks the range of
   // the decoded values. The check below is added for completeness.

   std::vector<uint8_t> test(m_public->mode().polynomial_vector_bytes());
   Kyber_Algos::encode_polynomial_vector(test, m_public->t());

   const auto& serialized_pubkey = m_public->public_key_bits_raw();
   return test.size() < serialized_pubkey.size() && std::equal(test.begin(), test.end(), serialized_pubkey.begin());
}

std::unique_ptr<Private_Key> Kyber_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Kyber_PrivateKey>(rng, mode());
}

/**
 * NIST FIPS 203, Algorithms 19 (ML-KEM.KeyGen)
 */
Kyber_PrivateKey::Kyber_PrivateKey(RandomNumberGenerator& rng, KyberMode mode) {
   std::tie(m_public, m_private) =
      Kyber_Algos::expand_keypair({rng.random_vec<KyberSeedRandomness>(KyberConstants::SEED_BYTES),
                                   rng.random_vec<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES)},
                                  mode);
}

Kyber_PrivateKey::Kyber_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      Kyber_PrivateKey(key_bits, KyberMode(alg_id.oid())) {}

Kyber_PrivateKey::Kyber_PrivateKey(std::span<const uint8_t> sk, KyberMode m) {
   KyberConstants mode(m);

   if(mode.private_key_bytes() != sk.size()) {
      throw Invalid_Argument("Private key does not have the correct byte count");
   }

   const auto& codec = mode.keypair_codec();
   std::tie(m_public, m_private) = codec.decode_keypair(sk, std::move(mode));
}

std::unique_ptr<Public_Key> Kyber_PrivateKey::public_key() const {
   return std::make_unique<Kyber_PublicKey>(*this);
}

secure_vector<uint8_t> Kyber_PrivateKey::raw_private_key_bits() const {
   return this->private_key_bits();
}

secure_vector<uint8_t> Kyber_PrivateKey::private_key_bits() const {
   return m_private->mode().keypair_codec().encode_keypair({m_public, m_private});
}

bool Kyber_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const {
   // As we do not support loading a private key in extended format but rather
   // always extract it from a 64-byte seed, these checks (as described in
   // FIPS 203, Section 7.1) should never fail. Particularly, the length checks
   // and the hash consistency check described in Section 7.2 and 7.3 are
   // trivial when the private key is always extracted from a seed. The encaps/
   // decaps roundtrip test is added for completeness.

   if(!Kyber_PublicKey::check_key(rng, strong)) {
      return false;
   }

   PK_KEM_Encryptor enc(*this, "Raw");
   PK_KEM_Decryptor dec(*this, rng, "Raw");

   const auto [c, K] = KEM_Encapsulation::destructure(enc.encrypt(rng));
   const auto K_prime = dec.decrypt(c);

   return K == K_prime;
}

std::unique_ptr<PK_Ops::KEM_Encryption> Kyber_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                  std::string_view provider) const {
   if(provider.empty() || provider == "base") {
#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
      if(mode().is_kyber_round3()) {
         return std::make_unique<Kyber_KEM_Encryptor>(m_public, params);
      }
#endif

#if defined(BOTAN_HAS_ML_KEM)
      if(mode().is_ml_kem()) {
         return std::make_unique<ML_KEM_Encryptor>(m_public, params);
      }
#endif

      BOTAN_ASSERT_UNREACHABLE();
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::KEM_Decryption> Kyber_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                                   std::string_view params,
                                                                                   std::string_view provider) const {
   BOTAN_UNUSED(rng);
   if(provider.empty() || provider == "base") {
#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
      if(mode().is_kyber_round3()) {
         return std::make_unique<Kyber_KEM_Decryptor>(m_private, m_public, params);
      }
#endif

#if defined(BOTAN_HAS_ML_KEM)
      if(mode().is_ml_kem()) {
         return std::make_unique<ML_KEM_Decryptor>(m_private, m_public, params);
      }
#endif

      BOTAN_ASSERT_UNREACHABLE();
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
