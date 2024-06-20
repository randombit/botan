/*
 * Crystals Kyber key encapsulation mechanism
 * Based on the public domain reference implementation by the
 * designers (https://github.com/pq-crystals/kyber)
 *
 * Further changes
 * (C) 2021-2022 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024      René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/kyber.h>

#include <botan/assert.h>
#include <botan/mem_ops.h>
#include <botan/rng.h>
#include <botan/secmem.h>

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
   #include <botan/internal/kyber_encaps.h>
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
   }

   BOTAN_ASSERT_UNREACHABLE();
}

bool KyberMode::is_90s() const {
   return m_mode == Kyber512_90s || m_mode == Kyber768_90s || m_mode == Kyber1024_90s;
}

bool KyberMode::is_modern() const {
   return !is_90s();
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

   return false;
}

KyberMode Kyber_PublicKey::mode() const {
   return m_public->mode().mode();
}

std::string Kyber_PublicKey::algo_name() const {
   return "Kyber";
}

AlgorithmIdentifier Kyber_PublicKey::algorithm_identifier() const {
   return AlgorithmIdentifier(mode().object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
}

OID Kyber_PublicKey::object_identifier() const {
   return mode().object_identifier();
}

size_t Kyber_PublicKey::estimated_strength() const {
   return m_public->mode().estimated_strength();
}

std::shared_ptr<Kyber_PublicKeyInternal> Kyber_PublicKey::initialize_from_encoding(std::span<const uint8_t> pub_key,
                                                                                   KyberMode m) {
   KyberConstants mode(m);

   if(pub_key.size() != mode.public_key_bytes()) {
      throw Invalid_Argument("kyber public key does not have the correct byte count");
   }

   BufferSlicer s(pub_key);

   auto poly_vec = s.take(mode.polynomial_vector_bytes());
   auto seed = s.copy<KyberSeedRho>(KyberConstants::SEED_BYTES);
   BOTAN_ASSERT_NOMSG(s.empty());

   return std::make_shared<Kyber_PublicKeyInternal>(std::move(mode), poly_vec, std::move(seed));
}

Kyber_PublicKey::Kyber_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      Kyber_PublicKey(key_bits, KyberMode(alg_id.oid())) {}

Kyber_PublicKey::Kyber_PublicKey(std::span<const uint8_t> pub_key, KyberMode m) :
      m_public(initialize_from_encoding(pub_key, m)) {}

Kyber_PublicKey::Kyber_PublicKey(const Kyber_PublicKey& other) :
      m_public(std::make_shared<Kyber_PublicKeyInternal>(*other.m_public)) {}

std::vector<uint8_t> Kyber_PublicKey::raw_public_key_bits() const {
   return m_public->public_key_bits_raw().get();
}

std::vector<uint8_t> Kyber_PublicKey::public_key_bits() const {
   // Currently, there isn't a finalized definition of an ASN.1 structure for
   // Kyber aka ML-KEM public keys. Therefore, we return the raw public key bits.
   return raw_public_key_bits();
}

size_t Kyber_PublicKey::key_length() const {
   // TODO: this should report 512, 768, 1024
   return m_public->mode().public_key_bytes();
}

bool Kyber_PublicKey::check_key(RandomNumberGenerator&, bool) const {
   return true;  // ??
}

std::unique_ptr<Private_Key> Kyber_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Kyber_PrivateKey>(rng, mode());
}

/**
 * NIST FIPS 203 IPD, Algorithms 12 (K-PKE.KeyGen) and 15 (ML-KEM.KeyGen)
 */
Kyber_PrivateKey::Kyber_PrivateKey(RandomNumberGenerator& rng, KyberMode m) {
   KyberConstants mode(m);

   // Algorithm 12 (K-PKE.KeyGen) ----------------

   const auto d = rng.random_vec<KyberSeedRandomness>(KyberConstants::SEED_BYTES);
   auto [rho, sigma] = mode.symmetric_primitives().G(d);
   Kyber_Algos::PolynomialSampler ps(sigma, mode);

   auto A = Kyber_Algos::sample_matrix(rho, false /* not transposed */, mode);
   auto s = ntt(ps.sample_polynomial_vector_cbd_eta1());
   const auto e = ntt(ps.sample_polynomial_vector_cbd_eta1());

   auto t = montgomery(A * s);
   t += e;
   t.reduce();

   // End Algorithm 12 ---------------------------

   m_public = std::make_shared<Kyber_PublicKeyInternal>(mode, std::move(t), std::move(rho));
   m_private = std::make_shared<Kyber_PrivateKeyInternal>(
      std::move(mode), std::move(s), rng.random_vec<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES));
}

Kyber_PrivateKey::Kyber_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits) :
      Kyber_PrivateKey(key_bits, KyberMode(alg_id.oid())) {}

Kyber_PrivateKey::Kyber_PrivateKey(std::span<const uint8_t> sk, KyberMode m) {
   KyberConstants mode(m);

   if(mode.private_key_bytes() != sk.size()) {
      throw Invalid_Argument("kyber private key does not have the correct byte count");
   }

   BufferSlicer s(sk);

   auto skpv = Kyber_Algos::decode_polynomial_vector(s.take(mode.polynomial_vector_bytes()), mode);
   auto pub_key = s.take<KyberSerializedPublicKey>(mode.public_key_bytes());
   auto puk_key_hash = s.take<KyberHashedPublicKey>(KyberConstants::PUBLIC_KEY_HASH_BYTES);
   auto z = s.copy<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES);

   BOTAN_ASSERT_NOMSG(s.empty());

   m_public = initialize_from_encoding(pub_key, m);
   m_private = std::make_shared<Kyber_PrivateKeyInternal>(std::move(mode), std::move(skpv), std::move(z));

   BOTAN_ASSERT(m_private && m_public, "reading private key encoding");
   BOTAN_STATE_CHECK(m_public->H_public_key_bits_raw().size() == puk_key_hash.size() &&
                     std::equal(m_public->H_public_key_bits_raw().begin(),
                                m_public->H_public_key_bits_raw().end(),
                                puk_key_hash.begin()));
}

std::unique_ptr<Public_Key> Kyber_PrivateKey::public_key() const {
   return std::make_unique<Kyber_PublicKey>(*this);
}

secure_vector<uint8_t> Kyber_PrivateKey::raw_private_key_bits() const {
   return this->private_key_bits();
}

secure_vector<uint8_t> Kyber_PrivateKey::private_key_bits() const {
   return concat(
      Kyber_Algos::encode_polynomial_vector<secure_vector<uint8_t>>(m_private->s().reduce(), m_private->mode()),
      m_public->public_key_bits_raw(),
      m_public->H_public_key_bits_raw(),
      m_private->z());
}

std::unique_ptr<PK_Ops::KEM_Encryption> Kyber_PublicKey::create_kem_encryption_op(std::string_view params,
                                                                                  std::string_view provider) const {
   if(provider.empty() || provider == "base") {
#if defined(BOTAN_HAS_KYBER) || defined(BOTAN_HAS_KYBER_90S)
      if(mode().is_kyber_round3()) {
         return std::make_unique<Kyber_KEM_Encryptor>(m_public, params);
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

      BOTAN_ASSERT_UNREACHABLE();
   }
   throw Provider_Not_Found(algo_name(), provider);
}

}  // namespace Botan
