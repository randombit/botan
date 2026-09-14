/*
 * Crystals Kyber Internal Key Types
 *
 * (C) 2021-2024 Jack Lloyd
 * (C) 2021-2022 Manuel Glaser and Michael Boric, Rohde & Schwarz Cybersecurity
 * (C) 2021-2022 René Meusel and Hannes Rantzsch, neXenio GmbH
 * (C) 2024 René Meusel, Fabian Albert, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/kyber_keys.h>

#include <botan/asn1_obj.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/buffer_slicer.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/kyber_symmetric_primitives.h>

namespace Botan {

namespace {

KyberSerializedPublicKey validate_public_key_length(KyberSerializedPublicKey public_key, size_t expected_length) {
   if(public_key.size() != expected_length) {
      throw Invalid_Argument("Public key does not have the correct byte count");
   }
   return public_key;
}

}  // namespace

/**
 * Key decoding as specified in Crystals Kyber (Version 3.01),
 * Algorithms 4 (CPAPKE.KeyGen()), and 7 (CCAKEM.KeyGen())
 *
 * Public Key: pk  := (encode(t) || rho)
 * Secret Key: sk' := encode(s)
 *
 * Expanded Secret Key: sk  := (sk' || pk || H(pk) || z)
 */
KyberInternalKeypair Expanded_Keypair_Codec::decode_keypair(std::span<const uint8_t> sk, KyberConstants mode) const {
   auto scope = CT::scoped_poison(sk);
   BufferSlicer s(sk);

   auto skpv = Kyber_Algos::decode_polynomial_vector(s.take(mode.polynomial_vector_bytes()), mode);
   auto pub_key = s.copy<KyberSerializedPublicKey>(mode.public_key_bytes());
   auto puk_key_hash = s.take<KyberHashedPublicKey>(KyberConstants::PUBLIC_KEY_HASH_BYTES);
   auto z = s.copy<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES);

   BOTAN_ASSERT_NOMSG(s.empty());

   CT::unpoison_all(pub_key, puk_key_hash, skpv, z);

   KyberInternalKeypair keypair{
      std::make_shared<Kyber_PublicKeyInternal>(mode, std::move(pub_key)),
      std::make_shared<Kyber_PrivateKeyInternal>(
         std::move(mode),
         std::move(skpv),
         KyberPrivateKeySeed{std::nullopt,  // Reading from an expanded and encoded
                             // private key cannot reconstruct the
                             // original seed from key generation.
                             std::move(z)}),
   };

   BOTAN_ASSERT(keypair.first && keypair.second, "reading private key encoding");
   if(keypair.first->H_public_key_bits_raw().size() != puk_key_hash.size() ||
      !std::equal(keypair.first->H_public_key_bits_raw().begin(),
                  keypair.first->H_public_key_bits_raw().end(),
                  puk_key_hash.begin())) {
      throw Decoding_Error("public key's hash does not match the stored hash");
   }

   {
      // Pairwise consistency check: the hash check above does not detect a
      // secret vector s that does not belong to the public key (see RFC 9935,
      // Appendix C.4, example 2). A deterministic K-PKE encryption of an
      // arbitrary message with the public key must decrypt correctly with s.
      const auto& pk = *keypair.first;
      const auto& priv = *keypair.second;
      const auto& sym = pk.mode().symmetric_primitives();
      const auto& pk_hash = pk.H_public_key_bits_raw();
      const KyberMessage m(secure_vector<uint8_t>(pk_hash.begin(), pk_hash.end()));
      const auto [K, r] = sym.G(m, pk_hash);
      BOTAN_UNUSED(K);
      const auto At = Kyber_Algos::sample_matrix(pk.rho(), true /* transposed */, pk.mode());
      const auto ct = pk.indcpa_encrypt(m, r, At, pk.mode());
      const auto m_prime = priv.indcpa_decrypt(ct);
      if(m_prime.size() != m.size() || !constant_time_compare(m_prime, m)) {
         throw Decoding_Error("ML-KEM expanded private key is inconsistent with its public key");
      }
   }

   return keypair;
}

secure_vector<uint8_t> Expanded_Keypair_Codec::encode_keypair(KyberInternalKeypair keypair) const {
   BOTAN_ASSERT_NONNULL(keypair.first);
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& mode = keypair.first->mode();
   auto scope = CT::scoped_poison(*keypair.second);
   auto result = concat(Kyber_Algos::encode_polynomial_vector(keypair.second->s(), mode),
                        keypair.first->public_key_bits_raw(),
                        keypair.first->H_public_key_bits_raw(),
                        keypair.second->z());
   CT::unpoison(result);
   return result;
}

KyberInternalKeypair Seed_Expanding_Keypair_Codec::decode_keypair(std::span<const uint8_t> private_key,
                                                                  KyberConstants mode) const {
   BufferSlicer s(private_key);
   auto seed = KyberPrivateKeySeed{
      s.copy<KyberSeedRandomness>(KyberConstants::SEED_BYTES),
      s.copy<KyberImplicitRejectionValue>(KyberConstants::SEED_BYTES),
   };
   BOTAN_ASSERT_NOMSG(s.empty());
   return Kyber_Algos::expand_keypair(std::move(seed), std::move(mode));
}

secure_vector<uint8_t> Seed_Expanding_Keypair_Codec::encode_keypair(KyberInternalKeypair keypair) const {
   BOTAN_ASSERT_NONNULL(keypair.second);
   const auto& seed = keypair.second->seed();
   BOTAN_ARG_CHECK(seed.d.has_value(), "Cannot encode keypair without the full private seed");
   return concat<secure_vector<uint8_t>>(seed.d.value(), seed.z);
}

namespace {

KyberInternalKeypair decode_ml_kem_seed(std::span<const uint8_t> seed, KyberConstants mode) {
   if(seed.size() != mode.seed_private_key_bytes()) {
      throw Decoding_Error("invalid length of ML-KEM private key seed");
   }
   return Seed_Expanding_Keypair_Codec().decode_keypair(seed, std::move(mode));
}

KyberInternalKeypair decode_ml_kem_expanded(std::span<const uint8_t> expanded, KyberConstants mode) {
   if(expanded.size() != mode.expanded_private_key_bytes()) {
      throw Decoding_Error("invalid length of ML-KEM expanded private key");
   }
   return Expanded_Keypair_Codec().decode_keypair(expanded, std::move(mode));
}

}  // namespace

KyberDecodedKeypair decode_ml_kem_private_key(std::span<const uint8_t> private_key, KyberConstants mode) {
   BOTAN_ARG_CHECK(mode.mode().is_ml_kem(), "RFC 9935 private key encodings are only defined for ML-KEM");

   if(private_key.size() == mode.seed_private_key_bytes()) {
      // backwards compatibility (not RFC 9935 conforming) to the raw seed d || z
      return {decode_ml_kem_seed(private_key, std::move(mode)), MlPrivateKeyFormat::Seed};
   }
   if(private_key.size() == mode.expanded_private_key_bytes()) {
      // raw expanded key in the FIPS 203 dk encoding without ASN.1 wrapping (not RFC 9935
      // conforming), as used e.g. by the NIST ACVP and Wycheproof test vectors. The length
      // cannot collide with any of the RFC 9935 encodings.
      return {decode_ml_kem_expanded(private_key, std::move(mode)), MlPrivateKeyFormat::Expanded};
   }

   // RFC 9935, Section 6: the ASN.1 tag identifies the CHOICE alternative
   const auto obj = [&]() {
      try {
         return BER_Decoder(private_key).peek_next_object();
      } catch(const Decoding_Error&) {
         throw Decoding_Error("Invalid ML-KEM private key encoding");
      }
   }();

   if(obj.type() == ASN1_Type(0) && obj.class_tag() == ASN1_Class::ContextSpecific) {
      // "seed" alternative: [0] IMPLICIT OCTET STRING
      secure_vector<uint8_t> seed;
      BER_Decoder(private_key)
         .decode(seed, ASN1_Type::OctetString, ASN1_Type(0), ASN1_Class::ContextSpecific)
         .verify_end();
      return {decode_ml_kem_seed(seed, std::move(mode)), MlPrivateKeyFormat::Seed};
   }
   if(obj.type() == ASN1_Type::OctetString && obj.class_tag() == ASN1_Class::Universal) {
      // "expandedKey" alternative: OCTET STRING
      secure_vector<uint8_t> expanded;
      BER_Decoder(private_key).decode(expanded, ASN1_Type::OctetString).verify_end();
      return {decode_ml_kem_expanded(expanded, std::move(mode)), MlPrivateKeyFormat::Expanded};
   }
   if(obj.type() == ASN1_Type::Sequence && obj.class_tag() == ASN1_Class::Constructed) {
      // "both" alternative: SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
      secure_vector<uint8_t> seed;
      secure_vector<uint8_t> expanded;
      BER_Decoder(private_key)
         .start_sequence()
         .decode(seed, ASN1_Type::OctetString)
         .decode(expanded, ASN1_Type::OctetString)
         .end_cons()
         .verify_end();
      if(expanded.size() != mode.expanded_private_key_bytes()) {
         throw Decoding_Error("invalid length of ML-KEM expanded private key");
      }
      // RFC 9935, Section 8: the expanded key must be the expansion of the seed
      auto keypair = decode_ml_kem_seed(seed, std::move(mode));
      const auto expanded_from_seed = Expanded_Keypair_Codec().encode_keypair(keypair);
      if(expanded_from_seed.size() != expanded.size() || !constant_time_compare(expanded_from_seed, expanded)) {
         throw Decoding_Error("seed and expanded key in ML-KEM private key do not match");
      }
      return {std::move(keypair), MlPrivateKeyFormat::Both};
   }

   throw Decoding_Error("Invalid ML-KEM private key encoding");
}

secure_vector<uint8_t> encode_ml_kem_private_key(const KyberInternalKeypair& keypair, MlPrivateKeyFormat format) {
   BOTAN_ASSERT_NONNULL(keypair.second);
   BOTAN_ARG_CHECK(keypair.second->mode().mode().is_ml_kem(),
                   "RFC 9935 private key encodings are only defined for ML-KEM");
   if(format != MlPrivateKeyFormat::Expanded && !keypair.second->seed().d.has_value()) {
      throw Encoding_Error("ML-KEM private key does not contain the seed, cannot encode it in the requested format");
   }

   secure_vector<uint8_t> result;
   DER_Encoder der_enc(result);
   switch(format) {
      case MlPrivateKeyFormat::Seed:
         // RFC 9935 "seed" CHOICE alternative: [0] IMPLICIT OCTET STRING
         der_enc.encode(Seed_Expanding_Keypair_Codec().encode_keypair(keypair),
                        ASN1_Type::OctetString,
                        ASN1_Type(0),
                        ASN1_Class::ContextSpecific);
         break;
      case MlPrivateKeyFormat::Expanded:
         // RFC 9935 "expandedKey" CHOICE alternative: OCTET STRING
         der_enc.encode(Expanded_Keypair_Codec().encode_keypair(keypair), ASN1_Type::OctetString);
         break;
      case MlPrivateKeyFormat::Both:
         // RFC 9935 "both" CHOICE alternative:
         // SEQUENCE { seed OCTET STRING, expandedKey OCTET STRING }
         der_enc.start_sequence()
            .encode(Seed_Expanding_Keypair_Codec().encode_keypair(keypair), ASN1_Type::OctetString)
            .encode(Expanded_Keypair_Codec().encode_keypair(keypair), ASN1_Type::OctetString)
            .end_cons();
         break;
   }

   return result;
}

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, KyberSerializedPublicKey public_key) :
      m_mode(std::move(mode)),
      m_public_key_bits_raw(validate_public_key_length(std::move(public_key), m_mode.public_key_bytes())),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)),
      m_t(Kyber_Algos::decode_polynomial_vector(
         std::span{m_public_key_bits_raw}.first(m_mode.polynomial_vector_bytes()), m_mode)),
      m_rho(std::span{m_public_key_bits_raw}.last(Botan::KyberConstants::SEED_BYTES)) {}

Kyber_PublicKeyInternal::Kyber_PublicKeyInternal(KyberConstants mode, KyberPolyVecNTT t, KyberSeedRho rho) :
      m_mode(std::move(mode)),
      m_public_key_bits_raw(concat(Kyber_Algos::encode_polynomial_vector<std::vector<uint8_t>>(t, m_mode), rho)),
      m_H_public_key_bits_raw(m_mode.symmetric_primitives().H(m_public_key_bits_raw)),
      m_t(std::move(t)),
      m_rho(std::move(rho)) {}

/**
 * NIST FIPS 203, Algorithm 14 (K-PKE.Encrypt)
 *
 * In contrast to FIPS 203, the matrix @p At is not sampled for every invocation,
 * instead it is precomputed and passed in as a parameter. Similarly, the t^T is
 * already decoded and available as a member variable. This allows to reuse these
 * structures for multiple encryptions.
 *
 * The sampling loops spelled out in FIPS 203 are hidden in the sample_* functions.
 */
void Kyber_PublicKeyInternal::indcpa_encrypt(StrongSpan<KyberCompressedCiphertext> out_ct,
                                             StrongSpan<const KyberMessage> m,
                                             StrongSpan<const KyberEncryptionRandomness> r,
                                             const KyberPolyMat& At,
                                             const KyberConstants& mode) const {
   // The nonce N is handled internally by the PolynomialSampler
   Kyber_Algos::PolynomialSampler ps(r, mode);
   const auto y = ntt(ps.sample_polynomial_vector_cbd_eta1());
   const auto [e1, e2] = ps.sample_polynomial_vector_and_poly_cbd_eta2();

   auto u = inverse_ntt(At * y);
   u += e1;
   u.reduce();

   const auto mu = Kyber_Algos::polynomial_from_message(m);
   auto v = inverse_ntt(m_t * y);
   v += e2;
   v += mu;
   v.reduce();

   Kyber_Algos::compress_ciphertext(out_ct, u, v, m_mode);
}

/**
 * NIST FIPS 203, Algorithm 15 (K-PKE.Decrypt)
 *
 * s^T is already decoded and available as a member variable. This allows to reuse
 * the structure for multiple decryptions.
 */
KyberMessage Kyber_PrivateKeyInternal::indcpa_decrypt(StrongSpan<const KyberCompressedCiphertext> ct) const {
   auto [u, v] = Kyber_Algos::decompress_ciphertext(ct, m_mode);
   v -= inverse_ntt(m_s * ntt(std::move(u)));
   v.reduce();
   return Kyber_Algos::polynomial_to_message(v);
}

}  // namespace Botan
