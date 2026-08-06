/*
 * ML-KEM Composite KEM
 * (C) 2026 Falko Strenzke, MTG AG
 *     2026 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/ml_kem.h>
#include <botan/mlkem_comp.h>
#include <botan/oids.h>
#include <botan/pk_algs.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/internal/asymmetric_encryption_to_kem_adapter.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hybrid_kem_ops.h>
#include <botan/internal/kex_to_kem_adapter.h>

#if defined(BOTAN_HAS_ECDH)
   #include <botan/ec_group.h>
   #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif
#if defined(BOTAN_HAS_X448)
   #include <botan/x448.h>
#endif

#include <memory>
#include <string_view>
#include <vector>

namespace Botan {

namespace {

std::span<const uint8_t> mlkem_pubkey_subspan(const MLKEM_Composite_Param& param, std::span<const uint8_t> key_bits) {
   if(key_bits.size() <= param.mlkem_pubkey_size()) {
      throw Invalid_Argument(fmt("encoded MLKEM component public key is too short (len = {})", key_bits.size()));
   }
   return key_bits.first(param.mlkem_pubkey_size());
}

std::span<const uint8_t> mlkem_privkey_subspan(const MLKEM_Composite_Param& param, std::span<const uint8_t> key_bits) {
   if(key_bits.size() <= param.mlkem_privkey_size()) {
      throw Invalid_Argument("encoded MLKEM component private key is too short");
   }
   return key_bits.first(param.mlkem_privkey_size());
}

std::span<const uint8_t> traditional_pubkey_subspan(const MLKEM_Composite_Param& param,
                                                    std::span<const uint8_t> key_bits) {
   const size_t offset = param.mlkem_pubkey_size();
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument(fmt("encoded traditional component public key is too short (len = {})", key_bits.size()));
   }
   return key_bits.subspan(offset);
}

std::span<const uint8_t> traditional_privkey_subspan(const MLKEM_Composite_Param& param,
                                                     std::span<const uint8_t> key_bits) {
   const size_t offset = param.mlkem_privkey_size();
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument("encoded traditional component private key is too short");
   }
   return key_bits.subspan(offset);
}

std::unique_ptr<Private_Key> maybe_wrap_traditional_private_key(const MLKEM_Composite_Param& param,
                                                                std::unique_ptr<Private_Key> sk) {
   if(param.traditional_algorithm() == "RSA") {
      return std::make_unique<Botan::Asymmetric_Encryption_to_KEM_Adapter_PrivateKey>(std::move(sk),
                                                                                      param.traditional_padding());
   } else {
      // Other traditional non-KEM algorithms (e.g., ECDH) are handled by the
      // Hybrid_KEM_PrivateKey interface, so explicit wrapping is needed for
      // RSA only.
      return sk;
   }
}

std::unique_ptr<Public_Key> maybe_wrap_traditional_public_key(const MLKEM_Composite_Param& param,
                                                              std::unique_ptr<Public_Key> pk) {
   if(param.traditional_algorithm() == "RSA") {
      return std::make_unique<Botan::Asymmetric_Encryption_to_KEM_Adapter_PublicKey>(std::move(pk),
                                                                                     param.traditional_padding());
   } else {
      // Other traditional non-KEM algorithms (e.g., ECDH) are handled by the
      // Hybrid_KEM_PublicKey interface, so explicit wrapping is needed for
      // RSA only.
      return pk;
   }
}

std::unique_ptr<Public_Key> load_traditional_public_key(const MLKEM_Composite_Param& param,
                                                        std::span<const uint8_t> key_bits) {
#if defined(BOTAN_HAS_ECDH)
   if(param.traditional_algorithm() == "ECDH") {
      const auto group = Botan::EC_Group::from_name(param.curve());
      return std::make_unique<Botan::ECDH_PublicKey>(group, EC_AffinePoint(group, key_bits));
   }
#endif
   return load_public_key(param.get_traditional_algorithm_id(), key_bits);
}

PairOfPublicKeys load_public_keys(const MLKEM_Composite_Param& param, std::span<const uint8_t> key_bits) {
   const auto mlkem_pubkey_bits = mlkem_pubkey_subspan(param, key_bits);
   const auto trad_pubkey_bits = traditional_pubkey_subspan(param, key_bits);

   return {
      load_public_key(param.get_mlkem_algorithm_id(), mlkem_pubkey_bits),
      maybe_wrap_traditional_public_key(param, load_traditional_public_key(param, trad_pubkey_bits)),
   };
}

std::unique_ptr<Private_Key> load_traditional_private_key(MLKEM_Composite_Param param,
                                                          std::span<const uint8_t> key_bits) {
   // X25519/X448 are encoded as raw values, hence the need special handling here.
#if defined(BOTAN_HAS_X25519)
   if(param.traditional_algorithm() == "X25519") {
      return std::make_unique<X25519_PrivateKey>(key_bits);
   }
#endif
#if defined(BOTAN_HAS_X448)
   if(param.traditional_algorithm() == "X448") {
      return std::make_unique<X448_PrivateKey>(key_bits);
   }
#endif

   return load_private_key(param.get_traditional_algorithm_id(), key_bits);
}

PairOfPrivateKeys load_private_keys(const MLKEM_Composite_Param& param, std::span<const uint8_t> key_bits) {
   const auto mlkem_privkey_bits = mlkem_privkey_subspan(param, key_bits);
   const auto trad_privkey_bits = traditional_privkey_subspan(param, key_bits);

   return {
      load_private_key(param.get_mlkem_algorithm_id(), mlkem_privkey_bits),
      maybe_wrap_traditional_private_key(param, load_traditional_private_key(param, trad_privkey_bits)),
   };
}

secure_vector<uint8_t> encode_traditional_private_key(const MLKEM_Composite_Param& params, const Private_Key& trad_sk) {
   if(params.traditional_algorithm() == "ECDH") {
      /* For ML-KEM hybrid, we MUST encode this private key format
       * ( defined in https://www.rfc-editor.org/info/rfc5915/#section-3 and
       * further restricted in https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-kem-14.html#section-4-6.3.1 )
       *
       * SEQUENCE {
       * INTEGER 1
       * OCTET STRING
       *   B9 4E 76 09 A7 17 6A BA FB D4 A3 4F AB AE 42 B0
       *   91 E4 4D 9E 46 E6 7F CA 56 6C 2A 18 8A 63 C6 5F
       * [0] {
       *   OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
       *   }
       * } */
      const OID oid = OIDS::str2oid_or_empty(params.curve());
      BOTAN_ASSERT(!oid.empty(), "lookup of MLKEM-composite elliptic curve OID");
      return DER_Encoder()
         .start_sequence()
         .encode(static_cast<size_t>(1))
         .encode(trad_sk.raw_private_key_bits(), ASN1_Type::OctetString)
         .start_explicit_context_specific(0)
         .encode(oid)
         .end_cons()
         .end_cons()
         .get_contents();
   } else if(params.traditional_algorithm() == "X25519" || params.traditional_algorithm() == "X448") {
      return trad_sk.raw_private_key_bits();
   } else {
      return trad_sk.private_key_bits();
   }
}

std::unique_ptr<Private_Key> create_traditional_private_key(RandomNumberGenerator& rng, MLKEM_Composite_Param param) {
#if defined(BOTAN_HAS_ECDH)
   if(param.traditional_algorithm() == "ECDH") {
      const auto group = Botan::EC_Group::from_name(param.curve());
      return std::make_unique<Botan::ECDH_PrivateKey>(rng, group);
   }
#endif
   return create_private_key(param.traditional_algorithm(), rng, param.get_traditional_algo_param_str());
}

PairOfPrivateKeys create_private_keys(MLKEM_Composite_Param param, RandomNumberGenerator& rng) {
   return {
      std::make_unique<ML_KEM_PrivateKey>(rng, ML_KEM_Mode(param.get_mlkem_mode())),
      maybe_wrap_traditional_private_key(param, create_traditional_private_key(rng, param)),
   };
}

void combiner(std::span<uint8_t> out_shared_secret,
              const PairOfSharedSecrets& ss,
              const PairOfCiphertexts& ct,
              std::span<const uint8_t> traditional_pubkey_encoded,
              std::string_view label) {
   const auto sha3_256 = Botan::HashFunction::create_or_throw("SHA-3(256)");
   sha3_256->update(ss.first);
   sha3_256->update(ss.second);
   sha3_256->update(ct.second);
   sha3_256->update(traditional_pubkey_encoded);
   sha3_256->update(label);
   sha3_256->final(out_shared_secret);
}

class MLKEM_Composite_Encapsulation_Operation final : public KEM_Encryption_with_Combiner {
   public:
      MLKEM_Composite_Encapsulation_Operation(const PairOfPublicKeys& public_keys,
                                              std::string label,
                                              std::string_view provider) :
            KEM_Encryption_with_Combiner(public_keys, provider),
            m_traditional_pubkey_encoded(public_keys.second->public_key_bits()),
            m_label(std::move(label)) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const PairOfSharedSecrets& ss,
                                  const PairOfCiphertexts& ct,
                                  size_t /* desired_shared_key_len */,
                                  std::span<const uint8_t> /* salt */) override {
         combiner(out_shared_secret, ss, ct, m_traditional_pubkey_encoded, m_label);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override {
         return 32;  // output length of SHA-3(256)
      }

   private:
      std::vector<uint8_t> m_traditional_pubkey_encoded;
      std::string m_label;
};

class MLKEM_Composite_Decapsulation_Operation final : public KEM_Decryption_with_Combiner {
   public:
      explicit MLKEM_Composite_Decapsulation_Operation(const PairOfPrivateKeys& private_keys,
                                                       std::string label,
                                                       RandomNumberGenerator& rng,
                                                       std::string_view provider) :
            KEM_Decryption_with_Combiner(private_keys, rng, provider),
            m_traditional_pubkey_encoded(private_keys.second->public_key_bits()),
            m_label(std::move(label)) {}

      void combine_shared_secrets(std::span<uint8_t> out_shared_secret,
                                  const PairOfSharedSecrets& ss,
                                  const PairOfCiphertexts& ct,
                                  size_t /* desired_shared_key_len */,
                                  std::span<const uint8_t> /* salt */) override {
         combiner(out_shared_secret, ss, ct, m_traditional_pubkey_encoded, m_label);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override {
         return 32;  // output length of SHA-3(256) }
      }

   private:
      std::vector<uint8_t> m_traditional_pubkey_encoded;
      std::string m_label;
};

}  // namespace

MLKEM_Composite_PublicKey::MLKEM_Composite_PublicKey(const MLKEM_Composite_Param& parameters,
                                                     PairOfPublicKeys public_keys) :
      Hybrid_KEM_PublicKey(std::move(public_keys)), m_parameters(std::make_shared<MLKEM_Composite_Param>(parameters)) {
   BOTAN_ARG_CHECK(mlkem_public_key().algorithm_identifier() == m_parameters->get_mlkem_algorithm_id(),
                   "ML-KEM component does not match the ML-KEM composite parameters");

   if(traditional_public_key().algo_name() != m_parameters->traditional_algorithm()) {
      throw Invalid_Argument(
         fmt("MLKEM_Composite_Param indicates {} as the traditional algorithm – this does not fit to the {} public key",
             m_parameters->traditional_algorithm(),
             traditional_public_key().algo_name()));
   }
}

MLKEM_Composite_PublicKey::MLKEM_Composite_PublicKey(const AlgorithmIdentifier& algo_id,
                                                     std::span<const uint8_t> key_bits) :
      Hybrid_KEM_PublicKey(load_public_keys(MLKEM_Composite_Param::from_algo_id_or_throw(algo_id), key_bits)),
      m_parameters(std::make_shared<MLKEM_Composite_Param>(MLKEM_Composite_Param::from_algo_id_or_throw(algo_id))) {}

MLKEM_Composite_PublicKey::MLKEM_Composite_PublicKey(MLKEM_Composite_Param::id_t id,
                                                     std::span<const uint8_t> key_bits) :
      Hybrid_KEM_PublicKey(load_public_keys(MLKEM_Composite_Param::from_id_supported_or_throw(id), key_bits)),
      m_parameters(std::make_shared<MLKEM_Composite_Param>(MLKEM_Composite_Param::from_id_supported_or_throw(id))) {}

OID MLKEM_Composite_PublicKey::object_identifier() const {
   return m_parameters->object_identifier();
}

std::unique_ptr<Private_Key> MLKEM_Composite_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<MLKEM_Composite_PrivateKey>(rng, *m_parameters);
}

std::unique_ptr<PK_Ops::KEM_Encryption> MLKEM_Composite_PublicKey::create_kem_encryption_op(
   std::string_view params, std::string_view provider) const {
   if(!params.empty() && params != "Raw") {
      throw Botan::Invalid_Argument("only empty parameters or 'Raw' is supported by MLKEM-composite KEM");
   }

   if(!provider.empty() && provider != "base") {
      throw Provider_Not_Found(algo_name(), provider);
   }

   return std::make_unique<MLKEM_Composite_Encapsulation_Operation>(public_keys(), m_parameters->label(), provider);
}

const ML_KEM_PublicKey& MLKEM_Composite_PublicKey::mlkem_public_key() const {
   BOTAN_ASSERT(public_keys().first != nullptr, "ML-KEM public key is not null");
   const auto* mlkem_pk = dynamic_cast<const ML_KEM_PublicKey*>(public_keys().first.get());
   BOTAN_ASSERT_NONNULL(mlkem_pk);
   return *mlkem_pk;
}

const Public_Key& MLKEM_Composite_PublicKey::traditional_public_key() const {
   const auto* trad_pk = public_keys().second.get();
   BOTAN_ASSERT(trad_pk != nullptr, "Traditional public key is not null");

   if(const auto* raw_trad_pk = dynamic_cast<const Asymmetric_Encryption_to_KEM_Adapter_PublicKey*>(trad_pk)) {
      return raw_trad_pk->inner();
   }

   if(const auto* raw_trad_pk = dynamic_cast<const KEX_to_KEM_Adapter_PublicKey*>(trad_pk)) {
      return raw_trad_pk->inner();
   }

   return *trad_pk;
}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(const MLKEM_Composite_Param& parameters,
                                                       PairOfPrivateKeys private_keys) :
      // Explicitly calling the constructor of the virtually inherited base class
      // Hybrid_KEM_PublicKey to avoid the diamond problem of multiple inheritance.
      // MLKEM_Composite_PublicKey also calls this constructor, but without effect,
      // because the standard mandates that virtually inherited base classes are
      // only constructed once, by the most derived class: i.e. "here".
      //
      // TODO(Botan4): This is a workaround for the PrivateKey-is-a-PublicKey
      //               design nuisance and may be removed along with it.
      Hybrid_KEM_PublicKey(extract_public_keys(private_keys)),
      MLKEM_Composite_PublicKey(parameters, extract_public_keys(private_keys)),
      Hybrid_KEM_PrivateKey(std::move(private_keys)),
      m_parameters(std::make_shared<MLKEM_Composite_Param>(parameters)) {}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(MLKEM_Composite_Param::id_t id, std::span<const uint8_t> sk) :
      MLKEM_Composite_PrivateKey(MLKEM_Composite_Param::from_id_supported_or_throw(id),
                                 load_private_keys(MLKEM_Composite_Param::from_id_supported_or_throw(id), sk)) {}

secure_vector<uint8_t> MLKEM_Composite_PrivateKey::private_key_bits() const {
   return concat(mlkem_private_key().private_key_bits_with_format(MlPrivateKeyFormat::Seed),
                 encode_traditional_private_key(*m_parameters, traditional_private_key()));
}

std::unique_ptr<Public_Key> MLKEM_Composite_PrivateKey::public_key() const {
   return std::make_unique<MLKEM_Composite_PublicKey>(*m_parameters, extract_public_keys(private_keys()));
}

/**
 * Create a decryption operation that produces a MLKEM_Composite KEM Decryption Operation.
 */
std::unique_ptr<PK_Ops::KEM_Decryption> MLKEM_Composite_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view params, std::string_view provider) const {
   if(!params.empty() && params != "Raw") {
      throw Botan::Invalid_Argument("only empty parameters or 'Raw' is supported by MLKEM-composite KEM");
   }

   if(!provider.empty() && provider != "base") {
      throw Provider_Not_Found(algo_name(), provider);
   }

   return std::make_unique<MLKEM_Composite_Decapsulation_Operation>(
      private_keys(), m_parameters->label(), rng, provider);
}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(const AlgorithmIdentifier& algo_id,
                                                       std::span<const uint8_t> sk) :
      MLKEM_Composite_PrivateKey(MLKEM_Composite_Param::from_algo_id_or_throw(algo_id),
                                 load_private_keys(MLKEM_Composite_Param::from_algo_id_or_throw(algo_id), sk)) {}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(RandomNumberGenerator& rng, MLKEM_Composite_Param param) :
      MLKEM_Composite_PrivateKey(param, create_private_keys(param, rng)) {}

const ML_KEM_PrivateKey& MLKEM_Composite_PrivateKey::mlkem_private_key() const {
   BOTAN_ASSERT(private_keys().first != nullptr, "ML-KEM private key is not null");
   const auto* mlkem_sk = dynamic_cast<const ML_KEM_PrivateKey*>(private_keys().first.get());
   BOTAN_ASSERT_NONNULL(mlkem_sk);
   return *mlkem_sk;
}

const Private_Key& MLKEM_Composite_PrivateKey::traditional_private_key() const {
   const auto* trad_sk = private_keys().second.get();
   BOTAN_ASSERT(trad_sk != nullptr, "Traditional private key is not null");

   if(const auto* raw_trad_sk = dynamic_cast<const Asymmetric_Encryption_to_KEM_Adapter_PrivateKey*>(trad_sk)) {
      return raw_trad_sk->inner();
   }

   if(const auto* raw_trad_sk = dynamic_cast<const KEX_to_KEM_Adapter_PrivateKey*>(trad_sk)) {
      return raw_trad_sk->inner();
   }

   return *trad_sk;
}

}  // namespace Botan
