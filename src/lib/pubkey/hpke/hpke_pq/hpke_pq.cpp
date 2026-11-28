/*
* HPKE KEMs from draft-ietf-hpke-pq
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/hpke_pq.h>

#include <botan/ec_apoint.h>
#include <botan/ec_group.h>
#include <botan/ec_scalar.h>
#include <botan/ecdh.h>
#include <botan/exceptn.h>
#include <botan/ml_kem.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/internal/concat_util.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/sha3.h>
#include <botan/internal/shake_xof.h>
#include <optional>
#include <type_traits>

#if defined(BOTAN_HAS_X25519)
   #include <botan/x25519.h>
#endif

namespace Botan::HPKE {

namespace {

std::string pq_kem_name(KEM_Id kem) {
   return kem.to_string().value_or(std::to_string(kem.wire_code()));
}

/*
* DeriveKeyPair for the KEMs of draft-ietf-hpke-pq-05 (Sections 3 and 4). The
* private key of each of these KEMs is a seed of Nsk bytes, which is derived
* from the ikm as SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", Nsk), with
* LabeledDerive as defined in draft-ietf-hpke-hpke-03 Section 4.4. SHAKE256
* is used here whatever the KDF of the HPKE suite.
*/
secure_vector<uint8_t> derive_pq_key_seed(KEM_Id kem, std::span<const uint8_t> ikm) {
   /*
   * The recommended minimum is Nsk bytes, which for ML-KEM is 64. That is
   * not enforced, since protocols deriving key pairs from the output of the
   * suite's KDF (such as MLS) provide only Nh bytes, which can be 32.
   */
   BOTAN_ARG_CHECK(ikm.size() >= 32, "HPKE DeriveKeyPair ikm too short");

   const size_t nsk = kem.private_key_length();
   const std::string_view label = "DeriveKeyPair";

   SHAKE_256_XOF xof;
   xof.update(ikm);
   xof.update(as_span_of_bytes(std::string_view("HPKE-v1")));
   // The suite_id of a KEM
   xof.update(as_span_of_bytes(std::string_view("KEM")));
   xof.update(store_be(kem.wire_code()));
   // The length prefixed label
   xof.update(store_be(static_cast<uint16_t>(label.size())));
   xof.update(as_span_of_bytes(label));
   // The output length; the context which would follow it is empty
   xof.update(store_be(static_cast<uint16_t>(nsk)));
   return xof.output<secure_vector<uint8_t>>(nsk);
}

std::optional<ML_KEM_Mode> ml_kem_mode_for(KEM_Id kem) {
   switch(kem.code()) {
      case KEM_Code::ML_KEM_512:
         return ML_KEM_Mode(ML_KEM_Mode::ML_KEM_512);
      case KEM_Code::ML_KEM_768:
         return ML_KEM_Mode(ML_KEM_Mode::ML_KEM_768);
      case KEM_Code::ML_KEM_1024:
         return ML_KEM_Mode(ML_KEM_Mode::ML_KEM_1024);
      default:
         return std::nullopt;
   }
}

/*
* ML-KEM as an HPKE KEM (draft-ietf-hpke-pq-05 Section 3)
*
* Encap and Decap are ML-KEM.Encaps and ML-KEM.Decaps of FIPS 203, and the
* shared secret is used as is. The public key is the encapsulation key, and
* the private key is the 64 byte seed (d || z).
*/
class ML_KEM_Ops final : public KEM_Ops {
   public:
      ML_KEM_Ops(KEM_Id id, ML_KEM_Mode mode) : KEM_Ops(id), m_mode(mode) {}

      Encapsulation encap(const Botan::Public_Key& pkR, RandomNumberGenerator& rng) const override {
         PK_KEM_Encryptor encryptor(pkR, "Raw");
         auto [enc, shared_secret] = KEM_Encapsulation::destructure(encryptor.encrypt(rng));
         return {std::move(enc), std::move(shared_secret)};
      }

      secure_vector<uint8_t> decap(std::span<const uint8_t> enc,
                                   const Botan::Private_Key& skR,
                                   RandomNumberGenerator& rng) const override {
         if(enc.size() != kem_id().encapsulation_length()) {
            throw Decoding_Error(fmt("Invalid encapsulation length for HPKE KEM {}", pq_kem_name(kem_id())));
         }

         PK_KEM_Decryptor decryptor(skR, rng, "Raw");
         return decryptor.decrypt(enc);
      }

      std::unique_ptr<Botan::Private_Key> generate_key(RandomNumberGenerator& rng) const override {
         return std::make_unique<ML_KEM_PrivateKey>(rng, m_mode);
      }

      std::unique_ptr<Botan::Private_Key> derive_key_pair(std::span<const uint8_t> ikm) const override {
         return deserialize_private(derive_pq_key_seed(kem_id(), ikm));
      }

      std::unique_ptr<Botan::Public_Key> deserialize_public(std::span<const uint8_t> bytes) const override {
         if(bytes.size() != kem_id().public_key_length()) {
            throw Decoding_Error(fmt("Invalid public key length for HPKE KEM {}", pq_kem_name(kem_id())));
         }
         // This performs the encapsulation key check of FIPS 203 Section 7.2
         return std::make_unique<ML_KEM_PublicKey>(bytes, m_mode);
      }

      std::unique_ptr<Botan::Private_Key> deserialize_private(std::span<const uint8_t> bytes) const override {
         // The length check ensures that only the seed format is accepted here
         if(bytes.size() != kem_id().private_key_length()) {
            throw Decoding_Error(fmt("Invalid private key length for HPKE KEM {}", pq_kem_name(kem_id())));
         }
         return std::make_unique<ML_KEM_PrivateKey>(bytes, m_mode);
      }

      std::vector<uint8_t> serialize_public(const Botan::Public_Key& key) const override {
         auto bytes = key.raw_public_key_bits();
         BOTAN_ASSERT_NOMSG(bytes.size() == kem_id().public_key_length());
         return bytes;
      }

      secure_vector<uint8_t> serialize_private(const Botan::Private_Key& key) const override {
         const auto* mlkem = dynamic_cast<const ML_KEM_PrivateKey*>(&key);
         BOTAN_ARG_CHECK(mlkem != nullptr, "Key does not match the KEM");

         // A key adopted via from_key may have been loaded from the expanded
         // encoding, from which the seed cannot be recovered
         if(mlkem->private_key_format() == MlPrivateKeyFormat::Expanded) {
            throw Invalid_State("This ML-KEM private key was loaded without its seed, which is the HPKE encoding");
         }

         return mlkem->formatted_raw_private_key_bits(MlPrivateKeyFormat::Seed);
      }

      std::unique_ptr<Botan::Public_Key> adopt_public(std::unique_ptr<Botan::Public_Key> key) const override {
         return adopt_key(std::move(key));
      }

      std::unique_ptr<Botan::Private_Key> adopt_private(std::unique_ptr<Botan::Private_Key> key) const override {
         return adopt_key(std::move(key));
      }

   private:
      template <typename KeyT>
      std::unique_ptr<KeyT> adopt_key(std::unique_ptr<KeyT> key) const {
         using ML_KEM_KeyT =
            std::conditional_t<std::is_same_v<KeyT, Botan::Private_Key>, ML_KEM_PrivateKey, ML_KEM_PublicKey>;

         if(const auto* mlkem = dynamic_cast<const ML_KEM_KeyT*>(key.get())) {
            if(mlkem->mode() == m_mode) {
               return key;
            }
            throw Invalid_Argument(
               fmt("{} key cannot be used with HPKE KEM {}", mlkem->mode().to_string(), pq_kem_name(kem_id())));
         }

         throw Invalid_Argument(
            fmt("Key of type {} cannot be used with HPKE KEM {}", key->algo_name(), pq_kem_name(kem_id())));
      }

      ML_KEM_Mode m_mode;
};

/*
* The parameters, and nominal group, of one of the hybrid KEMs defined in
* draft-irtf-cfrg-concrete-hybrid-kems-03 Section 4. All of them combine
* ML-KEM with an elliptic curve group using the CG framework of
* draft-irtf-cfrg-hybrid-kems-12 Section 5.5, with SHAKE256 as the PRG and
* SHA3-256 as the KDF.
*/
class Hybrid_KEM_Params final {
   public:
      /// Returns nullptr if @p kem is not a hybrid KEM, or is unavailable
      static std::shared_ptr<const Hybrid_KEM_Params> create(KEM_Id kem) {
         switch(kem.code()) {
            case KEM_Code::MLKEM768_P256:
               return create_for_curve(kem, ML_KEM_Mode::ML_KEM_768, "secp256r1", 128, "MLKEM768-P256");

            case KEM_Code::MLKEM1024_P384:
               return create_for_curve(kem, ML_KEM_Mode::ML_KEM_1024, "secp384r1", 48, "MLKEM1024-P384");

            case KEM_Code::MLKEM768_X25519:
#if defined(BOTAN_HAS_X25519)
               if(ML_KEM_Mode(ML_KEM_Mode::ML_KEM_768).is_available()) {
                  // The X-Wing label: the six characters 5C 2E 2F 2F 5E 5C
                  return std::shared_ptr<const Hybrid_KEM_Params>(
                     new Hybrid_KEM_Params(kem, ML_KEM_Mode::ML_KEM_768, std::nullopt, 32, 32, "\\.//^\\"));
               }
#endif
               return nullptr;

            default:
               return nullptr;
         }
      }

      KEM_Id kem_id() const { return m_kem; }

      ML_KEM_Mode pq_mode() const { return m_pq_mode; }

      /// KEM_PQ.Nseed
      static constexpr size_t pq_seed_bytes() { return 64; }

      /// KEM_PQ.Nek
      size_t pq_public_key_bytes() const { return m_pq_public_key_bytes; }

      /// KEM_PQ.Nct
      size_t pq_ciphertext_bytes() const { return m_pq_ciphertext_bytes; }

      /// Group_T.Nseed
      size_t group_seed_bytes() const { return m_group_seed_bytes; }

      /// Group_T.Nelem
      size_t group_element_bytes() const { return m_group_element_bytes; }

      std::string_view label() const { return m_label; }

      /*
      * Group_T.RandomScalar from draft-irtf-cfrg-concrete-hybrid-kems-03
      * Section 3.1, returning the scalar as a key for the group's key
      * agreement algorithm.
      */
      std::unique_ptr<PK_Key_Agreement_Key> random_scalar(std::span<const uint8_t> seed) const {
         BOTAN_ARG_CHECK(seed.size() == m_group_seed_bytes, "Invalid seed length for RandomScalar");

         if(m_ec_group.has_value()) {
            // Section 3.1.1: the scalar is the first of the successive Nscalar
            // byte chunks of the seed which is in the range [1,n)
            const size_t scalar_bytes = m_ec_group->get_order_bytes();

            for(size_t offset = 0; offset + scalar_bytes <= seed.size(); offset += scalar_bytes) {
               if(const auto scalar = EC_Scalar::deserialize(*m_ec_group, seed.subspan(offset, scalar_bytes));
                  scalar.has_value() && scalar->is_nonzero()) {
                  return std::make_unique<ECDH_PrivateKey>(*m_ec_group, *scalar);
               }
            }

            // For a uniformly random seed this has probability under 2^-128
            throw Internal_Error("HPKE hybrid KEM scalar rejection sampling failed");
         }

#if defined(BOTAN_HAS_X25519)
         // Section 3.1.2: the scalar is the seed. The clamping of RFC 7748
         // is applied when the scalar is used.
         return std::make_unique<X25519_PrivateKey>(seed);
#else
         throw Not_Implemented("HPKE hybrid KEM group is not available");
#endif
      }

      /*
      * Check the encoding of an element of Group_T, as it appears in a public
      * key or an encapsulation. For the NIST curves an element is a point in
      * the uncompressed SEC1 encoding, which must be on the curve and not be
      * the identity. Every 32 byte string is an element of the Curve25519
      * group; the elements of low order are rejected by the key agreement.
      */
      void check_group_element(std::span<const uint8_t> bytes) const {
         if(bytes.size() != m_group_element_bytes) {
            throw Decoding_Error(fmt("Invalid group element length for HPKE KEM {}", pq_kem_name(m_kem)));
         }

         if(m_ec_group.has_value() && !EC_AffinePoint::deserialize_uncompressed(*m_ec_group, bytes).has_value()) {
            throw Decoding_Error(fmt("Invalid elliptic curve point for HPKE KEM {}", pq_kem_name(m_kem)));
         }
      }

   private:
      static std::shared_ptr<const Hybrid_KEM_Params> create_for_curve(
         KEM_Id kem, ML_KEM_Mode pq_mode, std::string_view curve, size_t group_seed_bytes, std::string_view label) {
         if(!pq_mode.is_available() || !EC_Group::supports_named_group(curve)) {
            return nullptr;
         }

         auto group = EC_Group::from_name(curve);
         const size_t group_element_bytes = 1 + 2 * group.get_p_bytes();
         return std::shared_ptr<const Hybrid_KEM_Params>(
            new Hybrid_KEM_Params(kem, pq_mode, std::move(group), group_seed_bytes, group_element_bytes, label));
      }

      Hybrid_KEM_Params(KEM_Id kem,
                        ML_KEM_Mode pq_mode,
                        std::optional<EC_Group> ec_group,
                        size_t group_seed_bytes,
                        size_t group_element_bytes,
                        std::string_view label) :
            m_kem(kem),
            m_pq_mode(pq_mode),
            m_ec_group(std::move(ec_group)),
            m_group_seed_bytes(group_seed_bytes),
            m_group_element_bytes(group_element_bytes),
            m_pq_public_key_bytes(kem.public_key_length() - group_element_bytes),
            m_pq_ciphertext_bytes(kem.encapsulation_length() - group_element_bytes),
            m_label(label) {}

      KEM_Id m_kem;
      ML_KEM_Mode m_pq_mode;
      std::optional<EC_Group> m_ec_group;  // unset for Curve25519
      size_t m_group_seed_bytes;
      size_t m_group_element_bytes;
      size_t m_pq_public_key_bytes;
      size_t m_pq_ciphertext_bytes;
      std::string_view m_label;
};

/*
* The key types of the hybrid KEMs. These exist only so that such a key can
* be held by HPKE::Public_Key and HPKE::Private_Key: there is no algorithm
* identifier assigned for these KEMs, so the keys have no X.509 or PKCS #8
* encoding, and they do not offer any operations themselves.
*/
class Hybrid_KEM_PublicKey : public virtual Botan::Public_Key {
   public:
      /// DeserializePublicKey: the encapsulation key is ek_PQ || ek_T
      Hybrid_KEM_PublicKey(std::shared_ptr<const Hybrid_KEM_Params> params, std::span<const uint8_t> bytes) :
            m_params(std::move(params)) {
         if(bytes.size() != m_params->kem_id().public_key_length()) {
            throw Decoding_Error(fmt("Invalid public key length for HPKE KEM {}", pq_kem_name(m_params->kem_id())));
         }

         const auto ek_pq = bytes.first(m_params->pq_public_key_bytes());
         const auto ek_t = bytes.subspan(m_params->pq_public_key_bytes());

         // This performs the encapsulation key check of FIPS 203 Section 7.2
         m_pq_key = std::make_shared<ML_KEM_PublicKey>(ek_pq, m_params->pq_mode());
         m_params->check_group_element(ek_t);
         m_group_element.assign(ek_t.begin(), ek_t.end());
      }

      Hybrid_KEM_PublicKey(std::shared_ptr<const Hybrid_KEM_Params> params,
                           std::shared_ptr<const Botan::Public_Key> pq_key,
                           std::vector<uint8_t> group_element) :
            m_params(std::move(params)), m_pq_key(std::move(pq_key)), m_group_element(std::move(group_element)) {}

      KEM_Id kem_id() const { return m_params->kem_id(); }

      const std::shared_ptr<const Hybrid_KEM_Params>& params() const { return m_params; }

      /// The ML-KEM encapsulation key ek_PQ
      const std::shared_ptr<const Botan::Public_Key>& pq_key() const { return m_pq_key; }

      /// The serialized group element ek_T
      const std::vector<uint8_t>& group_element() const { return m_group_element; }

      std::string algo_name() const override { return pq_kem_name(kem_id()); }

      size_t estimated_strength() const override { return m_pq_key->estimated_strength(); }

      size_t key_length() const override { return m_pq_key->key_length(); }

      bool supports_operation(PublicKeyOperation /*op*/) const override { return false; }

      // The group element was validated when the key was created
      bool check_key(RandomNumberGenerator& rng, bool strong) const override {
         return m_pq_key->check_key(rng, strong);
      }

      std::unique_ptr<Botan::Private_Key> generate_another(RandomNumberGenerator& rng) const override;

      AlgorithmIdentifier algorithm_identifier() const override {
         throw Not_Implemented(fmt("{} keys do not have an algorithm identifier", algo_name()));
      }

      std::vector<uint8_t> raw_public_key_bits() const override {
         return concat<std::vector<uint8_t>>(m_pq_key->raw_public_key_bits(), m_group_element);
      }

      std::vector<uint8_t> public_key_bits() const override { return raw_public_key_bits(); }

   private:
      std::shared_ptr<const Hybrid_KEM_Params> m_params;
      std::shared_ptr<const Botan::Public_Key> m_pq_key;
      std::vector<uint8_t> m_group_element;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class Hybrid_KEM_PrivateKey final : public Hybrid_KEM_PublicKey,
                                    public virtual Botan::Private_Key {
   public:
      /// The decapsulation key is a 32 byte seed, from which the keys of the
      /// two components are derived
      static constexpr size_t SeedBytes = 32;

      Hybrid_KEM_PrivateKey(const std::shared_ptr<const Hybrid_KEM_Params>& params, std::span<const uint8_t> seed) :
            Hybrid_KEM_PrivateKey(params, seed, expand_seed(*params, seed)) {}

      /// The ML-KEM decapsulation key dk_PQ
      const Botan::Private_Key& pq_private_key() const { return *m_pq_private; }

      /// The scalar dk_T
      const Botan::Private_Key& group_private_key() const { return *m_group_private; }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override {
         return m_pq_private->check_key(rng, strong) && m_group_private->check_key(rng, strong);
      }

      secure_vector<uint8_t> raw_private_key_bits() const override { return m_seed; }

      secure_vector<uint8_t> private_key_bits() const override {
         throw Not_Implemented(fmt("{} keys do not have a PKCS #8 encoding", algo_name()));
      }

      std::unique_ptr<Botan::Public_Key> public_key() const override {
         return std::make_unique<Hybrid_KEM_PublicKey>(params(), pq_key(), group_element());
      }

   private:
      struct Components {
            std::unique_ptr<ML_KEM_PrivateKey> pq;
            std::unique_ptr<PK_Key_Agreement_Key> group;
      };

      /// expandDecapsKeyG from draft-irtf-cfrg-hybrid-kems-12 Section 5.1.1
      static Components expand_seed(const Hybrid_KEM_Params& params, std::span<const uint8_t> seed) {
         BOTAN_ARG_CHECK(seed.size() == SeedBytes, "Invalid seed length for HPKE hybrid KEM");

         SHAKE_256_XOF prg;
         prg.update(seed);
         const auto seed_full =
            prg.output<secure_vector<uint8_t>>(Hybrid_KEM_Params::pq_seed_bytes() + params.group_seed_bytes());

         const auto seed_pq = std::span<const uint8_t>(seed_full).first(Hybrid_KEM_Params::pq_seed_bytes());
         const auto seed_t = std::span<const uint8_t>(seed_full).subspan(Hybrid_KEM_Params::pq_seed_bytes());

         // KEM_PQ.DeriveKeyPair is ML-KEM.KeyGen_internal(d, z) with seed_PQ = d || z
         Components components;
         components.pq = std::make_unique<ML_KEM_PrivateKey>(seed_pq, params.pq_mode());
         components.group = params.random_scalar(seed_t);
         return components;
      }

      Hybrid_KEM_PrivateKey(const std::shared_ptr<const Hybrid_KEM_Params>& params,
                            std::span<const uint8_t> seed,
                            Components components) :
            Hybrid_KEM_PublicKey(params, components.pq->public_key(), components.group->public_value()),
            m_seed(seed.begin(), seed.end()),
            m_pq_private(std::move(components.pq)),
            m_group_private(std::move(components.group)) {}

      secure_vector<uint8_t> m_seed;
      std::unique_ptr<const ML_KEM_PrivateKey> m_pq_private;
      std::unique_ptr<const PK_Key_Agreement_Key> m_group_private;
};

BOTAN_DIAGNOSTIC_POP

std::unique_ptr<Botan::Private_Key> Hybrid_KEM_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<Hybrid_KEM_PrivateKey>(m_params, rng.random_vec(Hybrid_KEM_PrivateKey::SeedBytes));
}

/*
* A hybrid of ML-KEM and an elliptic curve group as an HPKE KEM
* (draft-ietf-hpke-pq-05 Section 4)
*
* Encap and Decap are those of the CG framework, as given in
* draft-irtf-cfrg-hybrid-kems-12 Section 5.5.
*/
class Hybrid_KEM_Ops final : public KEM_Ops {
   public:
      explicit Hybrid_KEM_Ops(std::shared_ptr<const Hybrid_KEM_Params> params) :
            KEM_Ops(params->kem_id()), m_params(std::move(params)) {}

      Encapsulation encap(const Botan::Public_Key& pkR, RandomNumberGenerator& rng) const override {
         const auto& pk = hybrid_key<Hybrid_KEM_PublicKey>(pkR);
         const auto& ek_t = pk.group_element();

         /*
         * This is prepareEncapsG. The random values are requested in the order
         * that EncapsDerand (draft-irtf-cfrg-hybrid-kems-12 Appendix A) takes
         * them from its randomness input, which is relied on for testing: the
         * 32 bytes for ML-KEM.Encaps, then the seed for RandomScalar. Any
         * further requests are made by the key agreement, for blinding.
         */
         PK_KEM_Encryptor pq_encryptor(*pk.pq_key(), "Raw");
         auto [ct_pq, ss_pq] = KEM_Encapsulation::destructure(pq_encryptor.encrypt(rng));

         const auto sk_e = m_params->random_scalar(rng.random_vec(m_params->group_seed_bytes()));
         const auto ct_t = sk_e->public_value();
         const auto ss_t = dh(*sk_e, ek_t, rng);

         auto shared_secret = combine(ss_pq, ss_t, ct_t, ek_t);
         return {concat<std::vector<uint8_t>>(ct_pq, ct_t), std::move(shared_secret)};
      }

      secure_vector<uint8_t> decap(std::span<const uint8_t> enc,
                                   const Botan::Private_Key& skR,
                                   RandomNumberGenerator& rng) const override {
         const auto& sk = hybrid_key<Hybrid_KEM_PrivateKey>(skR);

         if(enc.size() != kem_id().encapsulation_length()) {
            throw Decoding_Error(fmt("Invalid encapsulation length for HPKE KEM {}", pq_kem_name(kem_id())));
         }

         const auto ct_pq = enc.first(m_params->pq_ciphertext_bytes());
         const auto ct_t = enc.subspan(m_params->pq_ciphertext_bytes());

         // An invalid group element is rejected explicitly; see
         // draft-irtf-cfrg-hybrid-kems-12 Section 4.2
         m_params->check_group_element(ct_t);

         // This is prepareDecapsG
         PK_KEM_Decryptor pq_decryptor(sk.pq_private_key(), rng, "Raw");
         const auto ss_pq = pq_decryptor.decrypt(ct_pq);
         const auto ss_t = dh(sk.group_private_key(), ct_t, rng);

         return combine(ss_pq, ss_t, ct_t, sk.group_element());
      }

      std::unique_ptr<Botan::Private_Key> generate_key(RandomNumberGenerator& rng) const override {
         return deserialize_private(rng.random_vec(Hybrid_KEM_PrivateKey::SeedBytes));
      }

      std::unique_ptr<Botan::Private_Key> derive_key_pair(std::span<const uint8_t> ikm) const override {
         return deserialize_private(derive_pq_key_seed(kem_id(), ikm));
      }

      std::unique_ptr<Botan::Public_Key> deserialize_public(std::span<const uint8_t> bytes) const override {
         return std::make_unique<Hybrid_KEM_PublicKey>(m_params, bytes);
      }

      std::unique_ptr<Botan::Private_Key> deserialize_private(std::span<const uint8_t> bytes) const override {
         if(bytes.size() != kem_id().private_key_length()) {
            throw Decoding_Error(fmt("Invalid private key length for HPKE KEM {}", pq_kem_name(kem_id())));
         }
         return std::make_unique<Hybrid_KEM_PrivateKey>(m_params, bytes);
      }

      std::vector<uint8_t> serialize_public(const Botan::Public_Key& key) const override {
         return hybrid_key<Hybrid_KEM_PublicKey>(key).raw_public_key_bits();
      }

      secure_vector<uint8_t> serialize_private(const Botan::Private_Key& key) const override {
         return hybrid_key<Hybrid_KEM_PrivateKey>(key).raw_private_key_bits();
      }

      std::unique_ptr<Botan::Public_Key> adopt_public(std::unique_ptr<Botan::Public_Key> key) const override {
         BOTAN_ARG_CHECK(key != nullptr, "Key is null");
         hybrid_key<Hybrid_KEM_PublicKey>(*key);
         return key;
      }

      std::unique_ptr<Botan::Private_Key> adopt_private(std::unique_ptr<Botan::Private_Key> key) const override {
         BOTAN_ARG_CHECK(key != nullptr, "Key is null");
         hybrid_key<Hybrid_KEM_PrivateKey>(*key);
         return key;
      }

   private:
      /// Check that a key is a key of this KEM
      template <typename HybridKeyT>
      const HybridKeyT& hybrid_key(const Botan::Public_Key& key) const {
         const auto* hybrid = dynamic_cast<const HybridKeyT*>(&key);
         if(hybrid == nullptr || hybrid->kem_id() != kem_id()) {
            throw Invalid_Argument(
               fmt("Key of type {} cannot be used with HPKE KEM {}", key.algo_name(), pq_kem_name(kem_id())));
         }
         return *hybrid;
      }

      /*
      * Group_T.ElementToSharedSecret(Group_T.Exp(peer, sk)): the x coordinate
      * of the resulting point for the NIST curves, or the output of X25519.
      *
      * The key agreement validates the peer's group element, and for X25519
      * throws Invalid_Argument if it is a point of low order (that is, if the
      * output is all zero bytes, as in RFC 7748 Section 6.1).
      */
      static secure_vector<uint8_t> dh(const Botan::Private_Key& sk,
                                       std::span<const uint8_t> peer,
                                       RandomNumberGenerator& rng) {
         const PK_Key_Agreement ka(sk, rng, "Raw");
         return ka.derive_key(0, peer).bits_of();
      }

      /// C2PRICombiner from draft-irtf-cfrg-hybrid-kems-12 Section 5.1.3
      secure_vector<uint8_t> combine(std::span<const uint8_t> ss_pq,
                                     std::span<const uint8_t> ss_t,
                                     std::span<const uint8_t> ct_t,
                                     std::span<const uint8_t> ek_t) const {
         SHA_3_256 kdf;
         kdf.update(ss_pq);
         kdf.update(ss_t);
         kdf.update(ct_t);
         kdf.update(ek_t);
         kdf.update(m_params->label());
         return kdf.final();
      }

      std::shared_ptr<const Hybrid_KEM_Params> m_params;
};

}  // namespace

std::unique_ptr<const KEM_Ops> create_pq_kem_ops(KEM_Id kem) {
   if(const auto mode = ml_kem_mode_for(kem)) {
      if(mode->is_available()) {
         return std::make_unique<ML_KEM_Ops>(kem, *mode);
      }
      return nullptr;
   }

   if(auto params = Hybrid_KEM_Params::create(kem)) {
      return std::make_unique<Hybrid_KEM_Ops>(std::move(params));
   }

   return nullptr;
}

}  // namespace Botan::HPKE
