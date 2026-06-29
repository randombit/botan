/*
 * ML-KEM Composite KEM 
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include <botan/hash.h>
#include <botan/mlkem_comp.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <botan/rsa.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#if defined BOTAN_HAS_ECDH
   #include <botan/ec_group.h>
   #include <botan/ecdh.h>
#endif

#if defined BOTAN_HAS_X25519
   #include <botan/x25519.h>
#endif
#if defined BOTAN_HAS_X448
   #include <botan/x448.h>
#endif
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/ml_kem.h>
#include <botan/oids.h>
#include <botan/pk_algs.h>
#include <botan/pk_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

namespace Botan {

namespace {

// with C++23, to be replaced by std::ranges::contains()
template <std::size_t N, typename T>
constexpr bool contains(const std::array<T, N>& c, const T& e) {
   return std::find(begin(c), std::end(c), e) != std::end(c);
}

std::span<const uint8_t> mlkem_pubkey_subspan(const MLKEM_Composite_Param& param, std::span<const uint8_t> key_bits) {
   if(key_bits.size() <= param.mlkem_pubkey_size()) {
      throw Invalid_Argument(fmt("encoded MLKEM component public key is too short (len = {})", key_bits.size()));
   }
   return std::span<const uint8_t>(key_bits.begin(), param.mlkem_pubkey_size());
}

std::span<const uint8_t> mlkem_privkey_subspan(const MLKEM_Composite_Param& param, std::span<const uint8_t> key_bits) {
   if(key_bits.size() <= param.mlkem_privkey_size()) {
      throw Invalid_Argument("encoded MLKEM component private key is too short");
   }
   return std::span<const uint8_t>(key_bits.begin(), param.mlkem_privkey_size());
}

std::span<const uint8_t> traditional_pubkey_subspan(const MLKEM_Composite_Param& param,
                                                    std::span<const uint8_t> key_bits) {
   const size_t offset = param.mlkem_pubkey_size();
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument(fmt("encoded traditional component public key is too short (len = {})", key_bits.size()));
   }
   return std::span<const uint8_t>(key_bits.begin() + offset, key_bits.end());
}

std::span<const uint8_t> traditional_privkey_subspan(const MLKEM_Composite_Param& param,
                                                     std::span<const uint8_t> key_bits) {
   const size_t offset = param.mlkem_privkey_size();
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument("encoded traditional component private key is too short");
   }
   return std::span<const uint8_t>(key_bits.begin() + offset, key_bits.end());
}

void ensure_consistent_algo_names(const Public_Key* trad_pubkey, const MLKEM_Composite_Param& param) {
   if(trad_pubkey->algo_name() != param.traditional_algorithm()) {
      throw Invalid_Argument(
         fmt("MLKEM_Composite_Param indicates {} as the traditional algorithm – this does not fit to the {} public key",
             param.traditional_algorithm(),
             trad_pubkey->algo_name()));
   }
}
}  // namespace

class MLKEM_Composite_Encapsulation_Operation final : public PK_Ops::KEM_Encryption {
   public:
      explicit MLKEM_Composite_Encapsulation_Operation(  //RandomNumberGenerator& rng,
         const MLKEM_Composite_Param& param,
         const ML_KEM_PublicKey& mlkem_pubkey,
         const Public_Key* trad_pubkey,
         std::string_view provider) :
            m_parameters(param),
            m_mlkem_enc_op(mlkem_pubkey.create_kem_encryption_op("Raw", "")),
            m_traditional_pubkey_encoded(trad_pubkey->public_key_bits()) {
         ensure_consistent_algo_names(trad_pubkey, param);
         if(trad_pubkey->algo_name() == "RSA") {
            m_traditional_enc_op.emplace<std::unique_ptr<PK_Ops::Encryption>>(
               trad_pubkey->create_encryption_op(m_null_rng, param.traditional_padding(), provider));
         } else {
            // this cast, which would simplify the code (remove the X... branches below), doesn't work:
            //const PK_Key_Agreement_Key* ec_key = dynamic_cast<const PK_Key_Agreement_Key*>(trad_pubkey);
            //m_traditional_enc_op.emplace<std::vector<uint8_t>>(ec_key->public_value());
#if BOTAN_HAS_ECDH
            if(param.traditional_algorithm() == "ECDH") {
               const ECDH_PublicKey* ecdh_key = dynamic_cast<const ECDH_PublicKey*>(trad_pubkey);
               m_traditional_enc_op.emplace<std::vector<uint8_t>>(ecdh_key->public_value());
               m_ec_group_opt = ecdh_key->domain();
            } else
#endif
#if BOTAN_HAS_X25519
               if(param.traditional_algorithm() == "X25519") {
               const X25519_PublicKey* ecdh_key = dynamic_cast<const X25519_PublicKey*>(trad_pubkey);
               m_traditional_enc_op.emplace<std::vector<uint8_t>>(ecdh_key->public_value());
            } else
#endif
#if BOTAN_HAS_X448
               if(param.traditional_algorithm() == "X448") {
               const X448_PublicKey* ecdh_key = dynamic_cast<const X448_PublicKey*>(trad_pubkey);
               m_traditional_enc_op.emplace<std::vector<uint8_t>>(ecdh_key->public_value());
            } else
#endif
            {
               throw Not_Implemented("MLKEM_Composite_Encapsulation_Operation(): parameters not supported");
            }
         }
      }

      void kem_encrypt(std::span<uint8_t> out_encapsulated_key,
                       std::span<uint8_t> out_shared_key,
                       RandomNumberGenerator& rng,
                       size_t /*desired_shared_key_len*/,
                       std::span<const uint8_t> /*salt*/) override {
         static const std::vector<uint8_t> empty_salt;
         secure_vector<uint8_t> ss_mlkem(m_mlkem_enc_op->shared_key_length(32));
         secure_vector<uint8_t> ss_trad(traditional_shared_key_length());
         if(out_encapsulated_key.size() != encapsulated_key_length()) {
            throw Invalid_Argument(
               fmt("provided ML-KEM composite ciphertext size for output invalid: expected: {} bytes; got {} bytes",
                   encapsulated_key_length(),
                   out_encapsulated_key.size()));
         }
         const std::span<uint8_t> out_mlkem_ct(out_encapsulated_key.begin(),
                                               out_encapsulated_key.begin() + m_parameters.mlkem_ciphertext_size());
         m_mlkem_enc_op->kem_encrypt(out_mlkem_ct, ss_mlkem, rng, 32, empty_salt);
         rng.randomize_with_ts_input(ss_trad);
         std::vector<uint8_t> trad_ct;
         if(std::get_if<std::unique_ptr<PK_Ops::Encryption>>(&this->m_traditional_enc_op) != nullptr) {
            PK_Ops::Encryption& encr_op = *std::get<std::unique_ptr<PK_Ops::Encryption>>(this->m_traditional_enc_op);
            try {
               trad_ct = encr_op.encrypt(ss_trad, rng);
            } catch(const PRNG_Unseeded&) {
               throw Internal_Error(
                  "RSA encryption operation failed with PRNG_Unseeded even though use of the provided Null_RNG is not expected");
            }
         } else {
            std::unique_ptr<PK_Key_Agreement_Key> privkey;
            if(m_parameters.traditional_algorithm() == "ECDH") {
               privkey = std::make_unique<Botan::ECDH_PrivateKey>(rng, m_ec_group_opt.value());
            } else if(m_parameters.traditional_algorithm() == "X25519") {
               privkey = std::make_unique<X25519_PrivateKey>(rng);
            } else if(m_parameters.traditional_algorithm() == "X448") {
               privkey = std::make_unique<X448_PrivateKey>(rng);
            } else {
               throw Internal_Error("kem_encrypt(): requested algorithm not implemented");
            }
            perform_key_agreement(ss_trad, trad_ct, privkey.get(), rng);
         }

         std::copy(trad_ct.begin(), trad_ct.end(), out_encapsulated_key.begin() + m_parameters.mlkem_ciphertext_size());
         // ss = SHA3-256(mlkemSS || tradSS || tradCT || tradPK || Label)
         const auto sha3_256 = Botan::HashFunction::create_or_throw("SHA-3(256)");
         sha3_256->update(ss_mlkem);
         sha3_256->update(ss_trad);
         sha3_256->update(trad_ct);
         sha3_256->update(m_traditional_pubkey_encoded);
         sha3_256->update(m_parameters.label());
         sha3_256->final(out_shared_key);
      }

      void perform_key_agreement(secure_vector<uint8_t>& ss_trad,
                                 std::vector<uint8_t>& trad_ct,
                                 const PK_Key_Agreement_Key* privkey,
                                 RandomNumberGenerator& rng) {
         const Botan::PK_Key_Agreement ka(*privkey, rng, "Raw");
         std::vector<uint8_t> public_value = std::get<std::vector<uint8_t>>(m_traditional_enc_op);
         ss_trad = ka.derive_key(0, public_value).bits_of();
         trad_ct = privkey->public_value();
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override { return 32; }

      size_t traditional_shared_key_length() const {
         if(m_parameters.traditional_algorithm() == "RSA" || m_parameters.traditional_algorithm() == "X25519") {
            return 32;
         } else if(m_parameters.traditional_algorithm() == "X448") {
            return 56;
         } else if(m_parameters.traditional_algorithm() == "ECDH") {
            const size_t result = m_ec_group_opt.value().get_p_bytes();
            return result;
         }
         throw Not_Implemented("traditional_shared_key_length(): todo");
      }

      size_t traditional_ciphertext_length() const {
         size_t result = 0;
         if(m_parameters.traditional_algorithm() == "RSA") {
            result = std::get<std::unique_ptr<PK_Ops::Encryption>>(m_traditional_enc_op)
                        ->ciphertext_length(traditional_shared_key_length());
         } else if(m_parameters.traditional_algorithm() == "ECDH") {
            result = m_ec_group_opt.value().get_p_bytes() * 2 + 1;
         } else if(m_parameters.traditional_algorithm() == "X25519") {
            result = 32;
         } else if(m_parameters.traditional_algorithm() == "X448") {
            result = 56;
         } else {
            throw Not_Implemented("MLKEM_Composite_Encapsulation_Operation::traditional_ciphertext_length(): todo");
         }
         return result;
      }

      size_t encapsulated_key_length() const override {
         return m_mlkem_enc_op->encapsulated_key_length() + traditional_ciphertext_length();
      }

   private:
      MLKEM_Composite_Param m_parameters;

      std::unique_ptr<PK_Ops::KEM_Encryption> m_mlkem_enc_op;
      // This variant can be either an encryption_op (RSA-OAEP) or the public_value of key agreement key:
      std::variant<std::unique_ptr<PK_Ops::Encryption>, std::vector<uint8_t>> m_traditional_enc_op;
      std::vector<uint8_t> m_traditional_pubkey_encoded;
      std::optional<EC_Group> m_ec_group_opt;
      Null_RNG m_null_rng;
};

class MLKEM_Composite_Decapsulation_Operation final : public PK_Ops::KEM_Decryption {
   public:
      explicit MLKEM_Composite_Decapsulation_Operation(RandomNumberGenerator& rng,
                                                       const MLKEM_Composite_Param& param,
                                                       const ML_KEM_PrivateKey& mlkem_privkey,
                                                       const Private_Key* trad_privkey,
                                                       std::string_view provider) :
            m_parameters(param),
            m_mlkem_dec_op(mlkem_privkey.create_kem_decryption_op(rng, "Raw", "")),
            m_traditional_pubkey_encoded(trad_privkey->public_key()->public_key_bits()) {
         if(trad_privkey->algo_name() == "RSA") {
            m_traditional_dec_op.emplace<std::unique_ptr<PK_Ops::Decryption>>(
               trad_privkey->create_decryption_op(rng, param.traditional_padding(), provider));
            // For some reason, the RSA decryption OP can't tell us it's ciphertext size. Thus we have to delve into the details...
            m_rsa_modulus_bytes = dynamic_cast<RSA_PublicKey*>(trad_privkey->public_key().get())->get_n().bytes();
         }
#if BOTAN_HAS_ECDH
         else if(param.traditional_algorithm() == "ECDH") {
            m_traditional_dec_op.emplace<PK_Key_Agreement>(PK_Key_Agreement(*trad_privkey, rng, "Raw"));
            const ECDH_PublicKey* ecdh_key = dynamic_cast<const ECDH_PrivateKey*>(trad_privkey);
            if(ecdh_key == nullptr) {
               throw Internal_Error(
                  "ECDH_PublicKey ptr is null in MLKEM_Composite_Decapsulation_Operation, this should not happen");
            }
            m_ec_group_opt = ecdh_key->domain();
         }
#endif
         else if(contains<2>({"X25519", "X448"}, param.traditional_algorithm())) {
            m_traditional_dec_op.emplace<PK_Key_Agreement>(PK_Key_Agreement(*trad_privkey, rng, "Raw"));
         } else {
            throw Not_Implemented("MLKEM_Composite_Decapsulation_Operation()::ctor todo");
         }
      }

      void kem_decrypt(std::span<uint8_t> out_shared_key,
                       std::span<const uint8_t> encapsulated_key,
                       size_t /*desired_shared_key_len*/,
                       std::span<const uint8_t> /*salt*/) override {
         secure_vector<uint8_t> ss_mlkem(m_mlkem_dec_op->shared_key_length(32));
         secure_vector<uint8_t> ss_trad(traditional_shared_key_length());
         if(encapsulated_key.size() != encapsulated_key_length()) {
            throw Invalid_Argument(
               fmt("ML-KEM composite ciphertext length is wrong. Should be {} bytes, but is {} bytes",
                   encapsulated_key_length(),
                   encapsulated_key.size()));
         }
         const std::span<const uint8_t> mlkem_ct(encapsulated_key.begin(),
                                                 encapsulated_key.begin() + m_mlkem_dec_op->encapsulated_key_length());
         const std::span<const uint8_t> trad_ct(encapsulated_key.begin() + m_mlkem_dec_op->encapsulated_key_length(),
                                                encapsulated_key.end());
         m_mlkem_dec_op->kem_decrypt(ss_mlkem, mlkem_ct, 32, std::span<uint8_t>());

         if(std::get_if<std::unique_ptr<PK_Ops::Decryption>>(&this->m_traditional_dec_op) != nullptr) {
            PK_Ops::Decryption& decr_op = *std::get<std::unique_ptr<PK_Ops::Decryption>>(this->m_traditional_dec_op);
            uint8_t valid_mask = 0;
            ss_trad = decr_op.decrypt(valid_mask, trad_ct);
            if(valid_mask == 0) {
               // draft-ietf-lamps-pq-composite-kem-14: "In general, in the case that one of the component primitives generates an error during Composite ML-KEM KeyGen, Encaps, or Decaps, Composite ML-KEM MUST clear all buffers containing key material and forward the error to its caller; i.e. Composite ML-KEM MUST be explicitly rejecting whenever one of its components is."
               throw Invalid_Argument("ciphertext was rejected during decryption");
            }
         } else if(contains<3>({"ECDH", "X25519", "X448"}, m_parameters.traditional_algorithm())) {
            ss_trad = std::get<PK_Key_Agreement>(m_traditional_dec_op).derive_key(0, trad_ct).bits_of();
         } else {
            throw Not_Implemented("kem_decrypt: unknown algo " + m_parameters.traditional_algorithm());
         }

         const auto sha3_256 = Botan::HashFunction::create_or_throw("SHA-3(256)");
         sha3_256->update(ss_mlkem);
         sha3_256->update(ss_trad);
         sha3_256->update(trad_ct);
         sha3_256->update(m_traditional_pubkey_encoded);
         sha3_256->update(m_parameters.label());
         sha3_256->final(out_shared_key);
      }

      size_t shared_key_length(size_t /*desired_shared_key_len*/) const override { return 32; }

      size_t traditional_shared_key_length() const {
         if(m_parameters.traditional_algorithm() == "RSA" || m_parameters.traditional_algorithm() == "X25519") {
            return 32;
         } else if(m_parameters.traditional_algorithm() == "X448") {
            return 56;
         } else if(m_parameters.traditional_algorithm() == "ECDH") {
            const size_t result = m_ec_group_opt.value().get_p_bytes();
            if(result > (521 + 7) / 8) {
               throw Internal_Error("invalid ECC public key size");
            }
            return result;
         }
         throw Internal_Error("traditional_shared_key_length(): Unknown algorithm");
      }

      size_t traditional_ciphertext_length() const {
         if(m_parameters.traditional_algorithm() == "RSA") {
            return m_rsa_modulus_bytes;
         } else if(m_parameters.traditional_algorithm() == "ECDH") {
            const size_t result = m_ec_group_opt.value().get_p_bytes() * 2 + 1;
            return result;
         } else if(m_parameters.traditional_algorithm() == "X25519") {
            return 32;
         } else if(m_parameters.traditional_algorithm() == "X448") {
            return 56;
         }

         throw Internal_Error("traditional_ciphertext_length(): unknown algorithm");
      }

      size_t encapsulated_key_length() const override {
         return m_mlkem_dec_op->encapsulated_key_length() + traditional_ciphertext_length();
      }

   private:
      MLKEM_Composite_Param m_parameters;
      std::unique_ptr<PK_Ops::KEM_Decryption> m_mlkem_dec_op;
      std::variant<std::unique_ptr<PK_Ops::Decryption>, PK_Key_Agreement> m_traditional_dec_op;
      std::vector<uint8_t> m_traditional_pubkey_encoded;
      size_t m_rsa_modulus_bytes = 0;
      std::optional<EC_Group> m_ec_group_opt;
};

// static
std::shared_ptr<Public_Key> MLKEM_Composite_PublicKey::load_traditional_public_key(const MLKEM_Composite_Param& param,
                                                                                   std::span<const uint8_t> key_bits) {
#if defined(BOTAN_HAS_ECDH)
   if(param.traditional_algorithm() == "ECDH") {
      const auto group = Botan::EC_Group::from_name(param.curve());
      return std::make_shared<Botan::ECDH_PublicKey>(group, EC_AffinePoint(group, key_bits));
   }
#endif
   return load_public_key(param.get_traditional_algorithm_id(), key_bits);
}

MLKEM_Composite_PublicKey::MLKEM_Composite_PublicKey(const MLKEM_Composite_PublicKey& other) :
      m_parameters(std::make_shared<MLKEM_Composite_Param>(*other.m_parameters)),
      m_mlkem_pubkey(std::make_shared<ML_KEM_PublicKey>(*other.m_mlkem_pubkey)),
      m_traditional_pubkey(load_traditional_public_key(*m_parameters, other.m_traditional_pubkey->public_key_bits())) {}

MLKEM_Composite_PublicKey::MLKEM_Composite_PublicKey(const AlgorithmIdentifier& algo_id,
                                                     std::span<const uint8_t> key_bits) :
      m_parameters(std::make_shared<MLKEM_Composite_Param>(MLKEM_Composite_Param::from_algo_id_or_throw(algo_id))),
      m_mlkem_pubkey(std::make_shared<ML_KEM_PublicKey>(m_parameters->get_mlkem_algorithm_id(),
                                                        mlkem_pubkey_subspan(*m_parameters, key_bits))),
      m_traditional_pubkey(
         load_traditional_public_key(*m_parameters, traditional_pubkey_subspan(*m_parameters, key_bits))) {}

MLKEM_Composite_PublicKey::MLKEM_Composite_PublicKey(MLKEM_Composite_Param::id_t id,
                                                     std::span<const uint8_t> key_bits) :
      m_parameters(std::make_shared<MLKEM_Composite_Param>(MLKEM_Composite_Param::from_id_supported_or_throw(id))),
      m_mlkem_pubkey(std::make_shared<ML_KEM_PublicKey>(m_parameters->get_mlkem_algorithm_id(),
                                                        mlkem_pubkey_subspan(*m_parameters, key_bits))),
      m_traditional_pubkey(
         load_traditional_public_key(*m_parameters, traditional_pubkey_subspan(*m_parameters, key_bits))) {}

MLKEM_Composite_PublicKey& MLKEM_Composite_PublicKey::operator=(const MLKEM_Composite_PublicKey& rhs) {
   if(this == &rhs) {
      return *this;
   }
   m_parameters = std::make_shared<MLKEM_Composite_Param>(*rhs.m_parameters);
   m_mlkem_pubkey = std::make_shared<ML_KEM_PublicKey>(*rhs.m_mlkem_pubkey);
   m_traditional_pubkey = load_traditional_public_key(*m_parameters, rhs.m_traditional_pubkey->public_key_bits());
   return *this;
}

std::vector<uint8_t> MLKEM_Composite_PublicKey::raw_public_key_bits() const {
   return public_key_bits();
}

OID MLKEM_Composite_PublicKey::object_identifier() const {
   return m_parameters->object_identifier();
}

std::vector<uint8_t> MLKEM_Composite_PublicKey::public_key_bits() const {
   std::vector<uint8_t> result(this->m_mlkem_pubkey->public_key_bits());
   std::vector<uint8_t> trad_bytes = this->m_traditional_pubkey->public_key_bits();
   result.insert(result.end(), trad_bytes.begin(), trad_bytes.end());
   return result;
}

std::unique_ptr<Private_Key> MLKEM_Composite_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<MLKEM_Composite_PrivateKey>(rng, *m_parameters);
}

std::unique_ptr<PK_Ops::KEM_Encryption> MLKEM_Composite_PublicKey::create_kem_encryption_op(
   std::string_view params, std::string_view provider) const {
   if(!params.empty() && params != "Raw") {
      throw Botan::Invalid_Argument("only empty parameters or 'Raw' is supported by MLKEM-composite KEM");
   }
   if(provider.empty() || provider == "base") {
      return std::make_unique<MLKEM_Composite_Encapsulation_Operation>(
         *this->m_parameters, *this->m_mlkem_pubkey, this->m_traditional_pubkey.get(), provider);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::shared_ptr<Private_Key> MLKEM_Composite_PrivateKey::load_traditional_private_key(
   const MLKEM_Composite_Param& param, std::span<const uint8_t> trad_key_bits) {
#if defined(BOTAN_HAS_X25519)
   if(param.traditional_algorithm() == "X25519") {
      return std::shared_ptr<Private_Key>(std::make_shared<X25519_PrivateKey>((X25519_PrivateKey(trad_key_bits))));
   }
#endif
#if defined(BOTAN_HAS_X448)
   if(param.traditional_algorithm() == "X448") {
      return std::shared_ptr<Private_Key>(std::make_shared<X448_PrivateKey>((X448_PrivateKey(trad_key_bits))));
   }
#endif

   return load_private_key(param.get_traditional_algorithm_id(), trad_key_bits);
}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(MLKEM_Composite_Param::id_t id, std::span<const uint8_t> sk) :
      m_parameters(std::make_shared<MLKEM_Composite_Param>(MLKEM_Composite_Param::from_id_supported_or_throw(id))),
      m_mlkem_privkey(std::make_shared<ML_KEM_PrivateKey>(m_parameters->get_mlkem_algorithm_id(),
                                                          mlkem_privkey_subspan(*m_parameters, sk))),
      m_traditional_privkey(
         load_traditional_private_key(*m_parameters, traditional_privkey_subspan(*m_parameters, sk))) {
   init_pubkey_members();
}

secure_vector<uint8_t> MLKEM_Composite_PrivateKey::encode_traditional_private_key() const {
   secure_vector<uint8_t> trad_bytes;

   if(m_parameters->traditional_algorithm() == "ECDH") {
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
      const OID oid = OIDS::str2oid_or_empty(m_parameters->curve());
      BOTAN_ASSERT(!oid.empty(), "lookup of MLKEM-composite elliptic curve OID");
      trad_bytes = DER_Encoder()
                      .start_sequence()
                      .encode(static_cast<size_t>(1))
                      .encode(m_traditional_privkey->raw_private_key_bits(), ASN1_Type::OctetString)
                      .start_explicit_context_specific(0)
                      .encode(oid)
                      .end_cons()
                      .end_cons()
                      .get_contents();
   } else {
      trad_bytes = m_traditional_privkey->private_key_bits();
   }
   if(m_parameters->traditional_algorithm() == "X25519" || m_parameters->traditional_algorithm() == "X448") {
      secure_vector<uint8_t> key_bits;
      BER_Decoder(trad_bytes).decode(key_bits, ASN1_Type::OctetString).discard_remaining();
      std::swap(trad_bytes, key_bits);
   }
   return trad_bytes;
}

secure_vector<uint8_t> MLKEM_Composite_PrivateKey::private_key_bits() const {
   secure_vector<uint8_t> result =
      m_mlkem_privkey
         ->raw_private_key_bits();  // "raw_...()" should still return the raw seed even after fixing the PKCS#8 encoding format for ML-KEM
   secure_vector<uint8_t> trad_bytes = encode_traditional_private_key();
   result.insert(result.end(), trad_bytes.begin(), trad_bytes.end());
   return result;
}

secure_vector<uint8_t> MLKEM_Composite_PrivateKey::raw_private_key_bits() const {
   return private_key_bits();
}

std::unique_ptr<Public_Key> MLKEM_Composite_PrivateKey::public_key() const {
   return std::make_unique<MLKEM_Composite_PublicKey>(*this);
}

/**
       * Create a decryption operation that produces a MLKEM_Composite KEM Decryption Operation.
       */
std::unique_ptr<PK_Ops::KEM_Decryption> MLKEM_Composite_PrivateKey::create_kem_decryption_op(
   RandomNumberGenerator& rng, std::string_view params, std::string_view provider) const {
   if(!params.empty() && params != "Raw") {
      throw Botan::Invalid_Argument("only empty parameters or 'Raw' is supported by MLKEM-composite KEM");
   }
   if(provider.empty() || provider == "base") {
      auto result = std::make_unique<MLKEM_Composite_Decapsulation_Operation>(
         rng, *this->m_parameters, *this->m_mlkem_privkey, this->m_traditional_privkey.get(), provider);
      return result;
   }
   throw Provider_Not_Found(algo_name(), provider);
}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(const AlgorithmIdentifier& algo_id,
                                                       std::span<const uint8_t> sk) :

      m_parameters(std::make_shared<MLKEM_Composite_Param>(MLKEM_Composite_Param::from_algo_id_or_throw(algo_id))),
      m_mlkem_privkey(std::make_shared<ML_KEM_PrivateKey>(m_parameters->get_mlkem_algorithm_id(),
                                                          mlkem_privkey_subspan(*m_parameters, sk))),
      m_traditional_privkey(load_traditional_private_key(*m_parameters, traditional_privkey_subspan(*m_parameters, sk)))

{
   init_pubkey_members();
}

// static
std::unique_ptr<Private_Key> MLKEM_Composite_PrivateKey::create_traditional_private_key(RandomNumberGenerator& rng,
                                                                                        MLKEM_Composite_Param param) {
#if defined(BOTAN_HAS_ECDH)
   if(param.traditional_algorithm() == "ECDH") {
      const auto group = Botan::EC_Group::from_name(param.curve());
      return std::make_unique<Botan::ECDH_PrivateKey>(rng, group);
   }
#endif
   return create_private_key(param.traditional_algorithm(), rng, param.get_traditional_algo_param_str());
}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(RandomNumberGenerator& rng, MLKEM_Composite_Param param) :
      m_parameters(std::make_shared<MLKEM_Composite_Param>(param)),
      m_mlkem_privkey(std::make_shared<ML_KEM_PrivateKey>(rng, m_parameters->get_mlkem_mode())),
      m_traditional_privkey(create_traditional_private_key(rng, param)) {
   init_pubkey_members();
}

void MLKEM_Composite_PrivateKey::init_pubkey_members() {
   MLKEM_Composite_PublicKey::m_parameters = m_parameters;
   MLKEM_Composite_PublicKey::m_mlkem_pubkey = m_mlkem_privkey;
   MLKEM_Composite_PublicKey::m_traditional_pubkey = m_traditional_privkey;
}

MLKEM_Composite_PrivateKey::MLKEM_Composite_PrivateKey(const MLKEM_Composite_PrivateKey& other) :
      MLKEM_Composite_PublicKey(other),  // this assigns private-key independent members in the public key!
      m_parameters(std::make_shared<MLKEM_Composite_Param>(*other.m_parameters)),
      m_mlkem_privkey(std::make_shared<ML_KEM_PrivateKey>(*other.m_mlkem_privkey)),
      m_traditional_privkey(load_traditional_private_key(
         *m_parameters, traditional_privkey_subspan(*m_parameters, other.private_key_bits()))) {
   init_pubkey_members();  // set them as shared, otherwise inconsistency may result
}

MLKEM_Composite_PrivateKey& MLKEM_Composite_PrivateKey::operator=(const MLKEM_Composite_PrivateKey& rhs) {
   if(this == &rhs) {
      return *this;
   }
   m_parameters = std::make_shared<MLKEM_Composite_Param>(*rhs.m_parameters);
   m_mlkem_privkey = std::make_shared<ML_KEM_PrivateKey>(*rhs.m_mlkem_privkey);
   m_traditional_privkey =
      load_traditional_private_key(*m_parameters, traditional_privkey_subspan(*m_parameters, rhs.private_key_bits()));
   init_pubkey_members();  // set them as shared, otherwise inconsistency may result

   return *this;
}
}  // namespace Botan
