#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/ed25519.h>
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/ml_dsa.h>
#include <botan/mldsa_comp.h>
#include <botan/pk_algs.h>
#include <botan/pk_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/pk_ops_impl.h>
#include <cstring>
#include <memory>
#include <string_view>
#include <vector>

#include <iostream>

namespace Botan {

namespace {
std::span<const uint8_t> mldsa_pubkey_subspan(const MLDSA_Composite_Param& param, std::span<const uint8_t> key_bits) {
   OID oid(param.mldsa_oid_str);
   AlgorithmIdentifier aid(oid, AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
   if(key_bits.size() <= param.mldsa_pubkey_size) {
      throw Invalid_Argument(fmt("encoded MLDSA component public key is too short (len = {})", key_bits.size()));
   }
   return std::span<const uint8_t>(key_bits.begin(), param.mldsa_pubkey_size);
}

std::span<const uint8_t> mldsa_privkey_subspan(const MLDSA_Composite_Param& param, std::span<const uint8_t> key_bits) {
   OID oid(param.mldsa_oid_str);
   AlgorithmIdentifier aid(oid, AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
   if(key_bits.size() <= param.mldsa_privkey_size()) {
      throw Invalid_Argument("encoded MLDSA component private key is too short");
   }
   std::cout << "mldsa_privkey_subspan(): trad private key size = " << key_bits.size() - param.mldsa_privkey_size()
             << std::endl;
   return std::span<const uint8_t>(key_bits.begin(), param.mldsa_privkey_size());
}

std::span<const uint8_t> traditional_pubkey_subspan(const MLDSA_Composite_Param& param,
                                                    std::span<const uint8_t> key_bits) {
   const size_t offset = param.mldsa_pubkey_size;
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument(fmt("encoded traditional component public key is too short (len = {})", key_bits.size()));
   }
   // debug ->
   // if(param.id == MLDSA_Composite_Param::id_t::MLDSA44_ECDSA_P256_SHA256) {
   //    std::vector<uint8_t> ecdsa_pub_bytes(key_bits.begin() + offset, key_bits.end());
   //    std::cout << "ECDSA Public Key bytes = " << hex_encode(ecdsa_pub_bytes) << std::endl;
   // }
   // <-
   std::span<const uint8_t> result(key_bits.begin() + offset, key_bits.end());
   return result;
}

std::span<const uint8_t> traditional_privkey_subspan(const MLDSA_Composite_Param& param,
                                                     std::span<const uint8_t> key_bits) {
   const size_t offset = param.mldsa_privkey_size();
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument("encoded traditional component private key is too short");
   }
   std::span<const uint8_t> result(key_bits.begin() + offset, key_bits.end());
   std::cout << fmt("traditional priv key (length = {}) = {}\n", key_bits.size() - offset, hex_encode(result));
   return result;
}
}  // namespace

class MLDSA_Composite_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      explicit MLDSA_Composite_Verification_Operation(const MLDSA_Composite_Param& param,
                                                      const ML_DSA_PublicKey& mldsa_pubkey,
                                                      const Public_Key* trad_pubkey) :
            PK_Ops::Verification_with_Hash(param.prehash_func),
            m_parameters(param),
            m_mldsa_ver_op(mldsa_pubkey.create_verification_op(param.mldsa_param_str(), "")),
            m_traditional_ver_op(trad_pubkey->create_verification_op(param.traditional_padding, "")) {}

      bool verify(std::span<const uint8_t> ph, std::span<const uint8_t> sig) override {
         //  M' = Prefix || Label || len(ctx) || ctx || PH( M )
         std::string msg_str = "CompositeAlgorithmSignatures2025";
         msg_str += m_parameters.label;
         std::vector<uint8_t> msg(msg_str.begin(), msg_str.end());
         msg.push_back(0);  // ctx = empty
         msg.insert(msg.end(), ph.begin(), ph.end());
         size_t mldsa_sig_size = m_parameters.mldsa_signature_size();
         m_mldsa_ver_op->update(msg);
         m_traditional_ver_op->update(msg);

         if(sig.size() <= mldsa_sig_size) {
            return false;
         }
         std::span<const uint8_t> mldsa_sig(sig.begin(), sig.begin() + mldsa_sig_size);
         std::span<const uint8_t> trad_sig(sig.begin() + mldsa_sig_size, sig.end());
         std::vector<uint8_t> trad_sig_buf;
         if(0 == std::strcmp(m_parameters.traditional_algoritm, "ECDSA")) {
            std::cout << "MLDSA_Composite_Verification_Operation: Verifying ECDSA signature: " << hex_encode(trad_sig)
                      << std::endl;
            BER_Decoder dec(trad_sig);
            BigInt ri;
            BigInt si;
            dec.start_sequence().decode(ri).decode(si).end_cons();
            const auto group = Botan::EC_Group::from_name(m_parameters.curve);
            EC_Scalar r = EC_Scalar::from_bigint(group, ri);
            std::cout << "  decoded r from signature = " << hex_encode(r.serialize()) << std::endl;
            EC_Scalar s = EC_Scalar::from_bigint(group, si);
            std::cout << "  decoded s from signature = " << hex_encode(s.serialize()) << std::endl;

            trad_sig_buf = EC_Scalar::serialize_pair(r, s);
            trad_sig = trad_sig_buf;
            std::cout << "  serialized pair = " << hex_encode(trad_sig) << std::endl;
         }
         if(!m_mldsa_ver_op->is_valid_signature(mldsa_sig)) {
            return false;
         }
         if(!m_traditional_ver_op->is_valid_signature(trad_sig)) {
            return false;
         }
         return true;
      }

   private:
      MLDSA_Composite_Param m_parameters;
      std::unique_ptr<PK_Ops::Verification> m_mldsa_ver_op;
      std::unique_ptr<PK_Ops::Verification> m_traditional_ver_op;
};

class MLDSA_Composite_Signature_Operation final : public PK_Ops::Signature_with_Hash {
   public:
      MLDSA_Composite_Signature_Operation(const MLDSA_Composite_Param& param,
                                          const ML_DSA_PrivateKey& mldsa_privkey,
                                          const Private_Key* trad_privkey,
                                          RandomNumberGenerator& rng) :

            PK_Ops::Signature_with_Hash(param.prehash_func),
            m_parameters(param),
            m_mldsa_sig_op(mldsa_privkey.create_signature_op(rng, param.mldsa_param_str(), "")),
            m_traditional_sig_op(trad_privkey->create_signature_op(rng, param.traditional_padding, "")) {}

      std::vector<uint8_t> raw_sign(std::span<const uint8_t> ph, RandomNumberGenerator& rng) override {
         //  M' = Prefix || Label || len(ctx) || ctx || PH( M )
         std::string msg_str = "CompositeAlgorithmSignatures2025";
         msg_str += m_parameters.label;
         std::vector<uint8_t> msg(msg_str.begin(), msg_str.end());
         msg.push_back(0);  // ctx = empty
         msg.insert(msg.end(), ph.begin(), ph.end());
         m_mldsa_sig_op->update(msg);
         m_traditional_sig_op->update(msg);
         auto sig = m_mldsa_sig_op->sign(rng);
         auto trad_sig = m_traditional_sig_op->sign(rng);
         if(0 == std::strcmp(m_parameters.traditional_algoritm, "ECDSA")) {
            BOTAN_ASSERT(trad_sig.size() % 2 == 0, "ECDSA signature size is not divisible by 2");
            std::vector<uint8_t> enc_sig;
            std::span<uint8_t> rs(trad_sig.begin(), trad_sig.begin() + trad_sig.size() / 2);
            std::span<uint8_t> ss(trad_sig.begin() + trad_sig.size() / 2, trad_sig.end());
            BigInt r(rs);
            BigInt s(ss);
            DER_Encoder enc(enc_sig);
            enc.start_sequence().encode(r).encode(s).end_cons();
            std::swap(trad_sig, enc_sig);
         }
         sig.insert(sig.end(), trad_sig.begin(), trad_sig.end());
         return sig;
      }

      size_t signature_length() const override { return m_parameters.signature_size(); }

      AlgorithmIdentifier algorithm_identifier() const override { return m_parameters.get_composite_algorithm_id(); }

   private:

   private:
      MLDSA_Composite_Param m_parameters;
      std::unique_ptr<PK_Ops::Signature> m_mldsa_sig_op;
      std::unique_ptr<PK_Ops::Signature> m_traditional_sig_op;
};

// static
std::shared_ptr<Public_Key> MLDSA_Composite_PublicKey::load_traditional_public_key(const MLDSA_Composite_Param& param,
                                                                                   std::span<const uint8_t> key_bits) {
   if(0 == strcmp(param.traditional_algoritm, "ECDSA")) {
      const auto group = Botan::EC_Group::from_name(param.curve);
      std::cout << fmt("load_traditional_public_key(): decoding ECDSA_PublicKey of length {}\n", key_bits.size());

      return std::make_shared<Botan::ECDSA_PublicKey>(group, EC_AffinePoint(group, key_bits));
   }
   return load_public_key(param.get_traditional_algorithm_id(), key_bits);
}

MLDSA_Composite_PublicKey::MLDSA_Composite_PublicKey(const MLDSA_Composite_PublicKey& other) :
      m_parameters(std::make_shared<MLDSA_Composite_Param>(*other.m_parameters)),
      m_mldsa_pubkey(std::make_shared<ML_DSA_PublicKey>(*other.m_mldsa_pubkey)),
      // m_tradtional_pubkey(std::make_shared<Public_Key>(*other.m_tradtional_pubkey)) {}
      m_tradtional_pubkey(load_traditional_public_key(*m_parameters, other.m_tradtional_pubkey->public_key_bits())) {}

MLDSA_Composite_PublicKey::MLDSA_Composite_PublicKey(const AlgorithmIdentifier& algo_id,
                                                     std::span<const uint8_t> key_bits) :
      m_parameters(std::make_shared<MLDSA_Composite_Param>(MLDSA_Composite_Param::from_algo_id_or_throw(algo_id))),
      m_mldsa_pubkey(std::make_shared<ML_DSA_PublicKey>(m_parameters->get_mldsa_algorithm_id(),
                                                        mldsa_pubkey_subspan(*m_parameters, key_bits))),
      m_tradtional_pubkey(
         load_traditional_public_key(*m_parameters, traditional_pubkey_subspan(*m_parameters, key_bits))) {}

MLDSA_Composite_PublicKey::MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t id,
                                                     std::span<const uint8_t> key_bits) :
      m_parameters(std::make_shared<MLDSA_Composite_Param>(MLDSA_Composite_Param::from_id_or_throw(id))),
      m_mldsa_pubkey(std::make_shared<ML_DSA_PublicKey>(m_parameters->get_mldsa_algorithm_id(),
                                                        mldsa_pubkey_subspan(*m_parameters, key_bits))),
      m_tradtional_pubkey(
         load_traditional_public_key(*m_parameters, traditional_pubkey_subspan(*m_parameters, key_bits))) {}

MLDSA_Composite_PublicKey& MLDSA_Composite_PublicKey::operator=(const MLDSA_Composite_PublicKey& rhs) {
   if(this == &rhs) {
      return *this;
   }
   m_parameters = std::make_shared<MLDSA_Composite_Param>(*rhs.m_parameters);
   m_mldsa_pubkey = std::make_shared<ML_DSA_PublicKey>(*rhs.m_mldsa_pubkey);
   //  m_tradtional_pubkey = std::make_shared<Public_Key>(*rhs.m_tradtional_pubkey);
   m_tradtional_pubkey =
      load_public_key(m_parameters->get_traditional_algorithm_id(), rhs.m_tradtional_pubkey->public_key_bits());
   return *this;
}

std::vector<uint8_t> MLDSA_Composite_PublicKey::raw_public_key_bits() const {
   return public_key_bits();
}

OID MLDSA_Composite_PublicKey::object_identifier() const {
   return m_parameters->object_identifier();
}

std::vector<uint8_t> MLDSA_Composite_PublicKey::public_key_bits() const {
   std::vector<uint8_t> result(this->m_mldsa_pubkey->public_key_bits());
   std::vector<uint8_t> trad_bytes = this->m_tradtional_pubkey->public_key_bits();
   if(0 == strcmp(m_parameters->traditional_algoritm, "ECDSA")) {
      std::cout << fmt("encoded ECDSA public key (len = {}) = {}\n", trad_bytes.size(), hex_encode(trad_bytes));
   }
   result.insert(result.end(), trad_bytes.begin(), trad_bytes.end());
   return result;
}

std::unique_ptr<Private_Key> MLDSA_Composite_PublicKey::generate_another(RandomNumberGenerator& rng) const {
   return std::make_unique<MLDSA_Composite_PrivateKey>(rng, *m_parameters);
}

// ALLOW NON-EMPTY CTX VIA PARAMS?
std::unique_ptr<PK_Ops::Verification> MLDSA_Composite_PublicKey::create_verification_op(
   std::string_view params_for_ctx, std::string_view provider) const {
   std::cout << "MLDSA_Composite_PublicKey::create_verification_op() called\n";
   if(params_for_ctx != "") {
      throw Botan::Invalid_Argument("signature parameters not supported for MLDSA composite signatures");
   }
   if(provider.empty() || provider == "base") {
      return std::make_unique<MLDSA_Composite_Verification_Operation>(
         *this->m_parameters, *this->m_mldsa_pubkey, this->m_tradtional_pubkey.get());
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> MLDSA_Composite_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& alg_id, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      if(alg_id != this->algorithm_identifier()) {
         throw Decoding_Error("Unexpected AlgorithmIdentifier for MLDSA-Composite X.509 signature");
      }
      return std::make_unique<MLDSA_Composite_Verification_Operation>(
         *this->m_parameters, *this->m_mldsa_pubkey, this->m_tradtional_pubkey.get());
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::shared_ptr<Private_Key> MLDSA_Composite_PrivateKey::load_traditional_private_key(
   const MLDSA_Composite_Param& param, std::span<const uint8_t> trad_key_bits) {
   if(0 == strcmp(param.traditional_algoritm, "Ed25519")) {
      std::cout << fmt("load_traditional_private_key(): decoding Ed25519_PrivateKey of length {}\n",
                       trad_key_bits.size());
      return std::shared_ptr<Private_Key>(new Ed25519_PrivateKey(Ed25519_PrivateKey::from_seed(trad_key_bits)));
   }
   if(0 == strcmp(param.traditional_algoritm, "ECDSA")) {
      /* Must decode this private key format:
 * SEQUENCE {
  INTEGER 1
  OCTET STRING
    B9 4E 76 09 A7 17 6A BA FB D4 A3 4F AB AE 42 B0
    91 E4 4D 9E 46 E6 7F CA 56 6C 2A 18 8A 63 C6 5F
  [0] {
    OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
    }
  } */
      std::cout << "load_traditional_private_key(): about to decode ECDSA key\n";
      return std::make_shared<ECDSA_PrivateKey>(param.get_traditional_algorithm_id(), trad_key_bits);
   }
   return load_private_key(param.get_traditional_algorithm_id(), trad_key_bits);
}

MLDSA_Composite_PrivateKey::MLDSA_Composite_PrivateKey(MLDSA_Composite_Param::id_t id, std::span<const uint8_t> sk) :
      m_parameters(std::make_shared<MLDSA_Composite_Param>(MLDSA_Composite_Param::from_id_or_throw(id))),
      m_mldsa_privkey(std::make_shared<ML_DSA_PrivateKey>(m_parameters->get_mldsa_algorithm_id(),
                                                          mldsa_privkey_subspan(*m_parameters, sk))),
      m_tradtional_privkey(
         load_traditional_private_key(*m_parameters, traditional_privkey_subspan(*m_parameters, sk))) {
   init_pubkey_members();
}

secure_vector<uint8_t> MLDSA_Composite_PrivateKey::private_key_bits() const {
   secure_vector<uint8_t> result =
      m_mldsa_privkey
         ->raw_private_key_bits();  // "raw_...()" should still return the raw seed even after fixing the PKCS#8 encoding format for ML-DSA
   secure_vector<uint8_t> trad_bytes;
   if(0 == strcmp(m_parameters->traditional_algoritm, "ECDSA")) {
      trad_bytes = m_tradtional_privkey->raw_private_key_bits();
   } else {
      trad_bytes = m_tradtional_privkey->private_key_bits();
   }
   if(0 == strcmp(m_parameters->traditional_algoritm, "Ed25519")) {
      secure_vector<uint8_t> key_bits;
      BER_Decoder(trad_bytes).decode(key_bits, ASN1_Type::OctetString).discard_remaining();
      std::swap(trad_bytes, key_bits);
   }
   result.insert(result.end(), trad_bytes.begin(), trad_bytes.end());
   return result;
}

secure_vector<uint8_t> MLDSA_Composite_PrivateKey::raw_private_key_bits() const {
   return private_key_bits();
}

std::unique_ptr<Public_Key> MLDSA_Composite_PrivateKey::public_key() const {
   return std::make_unique<MLDSA_Composite_PublicKey>(*this);
}

/**
       * Create a signature operation that produces a MLDSA_Composite signature.
       */
std::unique_ptr<PK_Ops::Signature> MLDSA_Composite_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                                                                   std::string_view params_for_ctx,
                                                                                   std::string_view provider) const {
   if(params_for_ctx != "") {
      throw Botan::Invalid_Argument("signature parameters not supported for MLDSA composite signatures");
   }
   if(provider.empty() || provider == "base") {
      return std::make_unique<MLDSA_Composite_Signature_Operation>(
         *this->m_parameters, *this->m_mldsa_privkey, this->m_tradtional_privkey.get(), rng);
   }
   throw Provider_Not_Found(algo_name(), provider);
}

MLDSA_Composite_PrivateKey::MLDSA_Composite_PrivateKey(const AlgorithmIdentifier& algo_id,
                                                       std::span<const uint8_t> sk) :

      m_parameters(std::make_shared<MLDSA_Composite_Param>(MLDSA_Composite_Param::from_algo_id_or_throw(algo_id))),
      m_mldsa_privkey(std::make_shared<ML_DSA_PrivateKey>(m_parameters->get_mldsa_algorithm_id(),
                                                          mldsa_privkey_subspan(*m_parameters, sk))),
      m_tradtional_privkey(load_traditional_private_key(*m_parameters, traditional_privkey_subspan(*m_parameters, sk)))

{
   init_pubkey_members();
}

// static
std::unique_ptr<Private_Key> MLDSA_Composite_PrivateKey::create_traditional_private_key(RandomNumberGenerator& rng,
                                                                                        MLDSA_Composite_Param param) {
   if(0 != std::strcmp(param.traditional_algoritm, "ECDSA")) {
      return create_private_key(param.traditional_algoritm, rng, param.get_traditional_algo_param_str());
   }
   const auto group = Botan::EC_Group::from_name(param.curve);
   return std::make_unique<Botan::ECDSA_PrivateKey>(rng, group);
}

MLDSA_Composite_PrivateKey::MLDSA_Composite_PrivateKey(RandomNumberGenerator& rng, MLDSA_Composite_Param param) :
      m_parameters(std::make_shared<MLDSA_Composite_Param>(param)),
      m_mldsa_privkey(std::make_shared<ML_DSA_PrivateKey>(rng, m_parameters->get_mldsa_mode())),
      m_tradtional_privkey(create_traditional_private_key(rng, param)) {
   init_pubkey_members();
}

void MLDSA_Composite_PrivateKey::init_pubkey_members() {
   MLDSA_Composite_PublicKey::m_parameters = m_parameters;
   MLDSA_Composite_PublicKey::m_mldsa_pubkey = m_mldsa_privkey;
   MLDSA_Composite_PublicKey::m_tradtional_pubkey = m_tradtional_privkey;
}

MLDSA_Composite_PrivateKey::MLDSA_Composite_PrivateKey(const MLDSA_Composite_PrivateKey& other) :
      MLDSA_Composite_PublicKey(other),  // this assigns private-key independent members in the public key!
      m_parameters(std::make_shared<MLDSA_Composite_Param>(*other.m_parameters)),
      m_mldsa_privkey(std::make_shared<ML_DSA_PrivateKey>(*other.m_mldsa_privkey)),
      m_tradtional_privkey(
         load_traditional_private_key(*m_parameters, other.m_tradtional_privkey->private_key_bits())) {
   init_pubkey_members();  // set them as shared, otherwise inconsistency may result
}

MLDSA_Composite_PrivateKey& MLDSA_Composite_PrivateKey::operator=(const MLDSA_Composite_PrivateKey& rhs) {
   if(this == &rhs) {
      return *this;
   }
   m_parameters = std::make_shared<MLDSA_Composite_Param>(*rhs.m_parameters);
   m_mldsa_privkey = std::make_shared<ML_DSA_PrivateKey>(*rhs.m_mldsa_privkey);
   m_tradtional_privkey = load_traditional_private_key(
      *m_parameters, traditional_privkey_subspan(*m_parameters, rhs.m_tradtional_privkey->private_key_bits()));
   init_pubkey_members();
   return *this;
}
}  // namespace Botan
