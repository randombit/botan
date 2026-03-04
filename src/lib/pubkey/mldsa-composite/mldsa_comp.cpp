
#include "botan/internal/fmt.h"
#include "botan/internal/pk_ops_impl.h"
#include "botan/ml_dsa.h"
#include "botan/pk_ops.h"
#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/hex.h>
#include <botan/mldsa_comp.h>
#include <botan/pk_algs.h>
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
      throw Invalid_Argument("encoded key is too short");
   }
   return std::span<const uint8_t>(key_bits.begin(), param.mldsa_pubkey_size);
}

std::span<const uint8_t> mldsa_privkey_subspan(const MLDSA_Composite_Param& param, std::span<const uint8_t> key_bits) {
   OID oid(param.mldsa_oid_str);
   AlgorithmIdentifier aid(oid, AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
   if(key_bits.size() <= param.mldsa_privkey_size()) {
      throw Invalid_Argument("encoded key is too short");
   }
   return std::span<const uint8_t>(key_bits.begin(), param.mldsa_privkey_size());
}

std::span<const uint8_t> traditional_pubkey_subspan(const MLDSA_Composite_Param& param,
                                                    std::span<const uint8_t> key_bits) {
   const size_t offset = param.mldsa_pubkey_size;
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument("encoded key is too short");
   }
   std::span<const uint8_t> result(key_bits.begin() + offset, key_bits.end());
   return result;
}

std::span<const uint8_t> traditional_privkey_subspan(const MLDSA_Composite_Param& param,
                                                     std::span<const uint8_t> key_bits) {
   const size_t offset = param.mldsa_privkey_size();
   if(key_bits.size() <= 1 + offset) {
      throw Invalid_Argument("encoded key is too short");
   }
   std::span<const uint8_t> result(key_bits.begin() + offset, key_bits.end());
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
         sig.insert(sig.end(), trad_sig.begin(), trad_sig.end());
         return sig;
      }

      //std::vector<uint8_t> sign(RandomNumberGenerator& rng) override { throw Botan::Exception("TODO: NOT IMPLMENTED"); }

      size_t signature_length() const override { return m_parameters.signature_size(); }

      AlgorithmIdentifier algorithm_identifier() const override { throw Botan::Exception("TODO: NOT IMPLMENTED"); }

   private:

   private:
      MLDSA_Composite_Param m_parameters;
      std::unique_ptr<PK_Ops::Signature> m_mldsa_sig_op;
      std::unique_ptr<PK_Ops::Signature> m_traditional_sig_op;
};

MLDSA_Composite_PublicKey::MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t id,
                                                     std::span<const uint8_t> key_bits) :
      m_parameters(std::make_shared<MLDSA_Composite_Param>(MLDSA_Composite_Param::get_param_by_id(id))),
      m_mldsa_pubkey(std::make_unique<ML_DSA_PublicKey>(m_parameters->get_mldsa_algorithm_id(),
                                                        mldsa_pubkey_subspan(*m_parameters, key_bits))),
      m_tradtional_pubkey(load_public_key(m_parameters->get_traditional_algorithm_id(),
                                          traditional_pubkey_subspan(*m_parameters, key_bits))) {}

std::vector<uint8_t> MLDSA_Composite_PublicKey::raw_public_key_bits() const {
   std::vector<uint8_t> result = m_mldsa_pubkey->raw_public_key_bits();
   std::vector<uint8_t> trad = m_tradtional_pubkey->raw_public_key_bits();
   result.insert(result.end(), trad.begin(), trad.end());
   return result;
}

OID MLDSA_Composite_PublicKey::object_identifier() const {
   return m_parameters->object_identifier();
}

std::vector<uint8_t> MLDSA_Composite_PublicKey::public_key_bits() const {
   throw Botan::Exception("TODO: not implemented");
}

std::unique_ptr<Private_Key> MLDSA_Composite_PublicKey::generate_another(RandomNumberGenerator& /*rng*/) const {
   throw Botan::Exception("TODO: not implemented");
}

// TODO: ALLOW NON-EMPTY CTX VIA PARAMS?
std::unique_ptr<PK_Ops::Verification> MLDSA_Composite_PublicKey::create_verification_op(
   std::string_view params_for_ctx, std::string_view provider) const {
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
   const AlgorithmIdentifier& /*alg_id*/, std::string_view /*provider*/) const {
   throw Botan::Exception("TODO: not implemented");
}

MLDSA_Composite_PrivateKey::MLDSA_Composite_PrivateKey(MLDSA_Composite_Param::id_t id, std::span<const uint8_t> sk) :
      m_parameters(std::make_shared<MLDSA_Composite_Param>(MLDSA_Composite_Param::get_param_by_id(id))),
      m_mldsa_privkey(std::make_shared<ML_DSA_PrivateKey>(m_parameters->get_mldsa_algorithm_id(),
                                                          mldsa_privkey_subspan(*m_parameters, sk))),
      m_tradtional_privkey(load_private_key(m_parameters->get_traditional_algorithm_id(),
                                            traditional_privkey_subspan(*m_parameters, sk))) {
   // TODO: TO AVOID COPYING AND PROBLEMS WITH REASSIGNEMENTS, MAKE THE MEMBERS IN COMPOSITE PUBLIC KEY shared_ptr
   MLDSA_Composite_PublicKey::m_parameters = m_parameters;
   MLDSA_Composite_PublicKey::m_mldsa_pubkey = m_mldsa_privkey;

   MLDSA_Composite_PublicKey::m_tradtional_pubkey = m_tradtional_privkey;
}

secure_vector<uint8_t> MLDSA_Composite_PrivateKey::private_key_bits() const {
   throw Botan::Exception("TODO: not implemented");
}

secure_vector<uint8_t> MLDSA_Composite_PrivateKey::raw_private_key_bits() const {
   throw Botan::Exception("TODO: not implemented");
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

// MLDSA_Composite_PrivateKey::MLDSA_Composite_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk) :
//       m_parameters m_mldsa_privkey() {
//    // TODO: NEED TO INIT THE PUBKEY MEMBERS
// }

}  // namespace Botan
