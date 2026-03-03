
#include "botan/assert.h"
#include "botan/internal/pk_ops_impl.h"
#include "botan/ml_dsa.h"
#include "botan/pk_ops.h"
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

std::span<const uint8_t> traditional_pubkey_subspan(const MLDSA_Composite_Param& param,
                                                    std::span<const uint8_t> key_bits) {
   const size_t offset = param.mldsa_pubkey_size;
   if(key_bits.size() - offset <= 1) {
      throw Invalid_Argument("encoded key is too short");
   }
   std::cout << "RSA pub key byte size = " << key_bits.size() - offset << std::endl;
   std::span<const uint8_t> result(key_bits.begin() + offset, key_bits.end());
   std::cout << "RSA pub key hex = " << hex_encode(result) << std::endl;
   return result;
}
}  // namespace

//

class MLDSA_Composite_Verification_Operation final : public PK_Ops::Verification_with_Hash {
   public:
      explicit MLDSA_Composite_Verification_Operation(const MLDSA_Composite_Param& param,
                                                      const ML_DSA_PublicKey& mldsa_pubkey,
                                                      const Public_Key* trad_pubkey) :
            PK_Ops::Verification_with_Hash(param.prehash_func),
            m_parameters(param),
            m_mldsa_ver_op(mldsa_pubkey.create_verification_op(param.mldsa_param_str(), "")),
            m_traditional_ver_op(trad_pubkey->create_verification_op(param.traditional_padding, "")) {}

      //void update(std::span<const uint8_t> input) override { throw Botan::Exception("update() not implemented"); }

      bool verify(std::span<const uint8_t> ph, std::span<const uint8_t> sig) override {
         std::string msg_str = "CompositeAlgorithmSignatures2025";
         msg_str += m_parameters.label;
         std::vector<uint8_t> msg(msg_str.begin(), msg_str.end());
         msg.push_back(0);  // ctx = empty
         msg.insert(msg.end(), ph.begin(), ph.end());
         size_t mldsa_sig_size = m_parameters.mldsa_signature_size();
         if(sig.size() <= mldsa_sig_size) {
            return false;
         }
         m_mldsa_ver_op->update(msg);
         m_traditional_ver_op->update(msg);
         std::cout << "traditional signature size = " << sig.size() - mldsa_sig_size << std::endl;
         std::span<const uint8_t> mldsa_sig(sig.begin(), sig.begin() + mldsa_sig_size);
         std::span<const uint8_t> trad_sig(sig.begin() + mldsa_sig_size, sig.end());
         bool overall = true;
         if(!m_mldsa_ver_op->is_valid_signature(mldsa_sig)) {
            std::cout << "MLDSA signature valditation failed\n";
            overall = false;
         } else {
            std::cout << "MLDSA signature valditation SUCCEEDED\n";
         }
         if(!m_traditional_ver_op->is_valid_signature(trad_sig)) {
            std::cout << "traditional signature valditation failed\n";
            overall = false;
         } else {
            std::cout << "traditional signature valditation SUCCEEDED\n";
         }
         return overall;

         //  M' = Prefix || Label || len(ctx) || ctx || PH( M )
      }

      /**
       */
      // bool is_valid_signature(std::span<const uint8_t> sig) override {
      //    throw Botan::Exception("is_valid_signature() not implemented");
      // }

      //std::string hash_function() const override { throw Botan::Exception("hash_function() not implemented"); }

   private:
      //ML_DSA_PublicKey m_mldsa_public_key;
      MLDSA_Composite_Param m_parameters;
      std::unique_ptr<PK_Ops::Verification> m_mldsa_ver_op;
      std::unique_ptr<PK_Ops::Verification> m_traditional_ver_op;
};

MLDSA_Composite_PublicKey::MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t id,
                                                     std::span<const uint8_t> key_bits) :
      m_parameters(MLDSA_Composite_Param::get_param_by_id(id)),
      m_mldsa_pubkey(m_parameters.get_mldsa_algorithm_id(), mldsa_pubkey_subspan(m_parameters, key_bits)),
      m_tradtional_pubkey(load_public_key(m_parameters.get_traditional_algorithm_id(),
                                          traditional_pubkey_subspan(m_parameters, key_bits))) {
   std::cout << "MLDSA_Composite_PublicKey() decoded both keys\n";
}

std::vector<uint8_t> MLDSA_Composite_PublicKey::raw_public_key_bits() const {
   // TODO: CHECK POINTER NON-NULL
   std::vector<uint8_t> result = m_mldsa_pubkey.raw_public_key_bits();
   std::cerr << "MLDSA_Composite_PublicKey::raw_public_key_bits(): ML-DSA public_key_bits.size() = " << result.size()
             << std::endl;
   std::vector<uint8_t> trad = m_tradtional_pubkey->raw_public_key_bits();
   result.insert(result.end(), trad.begin(), trad.end());
   return result;
}

OID MLDSA_Composite_PublicKey::object_identifier() const {
   return m_parameters.object_identifier();
}

std::vector<uint8_t> MLDSA_Composite_PublicKey::public_key_bits() const {
   throw Botan::Exception("not implemented");
}

std::unique_ptr<Private_Key> MLDSA_Composite_PublicKey::generate_another(RandomNumberGenerator& /*rng*/) const {
   throw Botan::Exception("not implemented");
}

// TODO: ALLOW NON-EMPTY CTX VIA PARAMS?
std::unique_ptr<PK_Ops::Verification> MLDSA_Composite_PublicKey::create_verification_op(
   std::string_view /*params_for_ctx*/, std::string_view provider) const {
   if(provider.empty() || provider == "base") {
      return std::make_unique<MLDSA_Composite_Verification_Operation>(
         this->m_parameters, this->m_mldsa_pubkey, this->m_tradtional_pubkey.get());
   }
   throw Provider_Not_Found(algo_name(), provider);
}

std::unique_ptr<PK_Ops::Verification> MLDSA_Composite_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& /*alg_id*/, std::string_view /*provider*/) const {
   throw Botan::Exception("not implemented");
}

}  // namespace Botan
