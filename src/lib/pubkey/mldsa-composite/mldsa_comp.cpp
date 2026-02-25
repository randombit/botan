
#include "botan/exceptn.h"
#include <botan/mldsa_comp.h>
#include <vector>

#include <iostream>

namespace Botan {

MLDSA_Composite_PublicKey::MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t id,
                                                     std::span<const uint8_t> key_bits) :
      m_parameters(MLDSA_Composite_Param::get_param_by_id(id)) {
   OID oid(m_parameters.mldsa_oid_str);
   AlgorithmIdentifier aid(oid, AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
   if(key_bits.size() <= m_parameters.mldsa_pubkey_size) {
      throw Invalid_Argument("encoded key is too short");
   }
   const std::span<const uint8_t> mldsa_pub_enc(key_bits.begin(), m_parameters.mldsa_pubkey_size);
   m_mldsa_pubkey = std::make_unique<Dilithium_PublicKey>(aid, mldsa_pub_enc);
   std::cout << "MLDSA_Composite_PublicKey() decoded ML-DSA key\n";
   // TODO: DECODE TRADITIONAL KEY
}

std::vector<uint8_t> MLDSA_Composite_PublicKey::raw_public_key_bits() const {
   // TODO: CHECK POINTER NON-NULL
   std::vector<uint8_t> result = m_mldsa_pubkey->raw_public_key_bits();
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

std::unique_ptr<PK_Ops::Verification> MLDSA_Composite_PublicKey::create_verification_op(
   std::string_view /*params*/, std::string_view /*provider*/) const {
   throw Botan::Exception("not implemented");
}

std::unique_ptr<PK_Ops::Verification> MLDSA_Composite_PublicKey::create_x509_verification_op(
   const AlgorithmIdentifier& /*alg_id*/, std::string_view /*provider*/) const {
   throw Botan::Exception("not implemented");
}

}  // namespace Botan
