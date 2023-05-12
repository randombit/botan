/*
 * SPHINCS+
 * (C) 2023 Jack Lloyd
 *     2023 Fabian Albert, René Meusel, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_SPHINCS_PLUS_H_
#define BOTAN_SPHINCS_PLUS_H_

#include <botan/pk_keys.h>

#include <botan/sp_parameters.h>

#include <memory>
#include <vector>

namespace Botan
{

class SphincsPlus_PublicKeyInternal;
class SphincsPlus_PrivateKeyInternal;

class BOTAN_PUBLIC_API(3,1) SphincsPlus_PublicKey : public virtual Public_Key
   {
   public:
      SphincsPlus_PublicKey(std::span<const uint8_t> pub_key, Sphincs_Parameter_Set type, Sphincs_Hash_Type hash);
      SphincsPlus_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      ~SphincsPlus_PublicKey();

      std::string algo_name() const override
         {
         return "SPHINCS+";
         }

      size_t estimated_strength() const override;

      AlgorithmIdentifier algorithm_identifier() const override;
      OID object_identifier() const override;
      bool check_key(RandomNumberGenerator& rng,
                     bool strong) const override;

      std::vector<uint8_t> public_key_bits() const override;


      std::unique_ptr<PK_Ops::Verification>
         create_verification_op(std::string_view params,
                              std::string_view provider) const override;


      std::unique_ptr<PK_Ops::Verification>
         create_x509_verification_op(const AlgorithmIdentifier& signature_algorithm,
                                    std::string_view provider) const override;


      bool supports_operation(PublicKeyOperation op) const override;

   protected:
      std::shared_ptr<SphincsPlus_PublicKeyInternal> m_public;
   };

class BOTAN_PUBLIC_API(3,1) SphincsPlus_PrivateKey : public virtual SphincsPlus_PublicKey,
                                                     public virtual Private_Key
   {
   public:
      SphincsPlus_PrivateKey(std::span<const uint8_t> private_key, Sphincs_Parameter_Set type, Sphincs_Hash_Type hash);
      SphincsPlus_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);
      SphincsPlus_PrivateKey(RandomNumberGenerator& rng, Sphincs_Parameter_Set type, Sphincs_Hash_Type hash);

      ~SphincsPlus_PrivateKey();
      secure_vector<uint8_t> private_key_bits() const override;
      std::unique_ptr<Public_Key> public_key() const override;


      std::unique_ptr<PK_Ops::Signature>
         create_signature_op(RandomNumberGenerator& rng,
                           std::string_view params,
                           std::string_view provider) const override;

   private:
      std::shared_ptr<SphincsPlus_PrivateKeyInternal> m_private;
   };




// Temporary sign function without class
std::vector<uint8_t> sphincsplus_sign(const std::vector<uint8_t>& message,
                                      const secure_vector<uint8_t>& sk_seed_vec,
                                      const secure_vector<uint8_t>& sk_prf_vec,
                                      const std::vector<uint8_t>& pub_seed_vec,
                                      const std::vector<uint8_t>& opt_rand_vec,
                                      const std::vector<uint8_t>& pk_root,
                                      const Sphincs_Parameters& params);

bool sphincsplus_verify(const std::vector<uint8_t>& message,
                        const std::vector<uint8_t>& sig,
                        const std::vector<uint8_t>& pub_seed_vec,
                        const std::vector<uint8_t>& pk_root_vec,
                        const Sphincs_Parameters& params);

// TODO: Verification

}

#endif
