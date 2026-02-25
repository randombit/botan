/*
 * ML-DSA Composite Signature Schemes 
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_MLDSA_COMP_H_
#define BOTAN_MLDSA_COMP_H_

// id-MLDSA44-RSA2048-PSS-SHA256

#include <botan/dilithium.h>
#include <botan/mldsa_comp_parameters.h>
#include <botan/pk_keys.h>
#include <memory>
#include <span>

namespace Botan {

class BOTAN_PUBLIC_API(3, 0) MLDSA_Composite_PublicKey : public virtual Public_Key {
   public:
      /**
       * Creates a new MLDSA_Composite public key for the chosen MLDSA_Composite signature method.
       * New public and prf seeds are generated using rng. The appropriate WOTS
       * signature method will be automatically set based on the chosen MLDSA_Composite
       * signature method.
       *
       * @param xmss_oid Identifier for the selected MLDSA_Composite signature method.
       * @param rng A random number generator to use for key generation.
       **/
      // TODO: IMPLMEMENT:
      //MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t xmss_oid, RandomNumberGenerator& rng);

      /**
       * Loads a public key.
       *
       * Public key must be encoded as in RFC
       * draft-vangeest-x509-hash-sigs-03.
       *
       * @param key_bits DER encoded public key bits
       */
      BOTAN_FUTURE_EXPLICIT MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t id,
                                                      std::span<const uint8_t> key_bits);

      /**
       * Creates a new MLDSA_Composite public key for a chosen MLDSA_Composite signature method as
       * well as pre-computed root node and public_seed values.
       *
       * @param xmss_oid Identifier for the selected MLDSA_Composite signature method.
       * @param root Root node value.
       * @param public_seed Public seed value.
       **/
      // TODO: NEED CTOR BUILDING KEY FROM COMPONENT KEYS?
      /* MLDSA_Composite_PublicKey(MLDSA_Composite_Param::id_t id, */
      /*                           secure_vector<uint8_t> root, */
      /*                           secure_vector<uint8_t> public_seed); */

      std::string algo_name() const override { return "MLDSA_Composite"; }

      AlgorithmIdentifier algorithm_identifier() const override {
         return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      bool check_key(RandomNumberGenerator& /*rng*/, bool /*strong*/) const override {
         throw Botan::Exception("not implmented");
      }

      OID object_identifier() const override;

      size_t estimated_strength() const override { return m_parameters.estimated_strength(); }

      size_t key_length() const override { return m_parameters.estimated_strength(); }

      /**
       * Generates a byte sequence representing the MLDSA_Composite
       * public key, as defined in [1] (p. 23, "MLDSA_Composite Public Key")
       *
       * @return 4-byte OID, followed by n-byte root node, followed by
       *         public seed.
       **/
      std::vector<uint8_t> raw_public_key_bits() const override;

      /**
       * Returns the encoded public key as defined in RFC
       * draft-vangeest-x509-hash-sigs-03.
       *
       * @return encoded public key bits
       **/
      std::vector<uint8_t> public_key_bits() const override;

      BOTAN_DEPRECATED("Use raw_public_key_bits()") std::vector<uint8_t> raw_public_key() const;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<PK_Ops::Verification> create_verification_op(std::string_view params,
                                                                   std::string_view provider) const override;

      std::unique_ptr<PK_Ops::Verification> create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                        std::string_view provider) const override;

   private:
      MLDSA_Composite_Param m_parameters;
      std::unique_ptr<Dilithium_PublicKey> m_mldsa_pubkey;
      std::unique_ptr<Public_Key> m_tradtional_pubkey;
};

}  // namespace Botan
#endif /* BOTAN_MLDSA_COMP_H_ */
