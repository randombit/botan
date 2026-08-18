/*
 * ML-KEM Composite KEM
 * (C) 2026 Falko Strenzke, MTG AG
 *     2026 René Meusel
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_MLKEM_COMP_H_
#define BOTAN_MLKEM_COMP_H_

#include <botan/hybrid_kem.h>
#include <botan/mlkem_comp_parameters.h>
#include <botan/secmem.h>
#include <memory>
#include <span>

namespace Botan {

class Kyber_PublicKey;
class Kyber_PrivateKey;
using ML_KEM_PublicKey = Kyber_PublicKey;
using ML_KEM_PrivateKey = Kyber_PrivateKey;

class BOTAN_PUBLIC_API(3, 13) MLKEM_Composite_PublicKey : public virtual Hybrid_KEM_PublicKey {
   public:
      MLKEM_Composite_PublicKey(const MLKEM_Composite_Param& parameters, PairOfPublicKeys public_keys);

      /**
       * Loads a public key.
       *
       * @param key_bits DER encoded public key bits
       */
      BOTAN_FUTURE_EXPLICIT MLKEM_Composite_PublicKey(MLKEM_Composite_Param::id_t id,
                                                      std::span<const uint8_t> key_bits);

      BOTAN_FUTURE_EXPLICIT MLKEM_Composite_PublicKey(const AlgorithmIdentifier& algo_id,
                                                      std::span<const uint8_t> key_bits);

      std::string algo_name() const override { return MLKEM_Composite_Param::generic_algo_name; }

      AlgorithmIdentifier algorithm_identifier() const override {
         return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      OID object_identifier() const override;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(std::string_view params,
                                                                       std::string_view provider) const override;

      const ML_KEM_PublicKey& mlkem_public_key() const;
      const Public_Key& traditional_public_key() const;

   private:
      MLKEM_Composite_Param m_parameters;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 13) MLKEM_Composite_PrivateKey final : public virtual MLKEM_Composite_PublicKey,
                                                                 public virtual Hybrid_KEM_PrivateKey {
   public:
      std::unique_ptr<Public_Key> public_key() const override;

      MLKEM_Composite_PrivateKey(const MLKEM_Composite_Param& parameters, PairOfPrivateKeys private_keys);

      /**
       * Generates a new key pair
       */
      MLKEM_Composite_PrivateKey(RandomNumberGenerator& rng, MLKEM_Composite_Param param);

      /**
       * Read an encoded private key.
       */
      MLKEM_Composite_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> sk);

      /**
       * Read an encoded private key.
       */
      MLKEM_Composite_PrivateKey(MLKEM_Composite_Param::id_t id, std::span<const uint8_t> sk);

      const ML_KEM_PrivateKey& mlkem_private_key() const;
      const Private_Key& traditional_private_key() const;

   public:
      secure_vector<uint8_t> private_key_bits() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override { return private_key_bits(); }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override {
         return Hybrid_KEM_PrivateKey::check_key(rng, strong);
      }

      /**
       * Create a signature operation that produces a MLKEM_Composite signature.
       */
      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(RandomNumberGenerator& rng,
                                                                       std::string_view params,
                                                                       std::string_view provider) const override;

   private:
      MLKEM_Composite_Param m_parameters;
};
}  // namespace Botan

#endif /* BOTAN_MLKEM_COMP_H_ */
