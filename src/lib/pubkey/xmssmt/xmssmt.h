/*
 * XMSS^MT Keys
 * (C) 2026 Johannes Roth - MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSSMT_H_
#define BOTAN_XMSSMT_H_

#include <botan/exceptn.h>
#include <botan/pk_keys.h>
#include <botan/xmssmt_parameters.h>
#include <memory>
#include <span>

namespace Botan {

class RandomNumberGenerator;
class XMSS_Address;
class XMSS_Hash;
class XMSS_WOTS_PrivateKey;
class XMSSMT_PublicKey_Internal;
class XMSSMT_PrivateKey_Internal;
class XMSSMT_Verification_Operation;

/**
 * An XMSS^MT: Extended Hash-Based Signature public key.
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 **/
class BOTAN_PUBLIC_API(3, 13) XMSSMT_PublicKey : public virtual Public_Key {
   public:
      /**
       * Loads a public key from an X.509 SubjectPublicKeyInfo.
       *
       * Public key must be encoded as in RFC 9802.
       *
       * @param alg_id the X.509 AlgorithmIdentifier
       * @param key_bits public key bits
       */
      XMSSMT_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      /**
       * Creates a new XMSS^MT public key for a chosen XMSS^MT signature method as
       * well as pre-computed root node and public_seed values.
       *
       * @param xmssmt_oid Identifier for the selected XMSS^MT signature method.
       * @param root Root node value.
       * @param public_seed Public seed value.
       **/
      XMSSMT_PublicKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_oid,
                       secure_vector<uint8_t> root,
                       secure_vector<uint8_t> public_seed);

      std::string algo_name() const override { return "XMSSMT"; }

      AlgorithmIdentifier algorithm_identifier() const override {
         return AlgorithmIdentifier(object_identifier(), AlgorithmIdentifier::USE_EMPTY_PARAM);
      }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      size_t estimated_strength() const override;

      size_t key_length() const override;

      /**
       * Generates a byte sequence representing the XMSS^MT
       * public key, as defined in [1] (p. 23, "XMSS Public Key")
       *
       * @return 4-byte OID, followed by n-byte root node, followed by
       *         public seed.
       **/
      std::vector<uint8_t> raw_public_key_bits() const override;

      /**
       * Returns the encoded public key as defined in RFC 9802.
       *
       * @return encoded public key bits
       **/
      std::vector<uint8_t> public_key_bits() const override;

      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      bool supports_operation(PublicKeyOperation op) const override { return (op == PublicKeyOperation::Signature); }

      std::unique_ptr<PK_Ops::Verification> _create_verification_op(const PK_Signature_Options& options) const override;

      std::unique_ptr<PK_Ops::Verification> create_x509_verification_op(const AlgorithmIdentifier& alg_id,
                                                                        std::string_view provider) const override;

   protected:
      friend class XMSSMT_Verification_Operation;

      const secure_vector<uint8_t>& public_seed() const;

      const secure_vector<uint8_t>& root() const;

      const XMSSMT_Parameters& xmssmt_parameters() const;

   private:
      std::shared_ptr<const XMSSMT_PublicKey_Internal> m_public_key;
};

/**
 * An XMSS^MT: Extended Hash-Based Signature private key.
 * The XMSS^MT private key does not support the X509 and PKCS7 standard. Instead
 * the raw format described in [1] is used.
 *
 * [1] XMSS: Extended Hash-Based Signatures,
 *     Request for Comments: 8391
 *     Release: May 2018.
 *     https://datatracker.ietf.org/doc/rfc8391/
 **/

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

class BOTAN_PUBLIC_API(3, 13) XMSSMT_PrivateKey final : public virtual XMSSMT_PublicKey,
                                                        public virtual Private_Key {
   public:
      /**
      * Creates a new XMSS^MT private key for the chosen XMSS^MT signature method.
      * New seeds for public/private key and pseudo random function input are
      * generated using the provided RNG. The appropriate WOTS signature method
      * will be automatically set based on the chosen XMSS^MT signature method.
      *
      * @param xmssmt_algo_id Identifier for the selected XMSS^MT signature method.
      * @param rng A random number generator to use for key generation.
      **/
      XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id, RandomNumberGenerator& rng);

      /**
       * Loads a private key from a PKCS #8 PrivateKeyInfo.
       *
       * @param alg_id the PKCS #8 AlgorithmIdentifier
       * @param key_bits An XMSS^MT private key serialized using raw_private_key().
       **/
      XMSSMT_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bits);

      /**
       * Creates a new XMSS^MT private key for the chosen XMSS^MT signature method
       * using precomputed seeds for public/private keys and pseudo random
       * function input. The appropriate WOTS signature method will be
       * automatically set, based on the chosen XMSS^MT signature method.
       *
       * @param xmssmt_algo_id Identifier for the selected XMSS^MT signature method.
       * @param idx_leaf Index of the next unused leaf.
       * @param wots_priv_seed A seed to generate a Winternitz-One-Time-
       *                      Signature private key from.
       * @param prf a secret n-byte key sourced from a secure source
       *        of uniformly random data.
       * @param root Root node of the binary hash tree.
       * @param public_seed The public seed.
       **/
      XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                        uint64_t idx_leaf,
                        secure_vector<uint8_t> wots_priv_seed,
                        secure_vector<uint8_t> prf,
                        secure_vector<uint8_t> root,
                        secure_vector<uint8_t> public_seed);

      bool stateful_operation() const override { return true; }

      std::unique_ptr<Public_Key> public_key() const override;

      std::optional<uint64_t> remaining_operations() const override;

      std::unique_ptr<PK_Ops::Signature> _create_signature_op(RandomNumberGenerator& rng,
                                                              const PK_Signature_Options& options) const override;

      secure_vector<uint8_t> private_key_bits() const override;

      /**
       * Generates a non standardized byte sequence representing the XMSS^MT
       * private key.
       *
       * @return byte sequence consisting of the following elements in order:
       *         4-byte OID, n-byte root node, n-byte public seed,
       *         ceil(h/8) unused leaf index, n-byte prf seed, n-byte private seed.
       **/
      secure_vector<uint8_t> raw_private_key() const;

   private:
      friend class XMSSMT_Signature_Operation;

      // The seeds and the precomputed Merkle root produced during key
      // generation, used to construct the (immutable) public key before the
      // derived private key body runs.
      struct Keygen_Material;

      XMSSMT_PrivateKey(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id, Keygen_Material material);

      static Keygen_Material generate_keygen_material(XMSSMT_Parameters::xmssmt_algorithm_t xmssmt_algo_id,
                                                      RandomNumberGenerator& rng);

      struct Decoded_Private_Key;

      explicit XMSSMT_PrivateKey(Decoded_Private_Key decoded);

      static Decoded_Private_Key decode_private_key(const AlgorithmIdentifier& alg_id,
                                                    std::span<const uint8_t> key_bits);

      uint64_t reserve_unused_leaf_index();

      const secure_vector<uint8_t>& prf_value() const;

      XMSS_WOTS_PrivateKey wots_private_key_for(XMSS_Address& adrs, XMSS_Hash& hash) const;

      /**
       * Algorithm 9: "treeHash"
       * Computes the internal n-byte nodes of a single XMSS tree within the
       * hypertree. The caller presets the layer and tree address of @p adrs.
       *
       * @param start_idx The start index.
       * @param target_node_height Height of the target node.
       * @param adrs Address of the tree containing the target node.
       * @param hash The hash function to use
       *
       * @return The root node of a tree of height target_node height with the
       *         leftmost leaf being the hash of the WOTS+ pk with index
       *         start_idx.
       **/
      secure_vector<uint8_t> tree_hash(uint32_t start_idx,
                                       size_t target_node_height,
                                       XMSS_Address adrs,
                                       XMSS_Hash& hash) const;

      std::shared_ptr<const XMSSMT_PrivateKey_Internal> m_private;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan

#endif
