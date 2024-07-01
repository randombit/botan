/**
* Implementation of the Ounsworth KEM combiner (draft-ounsworth-cfrg-kem-combiners-05)
*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OUNSWORTH_H_
#define BOTAN_OUNSWORTH_H_

#include <botan/hybrid_kem.h>
#include <botan/ounsworth_mode.h>

namespace Botan {

/**
 * @brief Ounsworth KEM Combiner Public Key
 *
 * See Ounsworth_PrivateKey for more information.
 *
 * @warning Experimental: The implementation is based on a very early
 * draft version. Therefore, its behavior and API can change
 * in future library versions.
 */
class BOTAN_UNSTABLE_API Ounsworth_PublicKey : public virtual Hybrid_PublicKey {
   public:
      Ounsworth_PublicKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> pk_bytes);

      Ounsworth_PublicKey(std::span<const uint8_t> pk_bytes, const Ounsworth::Mode& mode);

      std::string algo_name() const override;
      AlgorithmIdentifier algorithm_identifier() const override;
      std::unique_ptr<Private_Key> generate_another(RandomNumberGenerator& rng) const final;

      /**
       * @brief Create a kem decryption operation object
       *
       * @param mac_big_k the value K used for additional domain separation. Must be empty for SHA3 modes.
       * @param provider the provider used for the underlying KEMs
       * @return the encryption operation
       */
      std::unique_ptr<PK_Ops::KEM_Encryption> create_kem_encryption_op(
         std::string_view mac_big_k = "", std::string_view provider = "base") const override;

      const Ounsworth::Mode& mode() const { return m_mode; }

   protected:
      Ounsworth_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks, const Ounsworth::Mode& mode);
      static std::unique_ptr<Ounsworth_PublicKey> from_public_keys(std::vector<std::unique_ptr<Public_Key>> pks,
                                                                   const Ounsworth::Mode& mode);

      Ounsworth_PublicKey(const Ounsworth::Mode& mode) : m_mode(mode) {}

   private:
      Ounsworth::Mode m_mode;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * @brief Ounsworth KEM Combiner Private Key
 *
 * Based on the specification draft (7 Feb 2024):
 * https://github.com/EntrustCorporation/draft-ounsworth-cfrg-kem-combiners/blob/475ff53eb8fb7213f6e5ab26dd23e5dc3203f7fa/draft-ounsworth-cfrg-kem-combiners.txt.
 * This combiner combines two or more key encapsulation mechanisms (KEMs) into
 * a single KEM. It can combine a post-quantum secure KEM (e.g., Frodo or
 * Kyber) with a classical KEM or KEX (e.g., ECDH). For that, the document
 * defines a KDF combining its sub-algorithm's shared secrets and ciphertexts
 * into a new shared secret.
 *
 * Here are some hints for using the KEM Combiner:
 *
 * - Ounsworth public and private keys are configured using an Ounsworth
 *   mode. This mode defines the set sub-algorithms and the KDF to use.
 *   Sub-algorithms are specified by an Ounsworth_Mode::Sub_Algo object using
 *   an Ounsworth_Mode::Sub_Algo_Type. For other or application-defined
 *   algorithms, Sub_Algo contains a constructor with callbacks for creating
 *   and loading private and public keys.
 *
 * - The salt used by PK_KEM_Encryptor::encrypt and
 *   PK_KEM_Decryptor::decrypt acts as the fixedInfo.
 *
 * - Only if using the KMAC KDF mode may a parameter string be passed to the
 *   PK_KEM_Encryptor's or PK_KEM_Decryptor's constructor. This string's
 *   bytes act as the context-specific string K (see section 5.1). If an
 *   empty string or no parameter is passed, the default K value is applied,
 *   as defined in NIST.SP.800-56Cr2 Section 4.1 as default_salt.
 *
 * Here are some details about the application of the specification:
 *
 * - The KDF always contains the right-encoded length of the ciphertexts and
 *   shared secrets, even if the lengths are fixed. I.e.:
 *	    ss = KDF(ct_1 || rlen(ct_1) || ss_1 || r_len(ss_1) || ct_2 || ..., fixedInfo)
 *   Encode are the lengths in bits rounded to the next byte. E.g. a X25519 sk
 *   has a length of 256 bits, even if it only contains 253 significant bits.
 *   Therefore, rlen(sk_x25519) = (0x01, 0x00, 0x02)
 *
 * - The Ounsworth public key concatenates its sub-algorithm's raw public
 *   keys. I.e.:
 *	    pk = pk_1 || pk_2 || ...
 *   Therefore, the raw public key size must be fixed for each sub-algorithm.
 *
 * - The Ounsworth secret key concatenates its sub-algorithm's raw private
 *   keys. I.e.:
 * 	 sk = sk_1 || sk_2 || ...
 *   Therefore, the raw secret key size must be fixed for each sub-algorithm.
 *
 * @warning Experimental: The implementation is based on a very early
 * draft version. Therefore, its behavior and API can change
 * in future library versions.
 */
class BOTAN_UNSTABLE_API Ounsworth_PrivateKey final : public Ounsworth_PublicKey,
                                                      public Hybrid_PrivateKey {
   public:
      /// Create a new Ounsworth KEM combiner key using the given RNG
      Ounsworth_PrivateKey(RandomNumberGenerator& rng, const Ounsworth::Mode& mode);

      // Load a raw Ounsworth KEM combiner private key
      Ounsworth_PrivateKey(std::span<const uint8_t> key_bytes, const Ounsworth::Mode& mode);

      /// Load a raw Ounsworth KEM combiner private key
      Ounsworth_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bytes);

      std::unique_ptr<Public_Key> public_key() const override;

      secure_vector<uint8_t> raw_private_key_bits() const override;

      secure_vector<uint8_t> private_key_bits() const override { return raw_private_key_bits(); }

      bool check_key(RandomNumberGenerator& rng, bool strong) const override;

      /**
       * @brief Create a kem decryption operation object
       *
       * @param rng the rng used for the underlying KEM's decryption (e.g. EC masking)
       * @param mac_big_k the value K used for additional domain separation. Must be empty for SHA3 modes.
       * @param provider the provider used for the underlying KEMs
       * @return the decryption operation
       */
      std::unique_ptr<PK_Ops::KEM_Decryption> create_kem_decryption_op(
         RandomNumberGenerator& rng,
         std::string_view mac_big_k = "",
         std::string_view provider = "base") const override;

   private:
      /// Constructor helper. Creates a private key using the underlying public keys and private keys.
      Ounsworth_PrivateKey(
         std::pair<std::vector<std::unique_ptr<Public_Key>>, std::vector<std::unique_ptr<Private_Key>>> key_pairs,
         const Ounsworth::Mode& mode);
};

}  // namespace Botan

#endif  // BOTAN_OUNSWORTH_H_
