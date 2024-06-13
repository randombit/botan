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

      // Load a raw Ounsworth KEM combiner public key using import information for each sub algorithm
      Ounsworth_PublicKey(std::span<const uint8_t> pk_bytes,
                          std::vector<Ounsworth::PublicKeyImportInfo> import_info,
                          Ounsworth::Kdf kdf);

      // Create an Ounsworth KEM combiner public key from multiple KEM public keys
      Ounsworth_PublicKey(std::vector<std::unique_ptr<Public_Key>> pks, Ounsworth::Kdf kdf);

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

      /// @returns the KDF used by the Ounsworth KEM combiner
      Ounsworth::Kdf kdf() const { return m_kdf; }

      void _set_alg_id_opt(std::optional<AlgorithmIdentifier> alg_id) { m_maybe_alg_id = std::move(alg_id); }

   protected:
      // Used for inheritance
      Ounsworth_PublicKey(Ounsworth::Kdf kdf) : m_kdf(kdf) {}

      std::optional<AlgorithmIdentifier> get_alg_id_opt() const { return m_maybe_alg_id; }

   private:
      /// Constructor helper
      Ounsworth_PublicKey(std::span<const uint8_t> pk_bytes,
                          std::pair<std::vector<Ounsworth::PublicKeyImportInfo>, Ounsworth::Kdf> pk_info_and_kdf) :
            Ounsworth_PublicKey(pk_bytes, std::move(pk_info_and_kdf.first), pk_info_and_kdf.second) {}

      Ounsworth::Kdf m_kdf;

      /// Contains an alg id if the key was loaded from bytes using an alg id (Constructor(alg_id, pk_bytes)).
      /// or created by the private key using a parameter string resembling the alg id.
      std::optional<AlgorithmIdentifier> m_maybe_alg_id;
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
 * - To create Ounsworth public and private keys, one can use a Key Derivation
 *   Function (KDF) with multiple private and public keys. The Ounsworth
 *   specification offers four different KDF options, which can be selected using
 *   the Ounsworth::Kdf::Option enum.
 *
 *   Alternatively, for private key generation, one can use a list of
 *   Ounsworth::PrivateKeyGenerationInfo objects to specify how each sub private
 *   key is generated. To load a private key, one can use the
 *   Ounsworth::PrivateKeyImportInfo object, which specifies how each sub private
 *   key is loaded from raw bytes. Similarly, for public key generation and
 *   loading, one can use a list of Ounsworth::PublicKeyGenerationInfo.
 *
 *   All three info classes can be easily instantiated with predefined
 *   sub-algorithms, which is the easiest way to use the KEM Combiner. However,
 *   if one need custom sub-algorithms, these classes also accept a callback
 *   function that allows defining how keys are generated and loaded.
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
      /**
       * Create a new Ounsworth KEM combiner key using the given RNG and the
       * provided key generation information (for each sub-algorithm)
       */
      Ounsworth_PrivateKey(RandomNumberGenerator& rng,
                           std::vector<Ounsworth::PrivateKeyGenerationInfo> gen_info,
                           Ounsworth::Kdf kdf);

      /**
       * @brief Construct a new Ounsworth key using a formatted string for the parameters
       *
       * The string must be formatted as follows:
       *    OunsworthKEMCombiner/[sub_algo_1]/[sub_alg_2]/.../[kdf]
       *
       * Example: "OunsworthKEMCombiner/Kyber-512-r3/FrodoKEM-640-SHAKE/KMAC-128"
       *
       * [sub_algo_i] is one of:
       *   Kyber-512-r3, Kyber-768-r3, Kyber-1024-r3, FrodoKEM-640-SHAKE,
       *   FrodoKEM-976-SHAKE, FrodoKEM-1344-SHAKE, FrodoKEM-640-AES,
       *   FrodoKEM-976-AES, FrodoKEM-1344-AES, X25519, X448, ECDH-secp192R1,
       *   ECDH-secp224R1, ECDH-secp256r1, ECDH-secp384r1, ECDH-secp521r1,
       *   ECDH-brainpool256r1, ECDH-brainpool384r1, ECDH-brainpool512r1
       *
       * [kdf] is one of: KMAC-128, KMAC-256, SHA3-256, SHA3-512
       *
       * @param rng the rng used for key generation
       * @param param_str the formatted string (see above)
       */
      Ounsworth_PrivateKey(RandomNumberGenerator& rng, std::string_view param_str);

      // Load a raw Ounsworth KEM combiner private key
      Ounsworth_PrivateKey(std::span<const uint8_t> key_bytes,
                           std::vector<Ounsworth::PrivateKeyImportInfo> import_info,
                           Ounsworth::Kdf kdf);

      // Load a raw Ounsworth KEM combiner private key using import information for each sub algorithm
      Ounsworth_PrivateKey(const AlgorithmIdentifier& alg_id, std::span<const uint8_t> key_bytes);

      // Create an Ounsworth KEM combiner private key from multiple KEM private keys
      Ounsworth_PrivateKey(std::vector<std::unique_ptr<Private_Key>> sks, Ounsworth::Kdf kdf);

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
      /// Constructor helpers.
      Ounsworth_PrivateKey(
         std::pair<std::vector<std::unique_ptr<Public_Key>>, std::vector<std::unique_ptr<Private_Key>>> key_pairs,
         Ounsworth::Kdf kdf);

      Ounsworth_PrivateKey(
         std::span<const uint8_t> key_bytes,
         std::pair<std::vector<Ounsworth::PrivateKeyImportInfo>, Ounsworth::Kdf> import_info_and_kdf) :
            Ounsworth_PrivateKey(key_bytes, std::move(import_info_and_kdf.first), import_info_and_kdf.second) {}

      Ounsworth_PrivateKey(
         RandomNumberGenerator& rng,
         std::pair<std::vector<Ounsworth::PrivateKeyGenerationInfo>, Ounsworth::Kdf> gen_info_and_kdf) :
            Ounsworth_PrivateKey(rng, std::move(gen_info_and_kdf.first), gen_info_and_kdf.second) {}
};

}  // namespace Botan

#endif  // BOTAN_OUNSWORTH_H_
