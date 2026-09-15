/*
* TLS Cryptographic Operations
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_CRYPTO_OPERATIONS_H_
#define BOTAN_TLS_CRYPTO_OPERATIONS_H_

#include <botan/ec_point_format.h>
#include <botan/pubkey.h>
#include <botan/tls_algos.h>
#include <memory>
#include <variant>

namespace Botan {
class AEAD_Mode;
class BlockCipher;
class DL_Group;
class HashFunction;
class KDF;
class MessageAuthenticationCode;
class PasswordHashFamily;
enum class Cipher_Dir : uint8_t;

namespace TLS {
class Callbacks;
class Policy;
class Ciphersuite;
class Protocol_Version;

/**
 * Cryptographic operations used by TLS.
 *
 * Applications may derive from this class and override individual operations.
 * The default implementations use Botan's cryptographic algorithms. Factories
 * return a new object or throw; they never return nullptr.
 *
 * An instance can be shared between channels. In that case, application-defined
 * implementations must support concurrent calls. Returned objects belong to
 * the caller and are not shared between channels.
 *
 * @warning This class is intended for derivation by applications but is *NOT*
 * covered by SemVer.
 */
class BOTAN_PUBLIC_API(3, 14) CryptoOperations {
   public:
      virtual ~CryptoOperations() = default;

      CryptoOperations() = default;
      CryptoOperations(const CryptoOperations& other) = default;
      CryptoOperations(CryptoOperations&& other) = default;
      CryptoOperations& operator=(const CryptoOperations& other) = default;
      CryptoOperations& operator=(CryptoOperations&& other) = default;

      virtual std::unique_ptr<HashFunction> create_hash(std::string_view algorithm) const;
      virtual std::unique_ptr<MessageAuthenticationCode> create_mac(std::string_view algorithm) const;
      virtual std::unique_ptr<KDF> create_kdf(std::string_view algorithm) const;
      virtual std::unique_ptr<BlockCipher> create_block_cipher(std::string_view algorithm) const;
      virtual std::unique_ptr<AEAD_Mode> create_aead(std::string_view algorithm, Cipher_Dir direction) const;
      virtual std::unique_ptr<PasswordHashFamily> create_password_hash_family(std::string_view algorithm) const;

      /// Create TLS 1.2 record protection, including CBC/HMAC and NULL/HMAC.
      virtual std::unique_ptr<AEAD_Mode> create_tls12_record_cipher(const Ciphersuite& suite,
                                                                    Protocol_Version version,
                                                                    Cipher_Dir direction,
                                                                    bool uses_encrypt_then_mac) const;

      /// Load a DER SubjectPublicKeyInfo, for certificates and raw public keys.
      virtual std::unique_ptr<Public_Key> load_public_key(std::span<const uint8_t> subject_public_key_info) const;

      /// TLS 1.2 RSA key transport. The decryptor must support decrypt_or_random().
      virtual std::unique_ptr<PK_Encryptor> create_rsa_encryptor(const Public_Key& key, RandomNumberGenerator& rng);
      virtual std::unique_ptr<PK_Decryptor> create_rsa_decryptor(const Private_Key& key, RandomNumberGenerator& rng);

      /**
       * sign a message
       *
       * Default implementation uses PK_Signer::sign_message().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param key the private key of the signer
       * @param rng a random number generator
       * @param padding the encoding method to be applied to the message
       * @param format the signature format
       * @param msg the input data for the signature
       *
       * @return the signature
       */
      virtual std::vector<uint8_t> sign_message(const Private_Key& key,
                                                RandomNumberGenerator& rng,
                                                std::string_view padding,
                                                Signature_Format format,
                                                std::span<const uint8_t> msg);

      /**
       * verify a message signature
       *
       * Default implementation uses PK_Verifier::verify_message().
       * Override to provide a different approach, e.g. using an external device.
       *
       * @param key the public key of the signer
       * @param padding the encoding method to be applied to the message
       * @param format the signature format
       * @param msg the input data for the signature
       * @param sig the signature to be checked
       *
       * @return true if the signature is valid, false otherwise
       */
      virtual bool verify_message(const Public_Key& key,
                                  std::string_view padding,
                                  Signature_Format format,
                                  std::span<const uint8_t> msg,
                                  std::span<const uint8_t> sig);

      /**
       * deserialize a public key received from the peer
       *
       * Default implementation simply parses the public key using Botan's
       * public keys. Override to provide a different approach, e.g. using an
       * external device.
       *
       * If deserialization fails, the default implementation throws a
       * Botan::Decoding_Error exception that will be translated into a
       * TLS_Exception with an Alert::IllegalParameter.
       *
       * @param group the group identifier or (in case of TLS 1.2) an explicit
       *              discrete-log group of the public key
       * @param key_bits the serialized public key
       *
       * @return the deserialized and ready-to-use public key
       */
      virtual std::unique_ptr<Public_Key> deserialize_peer_public_key(
         const std::variant<TLS::Group_Params, DL_Group>& group, std::span<const uint8_t> key_bits);

      /**
       * Generate an ephemeral KEM key for a TLS 1.3 handshake
       *
       * Applications may use this to add custom KEM algorithms or entirely
       * different key exchange schemes to the TLS 1.3 handshake. For instance,
       * this could provide an entry point to implement a hybrid key exchange
       * with both a traditional algorithm like ECDH and a quantum-secure KEM.
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key encapsulation
       * mechanism.
       *
       * Note that the KEM interface is usable for TLS 1.3 handshakes, only.
       *
       * The default implementation simply delegates this to the
       * generate_ephemeral_key() call when appropriate.
       *
       * @param group the group identifier to generate an ephemeral keypair for
       * @param rng   a random number generator
       *
       * @returns a keypair whose public key will be provided to the peer and
       *          the private key will be provided to kem_decapsulate later
       *          in the handshake.
       */
      virtual std::unique_ptr<Private_Key> kem_generate_key(TLS::Group_Params group, RandomNumberGenerator& rng);

      /**
       * Performs a key encapsulation operation (used for TLS 1.3 servers)
       *
       * Applications may use this to add custom KEM algorithms or entirely
       * different key exchange schemes to the TLS 1.3 handshake. For instance,
       * this could provide an entry point to implement a hybrid key exchange
       * with both a traditional algorithm like ECDH and a quantum-secure KEM.
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key encapsulation
       * mechanism.
       *
       * Note that the KEM interface is usable for TLS 1.3 handshakes, only.
       *
       * The default implementation implements this key encapsulation as a
       * combination of generate_ephemeral_key() followed by
       * ephemeral_key_agreement() with the provided @p encoded_public_key.
       * The just-generated ephemeral private key is destroyed immediately.
       *
       * @param group the group identifier of the KEM/KEX algorithm
       * @param encoded_public_key the public key used for encapsulation/KEX
       * @param rng a random number generator
       * @param policy a TLS policy object
       *
       * @returns the shared secret both in plaintext and encapsulated with
       *          @p encoded_public_key.
       *
       */
      virtual KEM_Encapsulation kem_encapsulate(TLS::Group_Params group,
                                                std::span<const uint8_t> encoded_public_key,
                                                RandomNumberGenerator& rng,
                                                const Policy& policy);

      /**
       * Performs a key decapsulation operation (used for TLS 1.3 clients).
       *
       * Applications may use this to add custom KEM algorithms or entirely
       * different key exchange schemes to the TLS 1.3 handshake. For instance,
       * this could provide an entry point to implement a hybrid key exchange
       * with both a traditional algorithm like ECDH and a quantum-secure KEM.
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key encapsulation
       * mechanism.
       *
       * Note that the KEM interface is usable for TLS 1.3 handshakes, only.
       *
       * The default implementation simply delegates this to the
       * ephemeral_key_agreement() operation to obtain the shared secret.
       *
       * @param group the group identifier of the KEM/KEX algorithm
       * @param private_key the private key used for decapsulation/KEX
       * @param encapsulated_bytes the content to decapsulate (or the public key share)
       * @param rng a random number generator
       * @param policy a TLS policy object
       *
       * @returns the plaintext shared secret from @p encapsulated_bytes after
       *          decapsulation with @p private_key.
       *
       */
      virtual secure_vector<uint8_t> kem_decapsulate(TLS::Group_Params group,
                                                     const Private_Key& private_key,
                                                     std::span<const uint8_t> encapsulated_bytes,
                                                     RandomNumberGenerator& rng,
                                                     const Policy& policy);

      /**
       * Generate an ephemeral key pair for the TLS handshake.
       *
       * Applications may use this to add custom groups, curves or entirely
       * different ephemeral key agreement mechanisms to the TLS handshake.
       * Note that this operation must be used in conjunction with
       * CryptoOperations::ephemeral_key_agreement.
       *
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key exchange
       * mechanism.
       *
       * @throws TLS_Exception(Alert::DecodeError) if the @p group is not known.
       *
       * @param group the group identifier to generate an ephemeral keypair for
       *              TLS 1.2 allows for specifying custom discrete logarithm
       *              parameters as part of the protocol. Hence the variant<>.
       * @param rng a random number generator
       *
       * @return a private key of an algorithm usable for key agreement
       */
      virtual std::unique_ptr<PK_Key_Agreement_Key> generate_ephemeral_key(
         const std::variant<TLS::Group_Params, DL_Group>& group, RandomNumberGenerator& rng);

      /**
       * Generate an ECDH key pair for the TLS 1.2 handshake.
       *
       * Note that this operation is called exclusively by TLS 1.2 to handle the
       * ECDH public key serialization format explicitly. TLS 1.3 fixes this
       * format to 'uncompressed' and does not allow negotiating anything else.
       * X25519 and X448 feature a defined and fixed public key encoding and are
       * therefore not explicitly handled by this operation either.
       *
       * Users may override this if they want to provide a custom keypair type
       * to offload TLS 1.2's ECDH handling to custom hardware, for instance. It
       * is worth noting that support for compressed points in Botan is
       * deprecated and this operation will disappear when it is removed in a
       * future release.
       *
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key exchange
       * mechanism.
       *
       * @throws TLS_Exception(Alert::DecodeError) if the @p group is not known.
       *
       * @param group ECDH group identifier to generate an ephemeral keypair for
       * @param rng a random number generator
       * @param tls12_ecc_pubkey_encoding_format the key's serialization format
       *
       * @return an ECDH private key of an algorithm usable for key agreement
       */
      virtual std::unique_ptr<PK_Key_Agreement_Key> tls12_generate_ephemeral_ecdh_key(
         TLS::Group_Params group, RandomNumberGenerator& rng, EC_Point_Format tls12_ecc_pubkey_encoding_format);

      /**
       * Agree on a shared secret with the peer's ephemeral public key for
       * the TLS handshake.
       *
       * Applications may use this to add custom groups, curves or entirely
       * different ephemeral key agreement mechanisms to the TLS handshake.
       * Note that this operation must be used in conjunction with
       * CryptoOperations::generate_ephemeral_key.
       *
       * Typical use cases of the library don't need to do that and serious
       * security risks are associated with customizing TLS's key exchange
       * mechanism.
       *
       * @param group         the TLS group identifier to be used
       *                      TLS 1.2 allows for specifying custom discrete
       *                      logarithm parameters as part of the protocol.
       *                      Hence the variant<>.
       * @param private_key   the private key (generated ahead in generate_ephemeral_key)
       * @param public_value  the public key exchange information received by the peer
       * @param rng           a random number generator
       * @param policy        a TLS policy object
       *
       * @return the shared secret derived from public_value and private_key
       *
       */
      virtual secure_vector<uint8_t> ephemeral_key_agreement(const std::variant<TLS::Group_Params, DL_Group>& group,
                                                             const PK_Key_Agreement_Key& private_key,
                                                             std::span<const uint8_t> public_value,
                                                             RandomNumberGenerator& rng,
                                                             const Policy& policy);

      /**
       * Returns the key derivation function to be used for TLS 1.2
       *
       * The default implementation can be overridden to provide a user-defined
       * key derivation function, for example to delegate key derivation to a
       * hardware-protected environment when a pre-shared key must remain
       * inaccessible to the non-secure world.
       *
       * @param prf_algo  name of the hash function (e.g. "SHA-256")
       *
       * @return  TLS 1.2 KDF implementation
       */
      virtual std::unique_ptr<KDF> tls12_protocol_specific_kdf(std::string_view prf_algo) const;
};

/**
 * Compatibility adapter for applications overriding cryptographic Callbacks.
 *
 * Existing channel constructors use this adapter automatically. New
 * applications should derive directly from CryptoOperations. The callbacks
 * must outlive this adapter and any operations performed through it.
 */
class BOTAN_PUBLIC_API(3, 14) DefaultCryptoOperations : public CryptoOperations {
   public:
      explicit DefaultCryptoOperations(Callbacks& callbacks) : m_callbacks(callbacks) {}

      std::vector<uint8_t> sign_message(const Private_Key& key,
                                        RandomNumberGenerator& rng,
                                        std::string_view padding,
                                        Signature_Format format,
                                        std::span<const uint8_t> msg) override;

      bool verify_message(const Public_Key& key,
                          std::string_view padding,
                          Signature_Format format,
                          std::span<const uint8_t> msg,
                          std::span<const uint8_t> sig) override;

      std::unique_ptr<Public_Key> deserialize_peer_public_key(const std::variant<TLS::Group_Params, DL_Group>& group,
                                                              std::span<const uint8_t> key_bits) override;

      std::unique_ptr<Private_Key> kem_generate_key(TLS::Group_Params group, RandomNumberGenerator& rng) override;

      KEM_Encapsulation kem_encapsulate(TLS::Group_Params group,
                                        std::span<const uint8_t> encoded_public_key,
                                        RandomNumberGenerator& rng,
                                        const Policy& policy) override;

      secure_vector<uint8_t> kem_decapsulate(TLS::Group_Params group,
                                             const Private_Key& private_key,
                                             std::span<const uint8_t> encapsulated_bytes,
                                             RandomNumberGenerator& rng,
                                             const Policy& policy) override;

      std::unique_ptr<PK_Key_Agreement_Key> generate_ephemeral_key(
         const std::variant<TLS::Group_Params, DL_Group>& group, RandomNumberGenerator& rng) override;

      std::unique_ptr<PK_Key_Agreement_Key> tls12_generate_ephemeral_ecdh_key(
         TLS::Group_Params group,
         RandomNumberGenerator& rng,
         EC_Point_Format tls12_ecc_pubkey_encoding_format) override;

      secure_vector<uint8_t> ephemeral_key_agreement(const std::variant<TLS::Group_Params, DL_Group>& group,
                                                     const PK_Key_Agreement_Key& private_key,
                                                     std::span<const uint8_t> public_value,
                                                     RandomNumberGenerator& rng,
                                                     const Policy& policy) override;

      std::unique_ptr<KDF> tls12_protocol_specific_kdf(std::string_view prf_algo) const override;

   private:
      Callbacks& m_callbacks;
};

}  // namespace TLS
}  // namespace Botan
#endif
