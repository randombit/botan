/*
* TPM 2.0 Key Wrappers' Base Class
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber - Rohde & Schwarz Cybersecurity GmbH, financed by LANCOM Systems GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#ifndef BOTAN_TPM2_ASYM_KEYS_H_
#define BOTAN_TPM2_ASYM_KEYS_H_

#include <botan/pk_keys.h>
#include <botan/tpm2_context.h>
#include <botan/tpm2_object.h>
#include <botan/tpm2_session.h>
#if defined(BOTAN_HAS_RSA)
   #include <botan/rsa.h>
#endif
#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_apoint.h>
   #include <botan/ec_group.h>
#endif

struct TPM2B_SENSITIVE_CREATE;
struct TPMT_PUBLIC;
struct TPM2B_PUBLIC;

namespace Botan::TPM2 {

#if defined(BOTAN_HAS_RSA)
/**
 * This helper function transforms a @p public_blob in a TPM2B_PUBLIC* format
 * into an ordinary Botan::RSA_PublicKey. Note that the resulting key is not
 * bound to a TPM and can be used as any other RSA key.
 *
 * @param public_blob The public blob to load as an ordinary RSA key
 */
BOTAN_PUBLIC_API(3, 6) Botan::RSA_PublicKey rsa_pubkey_from_tss2_public(const TPM2B_PUBLIC* public_blob);
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
/**
 * This helper function transforms a @p public_blob in a TPM2B_PUBLIC* format
 * into an ordinary Botan::EC_PublicKey in the form of a Botan::EC_Group and
 * a Botan::EC_AffinePoint. Note that the resulting key is not bound to a TPM
 * and can be used as any other ECC key.
 *
 * @param public_blob The public blob to load as an ordinary EC_Group and EC_AffinePoint
 */
BOTAN_PUBLIC_API(3, 7)
std::pair<EC_Group, EC_AffinePoint> ecc_pubkey_from_tss2_public(const TPM2B_PUBLIC* public_blob);
#endif

/**
 * This wraps a public key that is hosted in a TPM 2.0 device. This class allows
 * performing public-key operations on the TPM. Namely verifying signatures and
 * encrypting data.
 *
 * The class does not provide public constructors, but instead provides static
 * methods to obtain a public key handle from a TPM.
 */
class BOTAN_PUBLIC_API(3, 6) PublicKey : public virtual Botan::Public_Key {
   public:
      /**
       * Load a public key that resides in the TPM's persistent storage.
       *
       * @param ctx The TPM context to use
       * @param persistent_object_handle The handle of the persistent object to load
       * @param sessions The session bundle to use for loading
       */
      static std::unique_ptr<PublicKey> load_persistent(const std::shared_ptr<Context>& ctx,
                                                        TPM2_HANDLE persistent_object_handle,
                                                        const SessionBundle& sessions = {});

      /**
       * Load a public key from the public blob obtained by a TPM key creation.
       *
       * Transient keys don't reside inside the TPM but must be loaded by the
       * application as required. Once this object is destructed, the transient
       * memory on the TPM is cleared.
       *
       * @param ctx The TPM context to use
       * @param public_blob The public blob of the key to load
       * @param sessions The session bundle to use for loading
       */
      static std::unique_ptr<PublicKey> load_transient(const std::shared_ptr<Context>& ctx,
                                                       std::span<const uint8_t> public_blob,
                                                       const SessionBundle& sessions);

   public:
      std::unique_ptr<Private_Key> generate_another(Botan::RandomNumberGenerator&) const override {
         throw Not_Implemented("Cannot generate a new TPM-based keypair from this asymmetric key");
      }

      /**
       * @returns a TPM2-specific marshalled representation of the public key
       */
      std::vector<uint8_t> raw_public_key_bits() const override;

      const Object& handles() const { return m_handle; }

      const SessionBundle& sessions() const { return m_sessions; }

   protected:
      PublicKey(Object object, SessionBundle sessions) : m_handle(std::move(object)), m_sessions(std::move(sessions)) {}

      static std::unique_ptr<PublicKey> create(Object handles, const SessionBundle& sessions);

   private:
      Object m_handle;
      SessionBundle m_sessions;
};

BOTAN_DIAGNOSTIC_PUSH
BOTAN_DIAGNOSTIC_IGNORE_INHERITED_VIA_DOMINANCE

/**
 * This wraps a private key that is hosted in a TPM 2.0 device. This class
 * allows performing private-key operations on the TPM. Namely signing and
 * decrypting data.
 *
 * Note that there are two types of keys: persistent and transient. Persistent
 * keys are stored in the TPM's NVRAM and can be loaded at any time. Transient
 * keys are loaded by the application from an encrypted private blob that is
 * only readable by the TPM that created it. Once the key is loaded, the
 * application can use it as if it were a persistent key. Once the key is
 * destructed, the transient memory on the TPM is cleared.
 *
 * Applications may persist transient keys in the TPM's NVRAM by using the
 * TPM2_Context::persist() method. This allows the key to be loaded at a later
 * time without the need to provide the encrypted private blob. Similarly,
 * persistent keys may be permanently destroyed using TPM2_Context::evict().
 *
 * To obtain the public and private blobs of a transient key, use the
 * raw_public_key_bits() and raw_private_key_bits() methods, respectively.
 *
 * The class does not provide public constructors, but instead provides static
 * methods to obtain a private key handle from a TPM.
 */
class BOTAN_PUBLIC_API(3, 6) PrivateKey : public virtual Private_Key {
   public:
      /**
       * Load a private key that resides in the TPM's persistent storage.
       *
       * @param ctx The TPM context to use
       * @param persistent_object_handle The handle of the persistent object to load
       * @param auth_value The auth value required to use the key
       * @param sessions The session bundle to use for the key's operations
       */
      static std::unique_ptr<PrivateKey> load_persistent(const std::shared_ptr<Context>& ctx,
                                                         TPM2_HANDLE persistent_object_handle,
                                                         std::span<const uint8_t> auth_value,
                                                         const SessionBundle& sessions);

      /**
       * Load a private key from the public and private blobs obtained by a TPM
       * key creation.
       *
       * Transient keys don't reside inside the TPM but must be loaded by the
       * application as required. Once this object is destructed, the transient
       * memory on the TPM is cleared.
       *
       * @param ctx The TPM context to use
       * @param auth_value The auth value required to use the key
       * @param parent The parent key the key was originally created under
       * @param public_blob The public blob of the key to load
       * @param private_blob The private blob of the key to load
       * @param sessions The session bundle to use for loading
       */
      static std::unique_ptr<PrivateKey> load_transient(const std::shared_ptr<Context>& ctx,
                                                        std::span<const uint8_t> auth_value,
                                                        const TPM2::PrivateKey& parent,
                                                        std::span<const uint8_t> public_blob,
                                                        std::span<const uint8_t> private_blob,
                                                        const SessionBundle& sessions);

      /**
       * This is a wrapper around Esys_CreateLoaded creating a transient key
       * from a given @p key_template with @p sensitive_data. It gives maximal
       * flexibility to the caller to create a key with their own TSS2 template
       * configuration.
       *
       * Please use this if you know what you are doing, only! Most users should
       * use the more convenient create_transient() methods of the derived classes.
       *
       * @param ctx The TPM context to use
       * @param sessions The session bundle to use in Esys_CreateLoaded().
       * @param parent The handle of the parent object to create the new key under
       *               (this may reference a  "Primary Seed" to create a "Primary Key",
       *                a "Storage Parent" to create an "Ordinary Key", or
       *                a "Derivation Parent" to create a "Derived Key").
       * @param key_template The template data to use for the key creation. It
       *                     will be passed to Tss2_MU_TPMT_PUBLIC_Marshal() and
       *                     Esys_CreateLoaded().
       * @param sensitive_data The sensitive data (e.g. with the desired auth
       *                       value) to use for the key creation.
       */
      static std::unique_ptr<PrivateKey> create_transient_from_template(const std::shared_ptr<Context>& ctx,
                                                                        const SessionBundle& sessions,
                                                                        ESYS_TR parent,
                                                                        const TPMT_PUBLIC& key_template,
                                                                        const TPM2B_SENSITIVE_CREATE& sensitive_data);

   public:
      /// @throws Not_Implemented keys hosted in a TPM2 cannot be exported
      secure_vector<uint8_t> private_key_bits() const override {
         throw Not_Implemented("cannot export private key bits from a TPM2 key, maybe use raw_private_key_bits()?");
      }

      /**
       * @returns the encrypted private key blob, if the key is transient
       * @throws Invalid_State if the key is persistent
       */
      secure_vector<uint8_t> raw_private_key_bits() const override;

      /**
       * @returns a TPM2-specific marshalled representation of the public key
       */
      std::vector<uint8_t> raw_public_key_bits() const override;

      Object& handles() { return m_handle; }

      const Object& handles() const { return m_handle; }

      const SessionBundle& sessions() const { return m_sessions; }

      bool is_parent() const;

   protected:
      PrivateKey(Object handle, SessionBundle sessions, std::span<const uint8_t> private_blob = {}) :
            m_handle(std::move(handle)),
            m_sessions(std::move(sessions)),
            m_private_blob(private_blob.begin(), private_blob.end()) {}

      static std::unique_ptr<PrivateKey> create(Object handles,
                                                const SessionBundle& sessions,
                                                const TPM2B_PUBLIC* public_info,
                                                std::span<const uint8_t> private_blob);

   private:
      Object m_handle;
      SessionBundle m_sessions;

      /// Transient keys can be exported as an encrypted private blob that is
      /// readable by the TPM that created it.
      std::vector<uint8_t> m_private_blob;
};

BOTAN_DIAGNOSTIC_POP

}  // namespace Botan::TPM2

#endif
