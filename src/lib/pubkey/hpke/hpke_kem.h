/*
* HPKE KEM abstraction (RFC 9180 Section 7.1)
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HPKE_KEM_H_
#define BOTAN_HPKE_KEM_H_

#include <botan/hpke.h>
#include <botan/pk_keys.h>

namespace Botan::HPKE {

/**
* LabeledExtract from RFC 9180 Section 4
*
* @p hash is a Botan hash function name eg "SHA-256"; @p suite_id is
* either the KEM suite_id ("KEM" || kem_id) or the full HPKE suite_id
* ("HPKE" || kem_id || kdf_id || aead_id) depending on the caller.
*/
BOTAN_TEST_API secure_vector<uint8_t> labeled_extract(std::string_view hash,
                                                      std::span<const uint8_t> suite_id,
                                                      std::span<const uint8_t> salt,
                                                      std::string_view label,
                                                      std::span<const uint8_t> ikm);

/**
* LabeledExpand from RFC 9180 Section 4
*/
BOTAN_TEST_API secure_vector<uint8_t> labeled_expand(std::string_view hash,
                                                     std::span<const uint8_t> suite_id,
                                                     std::span<const uint8_t> prk,
                                                     std::string_view label,
                                                     std::span<const uint8_t> info,
                                                     size_t length);

/**
* Internal interface for the KEM operations HPKE requires
*
* Implemented by DHKEM (RFC 9180 Section 4.1) over the key agreement algorithms.
*/
class BOTAN_TEST_API KEM_Ops {
   public:
      struct Encapsulation {
            std::vector<uint8_t> enc;
            secure_vector<uint8_t> shared_secret;
      };

      /**
      * Create the operations for a KEM
      *
      * Throws Not_Implemented if the codepoint is unknown or the required
      * algorithms are not available in this build.
      */
      static std::unique_ptr<const KEM_Ops> create(KEM_Id kem);

      virtual ~KEM_Ops() = default;
      KEM_Ops(const KEM_Ops&) = delete;
      KEM_Ops& operator=(const KEM_Ops&) = delete;
      KEM_Ops(KEM_Ops&&) = delete;
      KEM_Ops& operator=(KEM_Ops&&) = delete;

      KEM_Id kem_id() const { return m_kem; }

      // See RFC 9180 Section 7.1.5
      virtual bool supports_auth() const { return false; }

      virtual Encapsulation encap(const Botan::Public_Key& pkR, RandomNumberGenerator& rng) const = 0;

      virtual secure_vector<uint8_t> decap(std::span<const uint8_t> enc,
                                           const Botan::Private_Key& skR,
                                           RandomNumberGenerator& rng) const = 0;

      /// Only supported if supports_auth(); the default implementations throw
      virtual Encapsulation auth_encap(const Botan::Public_Key& pkR,
                                       const Botan::Private_Key& skS,
                                       RandomNumberGenerator& rng) const;

      virtual secure_vector<uint8_t> auth_decap(std::span<const uint8_t> enc,
                                                const Botan::Private_Key& skR,
                                                const Botan::Public_Key& pkS,
                                                RandomNumberGenerator& rng) const;

      /**
      * Deterministic encapsulation with a caller-provided ephemeral key,
      * for known-answer testing of DHKEMs. The default implementation throws.
      */
      virtual Encapsulation encap_with_ephemeral(const Botan::Public_Key& pkR,
                                                 const Botan::Private_Key& skE,
                                                 RandomNumberGenerator& rng) const;

      /**
      * Deterministic authenticated encapsulation with a caller-provided
      * ephemeral key, for known-answer testing of DHKEMs. The default
      * implementation throws.
      */
      virtual Encapsulation auth_encap_with_ephemeral(const Botan::Public_Key& pkR,
                                                      const Botan::Private_Key& skS,
                                                      const Botan::Private_Key& skE,
                                                      RandomNumberGenerator& rng) const;

      virtual std::unique_ptr<Botan::Private_Key> generate_key(RandomNumberGenerator& rng) const = 0;

      virtual std::unique_ptr<Botan::Private_Key> derive_key_pair(std::span<const uint8_t> ikm) const = 0;

      virtual std::unique_ptr<Botan::Public_Key> deserialize_public(std::span<const uint8_t> bytes) const = 0;

      virtual std::unique_ptr<Botan::Private_Key> deserialize_private(std::span<const uint8_t> bytes) const = 0;

      virtual std::vector<uint8_t> serialize_public(const Botan::Public_Key& key) const = 0;

      virtual secure_vector<uint8_t> serialize_private(const Botan::Private_Key& key) const = 0;

      /**
      * Adopt an existing key for use with this KEM
      *
      * Returns the key itself if it is of the type the KEM operates on, or
      * an equivalent key of that type (for the NIST curves, an ECDSA key is
      * converted to ECDH). Throws Invalid_Argument for any other key, or if
      * the key's group does not match the KEM.
      */
      virtual std::unique_ptr<Botan::Public_Key> adopt_public(std::unique_ptr<Botan::Public_Key> key) const = 0;

      virtual std::unique_ptr<Botan::Private_Key> adopt_private(std::unique_ptr<Botan::Private_Key> key) const = 0;

   protected:
      explicit KEM_Ops(KEM_Id kem) : m_kem(kem) {}

   private:
      KEM_Id m_kem;
};

}  // namespace Botan::HPKE

#endif
