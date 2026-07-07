/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_HPKE_H_
#define BOTAN_HPKE_H_

#include <botan/secmem.h>
#include <botan/types.h>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Botan {

class Public_Key;
class Private_Key;
class RandomNumberGenerator;

}  // namespace Botan

namespace Botan::HPKE {

class Private_Key;
class Sender_Context;
class Recipient_Context;

/**
* HPKE KEM identifiers
*
* These codepoints match the IANA "HPKE KEM Identifiers" registry
* established by RFC 9180 Section 7.1.
*/
enum class KEM_Code : uint16_t /* NOLINT(*-enum-size) */ {
   DHKEM_P256 = 0x0010,    // DHKEM(P-256, HKDF-SHA256)
   DHKEM_P384 = 0x0011,    // DHKEM(P-384, HKDF-SHA384)
   DHKEM_P521 = 0x0012,    // DHKEM(P-521, HKDF-SHA512)
   DHKEM_X25519 = 0x0020,  // DHKEM(X25519, HKDF-SHA256)
   DHKEM_X448 = 0x0021,    // DHKEM(X448, HKDF-SHA512)
};

/**
* HPKE KDF identifiers (RFC 9180 Section 7.2)
*/
enum class KDF_Code : uint16_t /* NOLINT(*-enum-size) */ {
   HKDF_SHA256 = 0x0001,
   HKDF_SHA384 = 0x0002,
   HKDF_SHA512 = 0x0003,
};

/**
* HPKE AEAD identifiers (RFC 9180 Section 7.3)
*/
enum class AEAD_Code : uint16_t {
   AES_128_GCM = 0x0001,
   AES_256_GCM = 0x0002,
   ChaCha20Poly1305 = 0x0003,
   ExportOnly = 0xFFFF,
};

/**
* Identifies the KEM used by an HPKE ciphersuite
*
* This may hold any 16-bit codepoint, including values unknown to the
* library (as may be encountered eg when parsing an ECHConfigList);
* is_known() and is_available() distinguish what can actually be used.
*/
class BOTAN_PUBLIC_API(3, 14) KEM_Id final {
   public:
      using enum KEM_Code;

      // NOLINTNEXTLINE(*-explicit-conversions)
      constexpr KEM_Id(KEM_Code code) : m_code(code) {}

      // Any codepoint is representable, including ones unknown to this library
      // NOLINTNEXTLINE(*-explicit-conversions,clang-analyzer-optin.core.EnumCastOutOfRange)
      constexpr KEM_Id(uint16_t code) : m_code(static_cast<KEM_Code>(code)) {}

      constexpr KEM_Code code() const { return m_code; }

      constexpr uint16_t wire_code() const { return static_cast<uint16_t>(m_code); }

      constexpr bool operator==(const KEM_Id& other) const { return m_code == other.m_code; }

      constexpr bool operator==(KEM_Code code) const { return m_code == code; }

      /// True if this codepoint is known to this version of the library
      constexpr bool is_known() const {
         switch(m_code) {
            case KEM_Code::DHKEM_P256:
            case KEM_Code::DHKEM_P384:
            case KEM_Code::DHKEM_P521:
            case KEM_Code::DHKEM_X25519:
            case KEM_Code::DHKEM_X448:
               return true;
         }
         return false;
      }

      /// True if the algorithms this KEM requires are available in this build
      bool is_available() const;

      constexpr bool is_dhkem() const {
         // See RFC 9180 Section 7.1
         return m_code == KEM_Code::DHKEM_P256 || m_code == KEM_Code::DHKEM_P384 || m_code == KEM_Code::DHKEM_P521 ||
                m_code == KEM_Code::DHKEM_X25519 || m_code == KEM_Code::DHKEM_X448;
      }

      /// Only the DH-based KEMs support the Auth and AuthPSK modes
      /// See RFC 9180 Section 7.1
      constexpr bool supports_auth_modes() const { return is_dhkem(); }

      /// Return the constant Nsecret from RFC 9180 Section 7.1, throws for invalid code points
      size_t shared_secret_length() const;

      /// Return the constant Nenc from RFC 9180 Section 7.1, throws for invalid code points
      size_t encapsulation_length() const;

      /// Return the constant Npk from RFC 9180 Section 7.1, throws for invalid code points
      size_t public_key_length() const;

      /// Return the constant Nsk from RFC 9180 Section 7.1, throws for invalid code points
      size_t private_key_length() const;

      /// Returns std::nullopt for unknown codepoints
      std::optional<std::string> to_string() const;

   private:
      KEM_Code m_code;
};

/**
* Identifies the KDF used by an HPKE ciphersuite
*/
class BOTAN_PUBLIC_API(3, 14) KDF_Id final {
   public:
      using enum KDF_Code;

      // NOLINTNEXTLINE(*-explicit-conversions)
      constexpr KDF_Id(KDF_Code code) : m_code(code) {}

      // Any codepoint is representable, including ones unknown to this library
      // NOLINTNEXTLINE(*-explicit-conversions,clang-analyzer-optin.core.EnumCastOutOfRange)
      constexpr KDF_Id(uint16_t code) : m_code(static_cast<KDF_Code>(code)) {}

      constexpr KDF_Code code() const { return m_code; }

      constexpr uint16_t wire_code() const { return static_cast<uint16_t>(m_code); }

      constexpr bool operator==(const KDF_Id& other) const { return m_code == other.m_code; }

      constexpr bool operator==(KDF_Code code) const { return m_code == code; }

      constexpr bool is_known() const {
         switch(m_code) {
            case KDF_Code::HKDF_SHA256:
            case KDF_Code::HKDF_SHA384:
            case KDF_Code::HKDF_SHA512:
               return true;
         }
         return false;
      }

      bool is_available() const;

      /// The KDF output length Nh; throws Invalid_State for unknown codepoints
      /// See RFC 9180 Section 7.2
      size_t output_length() const;

      std::optional<std::string> to_string() const;

   private:
      KDF_Code m_code;
};

/**
* Identifies the AEAD used by an HPKE ciphersuite
*/
class BOTAN_PUBLIC_API(3, 14) AEAD_Id final {
   public:
      using enum AEAD_Code;

      // NOLINTNEXTLINE(*-explicit-conversions)
      constexpr AEAD_Id(AEAD_Code code) : m_code(code) {}

      // Any codepoint is representable, including ones unknown to this library
      // NOLINTNEXTLINE(*-explicit-conversions,clang-analyzer-optin.core.EnumCastOutOfRange)
      constexpr AEAD_Id(uint16_t code) : m_code(static_cast<AEAD_Code>(code)) {}

      constexpr AEAD_Code code() const { return m_code; }

      constexpr uint16_t wire_code() const { return static_cast<uint16_t>(m_code); }

      constexpr bool operator==(const AEAD_Id& other) const { return m_code == other.m_code; }

      constexpr bool operator==(AEAD_Code code) const { return m_code == code; }

      constexpr bool is_known() const {
         switch(m_code) {
            case AEAD_Code::AES_128_GCM:
            case AEAD_Code::AES_256_GCM:
            case AEAD_Code::ChaCha20Poly1305:
            case AEAD_Code::ExportOnly:
               return true;
         }
         return false;
      }

      bool is_available() const;

      /// An export-only suite creates contexts usable only for export_secret
      /// See RFC 9180 Section 5.3
      constexpr bool is_export_only() const { return m_code == AEAD_Code::ExportOnly; }

      /// Return the constant Nk from RFC 9180 Section 7.3, throws for invalid code points
      size_t key_length() const;

      /// Return the constant Nn from RFC 9180 Section 7.3, throws for invalid code points
      size_t nonce_length() const;

      /// Return the constant Nt from RFC 9180 Section 7.3, throws for invalid code points
      size_t tag_length() const;

      std::optional<std::string> to_string() const;

   private:
      AEAD_Code m_code;
};

/**
* An HPKE ciphersuite: the triple of KEM, KDF and AEAD
* See RFC 9180 Section 4
*
* This is a plain value type; it may hold any combination of codepoints,
* including unknown ones. Availability is checked when a context is created.
*/
class BOTAN_PUBLIC_API(3, 14) Suite final {
   public:
      constexpr Suite(KEM_Id kem, KDF_Id kdf, AEAD_Id aead) : m_kem(kem), m_kdf(kdf), m_aead(aead) {}

      constexpr KEM_Id kem() const { return m_kem; }

      constexpr KDF_Id kdf() const { return m_kdf; }

      constexpr AEAD_Id aead() const { return m_aead; }

      constexpr bool operator==(const Suite& other) const {
         return m_kem == other.m_kem && m_kdf == other.m_kdf && m_aead == other.m_aead;
      }

      constexpr bool is_known() const { return m_kem.is_known() && m_kdf.is_known() && m_aead.is_known(); }

      bool is_available() const { return m_kem.is_available() && m_kdf.is_available() && m_aead.is_available(); }

      constexpr bool is_export_only() const { return m_aead.is_export_only(); }

      /// Bytes added to each plaintext when sealed (the AEAD tag length)
      /// See RFC 9180 Section 5.2
      size_t ciphertext_overhead() const { return m_aead.tag_length(); }

      std::optional<std::string> to_string() const;

   private:
      KEM_Id m_kem;
      KDF_Id m_kdf;
      AEAD_Id m_aead;
};

/**
* An HPKE public key
*
* This is a value type (cheap to copy) wrapping an asymmetric key that
* has been validated for use with a particular HPKE KEM. It has no
* inheritance relationship with Botan::Public_Key or with HPKE::Private_Key.
*/
class BOTAN_PUBLIC_API(3, 14) Public_Key final {
   public:
      /**
      * DeserializePublicKey from RFC 9180 Section 7.1.1
      *
      * Accepts exactly the wire format the KEM defines (raw bytes for
      * X25519/X448, an uncompressed SEC1 point for the NIST curves)
      * and validates the key. Throws Decoding_Error if malformed.
      */
      static Public_Key deserialize(KEM_Id kem, std::span<const uint8_t> bytes);

      /**
      * Adopt an existing key for use with HPKE
      *
      * For the NIST curves both ECDH and ECDSA keys are accepted, the latter
      * being how keys with the id-ecPublicKey OID (eg from an X.509 certificate)
      * are loaded; an ECDSA key is converted, so underlying() always returns an
      * ECDH key. Keys of other EC algorithms (SM2, ECGDSA, ...) are not accepted.
      *
      * Throws Invalid_Argument unless the algorithm (and, for the NIST curves,
      * the group) matches the KEM.
      */
      static Public_Key from_key(KEM_Id kem, std::unique_ptr<Botan::Public_Key> key);

      KEM_Id kem() const;

      /// SerializePublicKey from RFC 9180 Section 7.1.1
      std::vector<uint8_t> serialize() const;

      /**
      * Access the wrapped key, eg for encoding as a X.509 SubjectPublicKeyInfo
      *
      * For the NIST curves this is an ECDH key, which encodes with the
      * id-ecDH algorithm identifier.
      */
      const Botan::Public_Key& underlying() const;

      friend bool operator==(const Public_Key& a, const Public_Key& b) {
         return a.kem() == b.kem() && a.serialize() == b.serialize();
      }

   private:
      class Data;

      explicit Public_Key(std::shared_ptr<const Data> data) : m_data(std::move(data)) {}

      friend class HPKE::Private_Key;
      friend class HPKE::Sender_Context;
      friend class HPKE::Recipient_Context;

      std::shared_ptr<const Data> m_data;
};

/**
* An HPKE private key
*
* This is a value type (cheap to copy) wrapping an asymmetric key that
* has been validated for use with a particular HPKE KEM. It has no
* inheritance relationship with Botan::Private_Key or with HPKE::Public_Key;
* the corresponding public key is obtained with public_key().
*/
class BOTAN_PUBLIC_API(3, 14) Private_Key final {
   public:
      /// GenerateKeyPair from RFC 9180 Section 4
      static Private_Key generate(KEM_Id kem, RandomNumberGenerator& rng);

      /**
      * DeriveKeyPair from RFC 9180 Section 7.1.3
      *
      * Deterministically derives a key pair from input keying material,
      * which must be full-entropy secret data of at least Nsk bytes; as
      * an exception DHKEM(P-521) accepts 64 bytes, since MLS (RFC 9420 Section 7.4)
      * derives P-521 key pairs from 64-byte node secrets.
      */
      static Private_Key derive(KEM_Id kem, std::span<const uint8_t> ikm);

      /**
      * DeserializePrivateKey from RFC 9180 Section 7.1.2
      *
      * Accepts Nsk raw bytes. The scalar is range-checked for the NIST
      * curves, and clamped (RFC 7748 Section 5) for X25519 and X448.
      */
      static Private_Key deserialize(KEM_Id kem, std::span<const uint8_t> bytes);

      /**
      * Adopt an existing key (eg loaded from PKCS #8) for use with HPKE
      *
      * As for Public_Key::from_key, ECDSA keys on the NIST curves are accepted
      * and converted to ECDH, while other EC algorithms are rejected. Throws
      * Invalid_Argument unless the key's algorithm (and, for the NIST curves,
      * its group) matches the KEM.
      */
      static Private_Key from_key(KEM_Id kem, std::unique_ptr<Botan::Private_Key> key);

      KEM_Id kem() const;

      /// The corresponding public key
      Public_Key public_key() const;

      /**
      * SerializePrivateKey from RFC 9180 Section 7.1.2
      *
      * For X25519 and X448 the output is clamped, as RFC 9180 Section 7.1.2
      * requires.
      */
      secure_vector<uint8_t> serialize() const;

      /**
      * Access the wrapped key, eg for encoding as PKCS #8
      *
      * For the NIST curves this is an ECDH key, which encodes with the
      * id-ecDH algorithm identifier.
      */
      const Botan::Private_Key& underlying() const;

   private:
      class Data;

      explicit Private_Key(std::shared_ptr<const Data> data) : m_data(std::move(data)) {}

      friend class HPKE::Sender_Context;
      friend class HPKE::Recipient_Context;

      std::shared_ptr<const Data> m_data;
};

/**
* A pre-shared key plus identity, for the PSK and AuthPSK modes
*
* RFC 9180 Section 5.1 requires both fields to be non-empty, and (following the
* recommendation of its Section 9.5) the PSK must be at least 32 bytes.
*/
class BOTAN_PUBLIC_API(3, 14) PSK final {
   public:
      PSK(std::span<const uint8_t> psk, std::span<const uint8_t> psk_id);

      std::span<const uint8_t> secret() const { return m_psk; }

      std::span<const uint8_t> identity() const { return m_psk_id; }

   private:
      secure_vector<uint8_t> m_psk;
      std::vector<uint8_t> m_psk_id;
};

/// The four HPKE modes, with their codepoints from RFC 9180 Section 5
enum class Mode : uint8_t {
   Base = 0x00,
   PSK = 0x01,
   Auth = 0x02,
   AuthPSK = 0x03,
};

namespace detail {

class Context_Data;

}  // namespace detail

/**
* HPKE sender (encryption) context
*
* Created by one of the setup_* factories, each corresponding to an
* RFC 9180 setup function (SetupBaseS, SetupPSKS, SetupAuthS, SetupAuthPSKS).
*
* All factories throw Invalid_Argument if the recipient (or sender identity)
* key does not match the suite's KEM, if the recipient key is a low order
* X25519/X448 point, or for an auth mode if the KEM does not support sender
* authentication. They throw Not_Implemented or Lookup_Error if the suite is
* not available in this build.
*/
class BOTAN_PUBLIC_API(3, 14) Sender_Context final {
   public:
      static Sender_Context setup_base(const Suite& suite,
                                       const Public_Key& recipient_key,
                                       RandomNumberGenerator& rng,
                                       std::span<const uint8_t> info = {});

      static Sender_Context setup_psk(const Suite& suite,
                                      const Public_Key& recipient_key,
                                      RandomNumberGenerator& rng,
                                      const PSK& psk,
                                      std::span<const uint8_t> info = {});

      static Sender_Context setup_auth(const Suite& suite,
                                       const Public_Key& recipient_key,
                                       const Private_Key& sender_identity_key,
                                       RandomNumberGenerator& rng,
                                       std::span<const uint8_t> info = {});

      static Sender_Context setup_auth_psk(const Suite& suite,
                                           const Public_Key& recipient_key,
                                           const Private_Key& sender_identity_key,
                                           RandomNumberGenerator& rng,
                                           const PSK& psk,
                                           std::span<const uint8_t> info = {});

      Sender_Context(const Sender_Context&) = delete;
      Sender_Context& operator=(const Sender_Context&) = delete;
      Sender_Context(Sender_Context&&) noexcept;
      Sender_Context& operator=(Sender_Context&&) noexcept;
      ~Sender_Context();

      /// The KEM encapsulation ("enc") to be transmitted to the recipient
      const std::vector<uint8_t>& encapsulated_key() const;

      /**
      * Encrypt a message to the recipient, using the next sequence number
      *
      * Throws Invalid_State for an export-only suite, or if the message
      * limit has been reached.
      */
      std::vector<uint8_t> seal(std::span<const uint8_t> aad, std::span<const uint8_t> ptext);

      /**
      * Secret export (RFC 9180 Section 5.3)
      *
      * @p length must be at most 255 times the KDF output length
      */
      secure_vector<uint8_t> export_secret(std::span<const uint8_t> exporter_context, size_t length) const;

      /// The sequence number the next call to seal() will use
      uint64_t next_sequence() const;

      Mode mode() const;

      Suite suite() const;

   private:
      explicit Sender_Context(std::unique_ptr<detail::Context_Data> data);

      static Sender_Context setup(Mode mode,
                                  const Suite& suite,
                                  const Public_Key& recipient_key,
                                  const Private_Key* sender_identity_key,
                                  const PSK* psk,
                                  RandomNumberGenerator& rng,
                                  std::span<const uint8_t> info);

      std::unique_ptr<detail::Context_Data> m_data;
};

/**
* HPKE recipient (decryption) context
*
* Created by one of the setup_* factories, each corresponding to an
* RFC 9180 setup function (SetupBaseR, SetupPSKR, SetupAuthR, SetupAuthPSKR).
*
* The factories throw as described for Sender_Context, and additionally
* throw Decoding_Error if the encapsulated key is malformed (wrong length
* or encoding, or not a point on the curve), or Invalid_Argument if it or
* the sender identity key is a low order X25519/X448 point.
*/
class BOTAN_PUBLIC_API(3, 14) Recipient_Context final {
   public:
      static Recipient_Context setup_base(const Suite& suite,
                                          const Private_Key& recipient_key,
                                          std::span<const uint8_t> enc,
                                          RandomNumberGenerator& rng,
                                          std::span<const uint8_t> info = {});

      static Recipient_Context setup_psk(const Suite& suite,
                                         const Private_Key& recipient_key,
                                         std::span<const uint8_t> enc,
                                         RandomNumberGenerator& rng,
                                         const PSK& psk,
                                         std::span<const uint8_t> info = {});

      static Recipient_Context setup_auth(const Suite& suite,
                                          const Private_Key& recipient_key,
                                          std::span<const uint8_t> enc,
                                          const Public_Key& sender_identity_key,
                                          RandomNumberGenerator& rng,
                                          std::span<const uint8_t> info = {});

      static Recipient_Context setup_auth_psk(const Suite& suite,
                                              const Private_Key& recipient_key,
                                              std::span<const uint8_t> enc,
                                              const Public_Key& sender_identity_key,
                                              RandomNumberGenerator& rng,
                                              const PSK& psk,
                                              std::span<const uint8_t> info = {});

      Recipient_Context(const Recipient_Context&) = delete;
      Recipient_Context& operator=(const Recipient_Context&) = delete;
      Recipient_Context(Recipient_Context&&) noexcept;
      Recipient_Context& operator=(Recipient_Context&&) noexcept;
      ~Recipient_Context();

      /**
      * Decrypt a message, using the next sequence number
      *
      * Throws Invalid_Authentication_Tag for truncated or unauthentic ciphertexts,
      * or Invalid_State for export-only suites or an exhausted sequence counter.
      * The sequence number is consumed only if decryption succeeds.
      */
      secure_vector<uint8_t> open(std::span<const uint8_t> aad, std::span<const uint8_t> ctext);

      /**
      * Decrypt the message with the given sequence number
      *
      * This does not read or modify the sequence counter used by open(),
      * in order to support out-of-order transports.
      */
      secure_vector<uint8_t> open_at_sequence(uint64_t seq,
                                              std::span<const uint8_t> aad,
                                              std::span<const uint8_t> ctext);

      /**
      * Secret export (RFC 9180 Section 5.3)
      *
      * @p length must be at most 255 times the KDF output length
      */
      secure_vector<uint8_t> export_secret(std::span<const uint8_t> exporter_context, size_t length) const;

      /**
      * The sequence number the next call to open() will use
      */
      uint64_t next_sequence() const;

      Mode mode() const;

      Suite suite() const;

   private:
      explicit Recipient_Context(std::unique_ptr<detail::Context_Data> data);

      static Recipient_Context setup(Mode mode,
                                     const Suite& suite,
                                     const Private_Key& recipient_key,
                                     std::span<const uint8_t> enc,
                                     const Public_Key* sender_identity_key,
                                     const PSK* psk,
                                     RandomNumberGenerator& rng,
                                     std::span<const uint8_t> info);

      std::unique_ptr<detail::Context_Data> m_data;
};

}  // namespace Botan::HPKE

#endif
