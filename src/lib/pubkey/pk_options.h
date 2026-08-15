/*
* (C) 2024,2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPTIONS_H_
#define BOTAN_PK_OPTIONS_H_

#include <botan/pk_keys.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class PK_Signer;
class PK_Verifier;
class PK_Encryptor_EME;
class PK_Decryptor_EME;
class PK_KEM_Encryptor;
class PK_KEM_Decryptor;
class PK_Key_Agreement;

/**
* Signature generation/verification options
*
* The normal usage of this is in a builder style, eg
*
* PK_Signature_Options()
*   .with_hash("SHA-256")
*   .with_der_encoded_signature()
*   .with_context("Foo")
*
* Every option that is set must be understood by the signature scheme in use.
* If a scheme does not support an option (for example a context for RSA, or a
* salt for Ed25519) then constructing the PK_Signer or PK_Verifier throws an
* exception; an option is never silently ignored.
*/
class BOTAN_PUBLIC_API(3, 14) PK_Signature_Options final {
   public:
      /// Create an empty PK_Signature_Options
      ///
      /// This can be further parameterized by calling with_xxx functions
      PK_Signature_Options() = default;

      PK_Signature_Options(PK_Signature_Options&& other) = default;
      PK_Signature_Options& operator=(PK_Signature_Options&& other) = default;

      PK_Signature_Options(const PK_Signature_Options&) = default;
      PK_Signature_Options& operator=(const PK_Signature_Options& other) = default;
      ~PK_Signature_Options();

      /// Format this PK_Signature_Options as a string
      ///
      /// This is primarily intended for debugging and error messages;
      /// the format is not fixed
      std::string to_string() const;

      /// Specify the hash function to use for signing/verification
      ///
      /// Most, but not all, schemes require specifying a hash function.
      PK_Signature_Options with_hash(std::string_view hash);

      /// Specify a padding scheme
      ///
      /// This is mostly/only used for RSA
      ///
      /// If the scheme does not support a padding option, it will throw an
      /// exception when presented with such an option.
      PK_Signature_Options with_padding(std::string_view padding);

      /// Request that the library prehash the message
      ///
      /// Some signature schemes, such as Ed25519, normally sign the
      /// entire message along with some context data. However such
      /// schemes also sometimes offer a prehashing variant where the
      /// message is hashed on its own, then the hash is signed.
      ///
      /// With this option the library computes the prehash itself; the
      /// caller still provides the full message. If given this specifies
      /// what hash function to use for prehashing. If prehash is nullopt,
      /// this requests prehashing using an algorithm specific default
      /// function.
      ///
      /// If the scheme does not support prehashing, it will throw an
      /// exception when presented with such an option.
      ///
      /// This cannot be combined with with_externally_computed_prehash
      PK_Signature_Options with_prehash(std::optional<std::string> prehash = std::nullopt);

      /// Specify that the caller has already hashed the message
      ///
      /// With this option the data passed to the signature operation is
      /// not the message but a hash of it, which the caller computed. The
      /// library signs (or verifies) the provided digest directly, without
      /// hashing it again.
      ///
      /// The hash function that was used can be named either here or via
      /// with_hash (if both are given they must agree). Naming it allows
      /// the scheme to check the digest length and to identify the hash in
      /// the signature where the format requires it (for example the
      /// PKCS #1 v1.5 DigestInfo). If no hash is named the input is signed
      /// as an opaque byte string.
      ///
      /// @warning Signing externally computed hashes is easy to get wrong
      /// and many ways of doing it are insecure. Don't use this unless you
      /// know what you are doing.
      ///
      /// If the scheme does not support signing an externally computed hash,
      /// it will throw an exception when presented with such an option.
      ///
      /// This cannot be combined with with_prehash
      PK_Signature_Options with_externally_computed_prehash(std::optional<std::string> hash = std::nullopt);

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      PK_Signature_Options with_context(std::span<const uint8_t> context);

      /// Specify a context as a string
      ///
      /// Equivalent to the version taking a span above; just uses the bytes
      /// of the string instead.
      PK_Signature_Options with_context(std::string_view context);

      /// Specify the size of salt to be used
      ///
      /// A small number of padding schemes (most importantly RSA-PSS) use a randomized
      /// salt. This allows controlling the size of the salt that is used.
      PK_Signature_Options with_salt_size(size_t salt_size);

      /// Request producing a deterministic signature
      ///
      /// Some signature schemes are always deterministic, or always randomized.
      /// Others support both randomized or deterministic options. This allows
      /// requesting this. For signatures which are always deterministic this
      /// option has no effect. Schemes which can only produce randomized
      /// signatures reject this option.
      ///
      /// This option is ignored for verification
      PK_Signature_Options with_deterministic_signature(bool deterministic = true);

      /// Specify producing or expecting a DER encoded signature
      ///
      /// This is mostly used with ECDSA
      ///
      /// For schemes that do not support such formatting (such as RSA
      /// or post-quantum schemes), an exception will be thrown when the
      /// PK_Signer or PK_Verifier is created.
      PK_Signature_Options with_der_encoded_signature(bool der = true);

      /// Specify producing or expecting an explicit trailer field
      ///
      /// Certain RSA padding schemes, such as PSS and ISO-9796, support two
      /// different trailer fields. One is an "implicit" trailer, which does not
      /// directly identify the hash. The other is an "explicit" trailer, which
      /// does.
      ///
      /// Note that currently this option is only supported by ISO-9796. While
      /// some standards allow PSS to use a trailer field, others (such as RFC
      /// 4055) prohibit using explicit trailers for PSS, and it is not
      /// currently supported.
      ///
      PK_Signature_Options with_explicit_trailer_field(bool trailer = true);

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_Signature_Options with_provider(std::string_view provider);

      /// Return the name of the hash function to use
      ///
      /// This will throw an exception if no hash function was configured
      std::string hash_function_name() const;

      /*
      * Getters; these are mostly for internal use
      *
      * Calling any of these records that the respective option was examined by
      * the signature scheme (see PK_Signature_Options::Option below), so a scheme
      * should only read an option that it will actually act on.
      */

      const std::optional<std::string>& hash_function() const {
         note_examined(Option::Hash);
         return m_hash_fn;
      }

      const std::optional<std::string>& prehash_function() const {
         note_examined(Option::Prehash);
         return m_prehash;
      }

      const std::optional<std::string>& externally_computed_prehash_function() const {
         note_examined(Option::ExternalPrehash);
         return m_external_prehash;
      }

      const std::optional<std::string>& padding() const {
         note_examined(Option::Padding);
         return m_padding;
      }

      const std::optional<std::vector<uint8_t>>& context() const {
         note_examined(Option::Context);
         return m_context;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_provider;
      }

      const std::optional<size_t>& salt_size() const {
         note_examined(Option::SaltSize);
         return m_salt_size;
      }

      bool using_der_encoded_signature() const {
         note_examined(Option::DerEncoded);
         return m_use_der;
      }

      bool using_deterministic_signature() const {
         note_examined(Option::Deterministic);
         return m_deterministic_sig;
      }

      bool using_explicit_trailer_field() const {
         note_examined(Option::ExplicitTrailer);
         return m_explicit_trailer_field;
      }

      bool using_hash() const { return hash_function().has_value(); }

      bool using_context() const { return context().has_value(); }

      bool using_prehash() const {
         note_examined(Option::Prehash);
         return m_using_prehash;
      }

      bool using_externally_computed_prehash() const {
         note_examined(Option::ExternalPrehash);
         return m_using_external_prehash;
      }

      bool using_padding() const { return padding().has_value(); }

      bool using_salt_size() const { return salt_size().has_value(); }

      bool using_provider() const;

   private:
      friend class PK_Signer;
      friend class PK_Verifier;

      /*
      * Each option a caller sets must be examined by whatever creates the
      * signature operation, otherwise the option would be silently ignored.
      * The getters above record which options were examined; PK_Signer and
      * PK_Verifier then reject any option that was set but never examined.
      */
      enum class Option : uint32_t /* NOLINT(*-enum-size) */ {
         Hash = (1 << 0),
         Prehash = (1 << 1),
         Padding = (1 << 2),
         Context = (1 << 3),
         Provider = (1 << 4),
         SaltSize = (1 << 5),
         DerEncoded = (1 << 6),
         Deterministic = (1 << 7),
         ExplicitTrailer = (1 << 8),
         ExternalPrehash = (1 << 9),
      };

      void note_examined(Option option) const { m_examined |= static_cast<uint32_t>(option); }

      /// Return the bitmask of options which were set to a non-default value
      uint32_t options_in_use() const;

      void reset_examined() const { m_examined = 0; }

      /// Throw Invalid_Argument if any option in use has not been examined
      void throw_if_unexamined(std::string_view algo_name) const;

      std::optional<std::string> m_hash_fn;
      std::optional<std::string> m_prehash;
      std::optional<std::string> m_external_prehash;
      std::optional<std::string> m_padding;
      std::optional<std::vector<uint8_t>> m_context;
      std::optional<std::string> m_provider;
      std::optional<size_t> m_salt_size;
      bool m_using_prehash = false;
      bool m_using_external_prehash = false;
      bool m_use_der = false;
      bool m_deterministic_sig = false;
      bool m_explicit_trailer_field = false;
      mutable uint32_t m_examined = 0;
};

/**
* Public key encryption/decryption options
*
* The normal usage of this is in a builder style, eg
*
* PK_Encryption_Options()
*   .with_padding("OAEP")
*   .with_hash("SHA-256")
*   .with_context(label)
*
* As with PK_Signature_Options, every option that is set must be understood by
* the encryption scheme in use; constructing the PK_Encryptor_EME or
* PK_Decryptor_EME throws an exception otherwise. An option is never silently
* ignored.
*/
class BOTAN_PUBLIC_API(3, 14) PK_Encryption_Options final {
   public:
      PK_Encryption_Options() = default;

      PK_Encryption_Options(PK_Encryption_Options&& other) = default;
      PK_Encryption_Options& operator=(PK_Encryption_Options&& other) = default;

      PK_Encryption_Options(const PK_Encryption_Options&) = default;
      PK_Encryption_Options& operator=(const PK_Encryption_Options& other) = default;
      ~PK_Encryption_Options();

      /// Format this PK_Encryption_Options as a string
      ///
      /// This is primarily intended for debugging and error messages;
      /// the format is not fixed
      std::string to_string() const;

      /// Specify the padding scheme
      ///
      /// For RSA (and ElGamal) this is required, and is one of "OAEP", "PKCS1v15"
      /// or "Raw". Other schemes do not use padding.
      PK_Encryption_Options with_padding(std::string_view padding);

      /// Specify the hash function
      ///
      /// For OAEP this selects the hash used for the label and (unless
      /// with_mgf1_hash is also used) for the mask generation function.
      /// For SM2 it selects the KDF hash, and defaults to SM3.
      PK_Encryption_Options with_hash(std::string_view hash);

      /// Specify a different hash function for OAEP's MGF1
      ///
      /// Only OAEP supports this; by default MGF1 uses the same hash as OAEP
      PK_Encryption_Options with_mgf1_hash(std::string_view hash);

      /// Specify a context
      ///
      /// For OAEP this is the label ("L" in RFC 8017). Schemes without such
      /// a parameter reject this option.
      PK_Encryption_Options with_context(std::span<const uint8_t> context);

      /// Specify a context as a string
      ///
      /// Equivalent to the version taking a span above; just uses the bytes
      /// of the string instead.
      PK_Encryption_Options with_context(std::string_view context);

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_Encryption_Options with_provider(std::string_view provider);

      /// Return the name of the hash function to use
      ///
      /// This will throw an exception if no hash function was configured
      std::string hash_function_name() const;

      /*
      * Getters; these are mostly for internal use
      *
      * Calling any of these records that the respective option was examined
      * by the scheme, so a scheme should only read an option it will act on.
      */

      const std::optional<std::string>& padding() const {
         note_examined(Option::Padding);
         return m_padding;
      }

      const std::optional<std::string>& hash_function() const {
         note_examined(Option::Hash);
         return m_hash_fn;
      }

      const std::optional<std::string>& mgf1_hash_function() const {
         note_examined(Option::Mgf1Hash);
         return m_mgf1_hash_fn;
      }

      const std::optional<std::vector<uint8_t>>& context() const {
         note_examined(Option::Context);
         return m_context;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_provider;
      }

      bool using_padding() const { return padding().has_value(); }

      bool using_hash() const { return hash_function().has_value(); }

      bool using_mgf1_hash() const { return mgf1_hash_function().has_value(); }

      bool using_context() const { return context().has_value(); }

      bool using_provider() const;

   private:
      friend class PK_Encryptor_EME;
      friend class PK_Decryptor_EME;

      enum class Option : uint32_t /* NOLINT(*-enum-size) */ {
         Padding = (1 << 0),
         Hash = (1 << 1),
         Mgf1Hash = (1 << 2),
         Context = (1 << 3),
         Provider = (1 << 4),
      };

      void note_examined(Option option) const { m_examined |= static_cast<uint32_t>(option); }

      uint32_t options_in_use() const;

      void reset_examined() const { m_examined = 0; }

      void throw_if_unexamined(std::string_view algo_name) const;

      std::optional<std::string> m_padding;
      std::optional<std::string> m_hash_fn;
      std::optional<std::string> m_mgf1_hash_fn;
      std::optional<std::vector<uint8_t>> m_context;
      std::optional<std::string> m_provider;
      mutable uint32_t m_examined = 0;
};

/**
* Key encapsulation options
*
* The normal usage of this is in a builder style, eg
*
* PK_KEM_Options().with_kdf("HKDF(SHA-256)")
*
* As with PK_Signature_Options, every option that is set must be understood by
* the KEM in use; constructing the PK_KEM_Encryptor or PK_KEM_Decryptor throws
* an exception otherwise.
*/
class BOTAN_PUBLIC_API(3, 14) PK_KEM_Options final {
   public:
      PK_KEM_Options() = default;

      PK_KEM_Options(PK_KEM_Options&& other) = default;
      PK_KEM_Options& operator=(PK_KEM_Options&& other) = default;

      PK_KEM_Options(const PK_KEM_Options&) = default;
      PK_KEM_Options& operator=(const PK_KEM_Options& other) = default;
      ~PK_KEM_Options();

      /// Format this PK_KEM_Options as a string
      ///
      /// This is primarily intended for debugging and error messages;
      /// the format is not fixed
      std::string to_string() const;

      /// Specify a KDF used to derive the shared key from the KEM output
      ///
      /// The salt and desired length passed to the encrypt/decrypt operations
      /// are inputs to this KDF.
      ///
      /// The name must not be empty; this cannot be combined with with_raw_shared_key
      PK_KEM_Options with_kdf(std::string_view kdf);

      /// Request the raw output of the KEM as the shared key
      ///
      /// If neither this nor with_kdf is used, KEMs whose output is already a
      /// uniformly random key (for example ML-KEM) return that output directly,
      /// while KEMs whose output is not (for example RSA-KEM or a key
      /// agreement used as a KEM) reject the request.
      ///
      /// This cannot be combined with with_kdf
      PK_KEM_Options with_raw_shared_key();

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_KEM_Options with_provider(std::string_view provider);

      /*
      * Getters; these are mostly for internal use
      *
      * Calling any of these records that the respective option was examined
      * by the scheme, so a scheme should only read an option it will act on.
      */

      const std::optional<std::string>& kdf() const {
         note_examined(Option::Kdf);
         return m_kdf;
      }

      bool using_kdf() const { return kdf().has_value(); }

      bool using_raw_shared_key() const {
         note_examined(Option::RawSharedKey);
         return m_raw_shared_key;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_provider;
      }

      bool using_provider() const;

   private:
      friend class PK_KEM_Encryptor;
      friend class PK_KEM_Decryptor;

      enum class Option : uint32_t /* NOLINT(*-enum-size) */ {
         Kdf = (1 << 0),
         RawSharedKey = (1 << 1),
         Provider = (1 << 2),
      };

      void note_examined(Option option) const { m_examined |= static_cast<uint32_t>(option); }

      uint32_t options_in_use() const;

      void reset_examined() const { m_examined = 0; }

      void throw_if_unexamined(std::string_view algo_name) const;

      std::optional<std::string> m_kdf;
      bool m_raw_shared_key = false;
      std::optional<std::string> m_provider;
      mutable uint32_t m_examined = 0;
};

/**
* Key agreement options
*
* The normal usage of this is in a builder style, eg
*
* PK_Key_Agreement_Options().with_kdf("HKDF(SHA-256)")
*
* As with PK_Signature_Options, every option that is set must be understood by
* the scheme in use; constructing the PK_Key_Agreement throws an exception
* otherwise.
*/
class BOTAN_PUBLIC_API(3, 14) PK_Key_Agreement_Options final {
   public:
      PK_Key_Agreement_Options() = default;

      PK_Key_Agreement_Options(PK_Key_Agreement_Options&& other) = default;
      PK_Key_Agreement_Options& operator=(PK_Key_Agreement_Options&& other) = default;

      PK_Key_Agreement_Options(const PK_Key_Agreement_Options&) = default;
      PK_Key_Agreement_Options& operator=(const PK_Key_Agreement_Options& other) = default;
      ~PK_Key_Agreement_Options();

      /// Format this PK_Key_Agreement_Options as a string
      ///
      /// This is primarily intended for debugging and error messages;
      /// the format is not fixed
      std::string to_string() const;

      /// Specify a KDF used to derive the shared key from the agreed value
      ///
      /// The salt and desired length passed to derive_key are inputs to
      /// this KDF.
      ///
      /// The name must not be empty; this cannot be combined with with_raw_shared_key
      PK_Key_Agreement_Options with_kdf(std::string_view kdf);

      /// Request the raw agreed value as the shared key
      ///
      /// The agreed value (for example the x coordinate of an elliptic curve
      /// point) is not a uniformly random key, so key agreement requires either
      /// a KDF or this explicit request; the default options are rejected.
      ///
      /// This cannot be combined with with_kdf
      PK_Key_Agreement_Options with_raw_shared_key();

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_Key_Agreement_Options with_provider(std::string_view provider);

      /*
      * Getters; these are mostly for internal use
      *
      * Calling any of these records that the respective option was examined
      * by the scheme, so a scheme should only read an option it will act on.
      */

      const std::optional<std::string>& kdf() const {
         note_examined(Option::Kdf);
         return m_kdf;
      }

      bool using_kdf() const { return kdf().has_value(); }

      bool using_raw_shared_key() const {
         note_examined(Option::RawSharedKey);
         return m_raw_shared_key;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_provider;
      }

      bool using_provider() const;

   private:
      friend class PK_Key_Agreement;

      enum class Option : uint32_t /* NOLINT(*-enum-size) */ {
         Kdf = (1 << 0),
         RawSharedKey = (1 << 1),
         Provider = (1 << 2),
      };

      void note_examined(Option option) const { m_examined |= static_cast<uint32_t>(option); }

      uint32_t options_in_use() const;

      void reset_examined() const { m_examined = 0; }

      void throw_if_unexamined(std::string_view algo_name) const;

      std::optional<std::string> m_kdf;
      bool m_raw_shared_key = false;
      std::optional<std::string> m_provider;
      mutable uint32_t m_examined = 0;
};

}  // namespace Botan

#endif
