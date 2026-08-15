/*
* (C) 2024,2025,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPTIONS_READERS_H_
#define BOTAN_PK_OPTIONS_READERS_H_

#include <botan/pk_options.h>

/**
* Read access to the public key operation options
*
* Applications never interact with the types in this header; they build a
* PK_Signature_Options (or the encryption, KEM, or key agreement equivalent)
* and hand it to the wrapper in pubkey.h. The library then creates a reader
* object and passes it to the key's _create_xxx_op, so these types are only
* relevant for out-of-tree implementations of public key schemes.
*
* These types are unstable API and may change between releases.
*/

namespace Botan {

/**
* Read access to a PK_Signature_Options
*
* The library creates one of these when a PK_Signer or PK_Verifier is
* constructed and passes it to the key's _create_signature_op or
* _create_verification_op; applications never create or hold one.
*
* Each getter records that the scheme examined the option. Any option the
* caller set which the scheme never examined is then rejected, since it would
* otherwise be silently ignored. A scheme should therefore only read an option
* that it will actually act on.
*/
class BOTAN_UNSTABLE_API PK_Signature_Options_Reader final {
   public:
      PK_Signature_Options_Reader(const PK_Signature_Options_Reader&) = delete;
      PK_Signature_Options_Reader(PK_Signature_Options_Reader&&) = delete;
      PK_Signature_Options_Reader& operator=(const PK_Signature_Options_Reader&) = delete;
      PK_Signature_Options_Reader& operator=(PK_Signature_Options_Reader&&) = delete;
      ~PK_Signature_Options_Reader() = default;

      /// Format the options as a string, for error messages
      std::string to_string() const { return m_options.to_string(); }

      /// Return the name of the hash function to use
      ///
      /// This will throw an exception if no hash function was configured
      const std::string& hash_function_name() const;

      const std::optional<std::string>& hash_function() const {
         note_examined(Option::Hash);
         return m_options.m_hash_fn;
      }

      const std::optional<std::string>& prehash_function() const {
         note_examined(Option::Prehash);
         return m_options.m_prehash;
      }

      const std::optional<std::string>& externally_computed_prehash_function() const {
         note_examined(Option::ExternalPrehash);
         return m_options.m_external_prehash;
      }

      const std::optional<std::string>& padding() const {
         note_examined(Option::Padding);
         return m_options.m_padding;
      }

      const std::optional<std::vector<uint8_t>>& context() const {
         note_examined(Option::Context);
         return m_options.m_context;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_options.m_provider;
      }

      const std::optional<size_t>& salt_size() const {
         note_examined(Option::SaltSize);
         return m_options.m_salt_size;
      }

      bool using_der_encoded_signature() const {
         note_examined(Option::DerEncoded);
         return m_options.m_use_der;
      }

      bool using_deterministic_signature() const {
         note_examined(Option::Deterministic);
         return m_options.m_deterministic_sig && m_usage == Usage::Signing;
      }

      bool using_explicit_trailer_field() const {
         note_examined(Option::ExplicitTrailer);
         return m_options.m_explicit_trailer_field;
      }

      bool using_hash() const { return hash_function().has_value(); }

      bool using_context() const { return context().has_value(); }

      bool using_prehash() const {
         note_examined(Option::Prehash);
         return m_options.m_using_prehash;
      }

      bool using_externally_computed_prehash() const {
         note_examined(Option::ExternalPrehash);
         return m_options.m_using_external_prehash;
      }

      bool using_padding() const { return padding().has_value(); }

      bool using_salt_size() const { return salt_size().has_value(); }

      bool using_provider() const;

   private:
      friend class PK_Signer;
      friend class PK_Verifier;
      friend class PK_Options_Reader_Access;

      /*
      * The deterministic option only affects signature generation, so a reader
      * for verification hides it rather than have every verification operation
      * know to ignore it
      */
      enum class Usage : uint8_t {
         Signing,
         Verification,
      };

      PK_Signature_Options_Reader(const PK_Signature_Options& options, Usage usage) :
            m_options(options), m_usage(usage) {}

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

      /// Throw Invalid_Argument if any option in use has not been examined
      void throw_if_unexamined(std::string_view algo_name) const;

      const PK_Signature_Options& m_options;
      Usage m_usage;
      mutable uint32_t m_examined = 0;
};

/**
* Read access to a PK_Encryption_Options
*
* The library creates one of these when a PK_Encryptor_EME or PK_Decryptor_EME
* is constructed and passes it to the key's _create_encryption_op or
* _create_decryption_op; applications never create or hold one.
*
* As with PK_Signature_Options_Reader, each getter records that the scheme
* examined the option, and any option set but never examined is rejected.
*/
class BOTAN_UNSTABLE_API PK_Encryption_Options_Reader final {
   public:
      PK_Encryption_Options_Reader(const PK_Encryption_Options_Reader&) = delete;
      PK_Encryption_Options_Reader(PK_Encryption_Options_Reader&&) = delete;
      PK_Encryption_Options_Reader& operator=(const PK_Encryption_Options_Reader&) = delete;
      PK_Encryption_Options_Reader& operator=(PK_Encryption_Options_Reader&&) = delete;
      ~PK_Encryption_Options_Reader() = default;

      /// Format the options as a string, for error messages
      std::string to_string() const { return m_options.to_string(); }

      /// Return the name of the hash function to use
      ///
      /// This will throw an exception if no hash function was configured
      const std::string& hash_function_name() const;

      const std::optional<std::string>& padding() const {
         note_examined(Option::Padding);
         return m_options.m_padding;
      }

      const std::optional<std::string>& hash_function() const {
         note_examined(Option::Hash);
         return m_options.m_hash_fn;
      }

      const std::optional<std::string>& mgf1_hash_function() const {
         note_examined(Option::Mgf1Hash);
         return m_options.m_mgf1_hash_fn;
      }

      const std::optional<std::vector<uint8_t>>& context() const {
         note_examined(Option::Context);
         return m_options.m_context;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_options.m_provider;
      }

      bool using_padding() const { return padding().has_value(); }

      bool using_hash() const { return hash_function().has_value(); }

      bool using_mgf1_hash() const { return mgf1_hash_function().has_value(); }

      bool using_context() const { return context().has_value(); }

      bool using_provider() const;

   private:
      friend class PK_Encryptor_EME;
      friend class PK_Decryptor_EME;
      friend class PK_Options_Reader_Access;

      explicit PK_Encryption_Options_Reader(const PK_Encryption_Options& options) : m_options(options) {}

      enum class Option : uint32_t /* NOLINT(*-enum-size) */ {
         Padding = (1 << 0),
         Hash = (1 << 1),
         Mgf1Hash = (1 << 2),
         Context = (1 << 3),
         Provider = (1 << 4),
      };

      void note_examined(Option option) const { m_examined |= static_cast<uint32_t>(option); }

      uint32_t options_in_use() const;

      void throw_if_unexamined(std::string_view algo_name) const;

      const PK_Encryption_Options& m_options;
      mutable uint32_t m_examined = 0;
};

/**
* Read access to a PK_KEM_Options
*
* The library creates one of these when a PK_KEM_Encryptor or PK_KEM_Decryptor
* is constructed and passes it to the key's _create_kem_encryption_op or
* _create_kem_decryption_op; applications never create or hold one.
*
* As with PK_Signature_Options_Reader, each getter records that the scheme
* examined the option, and any option set but never examined is rejected.
*/
class BOTAN_UNSTABLE_API PK_KEM_Options_Reader final {
   public:
      PK_KEM_Options_Reader(const PK_KEM_Options_Reader&) = delete;
      PK_KEM_Options_Reader(PK_KEM_Options_Reader&&) = delete;
      PK_KEM_Options_Reader& operator=(const PK_KEM_Options_Reader&) = delete;
      PK_KEM_Options_Reader& operator=(PK_KEM_Options_Reader&&) = delete;
      ~PK_KEM_Options_Reader() = default;

      /// Format the options as a string, for error messages
      std::string to_string() const { return m_options.to_string(); }

      const std::optional<std::string>& kdf() const {
         note_examined(Option::Kdf);
         return m_options.m_kdf;
      }

      bool using_kdf() const { return kdf().has_value(); }

      bool using_raw_shared_key() const {
         note_examined(Option::RawSharedKey);
         return m_options.m_raw_shared_key;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_options.m_provider;
      }

      bool using_provider() const;

   private:
      friend class PK_KEM_Encryptor;
      friend class PK_KEM_Decryptor;
      friend class PK_Options_Reader_Access;

      explicit PK_KEM_Options_Reader(const PK_KEM_Options& options) : m_options(options) {}

      enum class Option : uint32_t /* NOLINT(*-enum-size) */ {
         Kdf = (1 << 0),
         RawSharedKey = (1 << 1),
         Provider = (1 << 2),
      };

      void note_examined(Option option) const { m_examined |= static_cast<uint32_t>(option); }

      uint32_t options_in_use() const;

      void throw_if_unexamined(std::string_view algo_name) const;

      const PK_KEM_Options& m_options;
      mutable uint32_t m_examined = 0;
};

/**
* Read access to a PK_Key_Agreement_Options
*
* The library creates one of these when a PK_Key_Agreement is constructed and
* passes it to the key's _create_key_agreement_op; applications never create
* or hold one.
*
* As with PK_Signature_Options_Reader, each getter records that the scheme
* examined the option, and any option set but never examined is rejected.
*/
class BOTAN_UNSTABLE_API PK_Key_Agreement_Options_Reader final {
   public:
      PK_Key_Agreement_Options_Reader(const PK_Key_Agreement_Options_Reader&) = delete;
      PK_Key_Agreement_Options_Reader(PK_Key_Agreement_Options_Reader&&) = delete;
      PK_Key_Agreement_Options_Reader& operator=(const PK_Key_Agreement_Options_Reader&) = delete;
      PK_Key_Agreement_Options_Reader& operator=(PK_Key_Agreement_Options_Reader&&) = delete;
      ~PK_Key_Agreement_Options_Reader() = default;

      /// Format the options as a string, for error messages
      std::string to_string() const { return m_options.to_string(); }

      const std::optional<std::string>& kdf() const {
         note_examined(Option::Kdf);
         return m_options.m_kdf;
      }

      bool using_kdf() const { return kdf().has_value(); }

      bool using_raw_shared_key() const {
         note_examined(Option::RawSharedKey);
         return m_options.m_raw_shared_key;
      }

      const std::optional<std::string>& provider() const {
         note_examined(Option::Provider);
         return m_options.m_provider;
      }

      bool using_provider() const;

   private:
      friend class PK_Key_Agreement;
      friend class PK_Options_Reader_Access;

      explicit PK_Key_Agreement_Options_Reader(const PK_Key_Agreement_Options& options) : m_options(options) {}

      enum class Option : uint32_t /* NOLINT(*-enum-size) */ {
         Kdf = (1 << 0),
         RawSharedKey = (1 << 1),
         Provider = (1 << 2),
      };

      void note_examined(Option option) const { m_examined |= static_cast<uint32_t>(option); }

      uint32_t options_in_use() const;

      void throw_if_unexamined(std::string_view algo_name) const;

      const PK_Key_Agreement_Options& m_options;
      mutable uint32_t m_examined = 0;
};

}  // namespace Botan

#endif
