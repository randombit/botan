/*
* (C) 2024 Jack Lloyd
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

/**
* Signature generation/verification options
*
* The normal usage of this is in a builder style, eg
*
* PK_Signature_Options()
*   .with_hash("SHA-256")
*   .with_der_encoded_signature()
*   .with_context("Foo")
*/
class BOTAN_PUBLIC_API(3, 6) PK_Signature_Options {
   public:
      /// Create an empty PK_Signature_Options
      ///
      /// This can be further parameterized by calling with_xxx functions
      PK_Signature_Options() = default;

      PK_Signature_Options(PK_Signature_Options&& other) = default;
      PK_Signature_Options(const PK_Signature_Options&) = delete;
      PK_Signature_Options& operator=(const PK_Signature_Options& other) = delete;
      PK_Signature_Options& operator=(PK_Signature_Options&& other) = delete;
      ~PK_Signature_Options();

      /// Format this PK_Signature_Options as a string
      ///
      /// This is primarily intended for debugging and error messages;
      /// the format is not fixed
      std::string to_string() const;

      /// Create a PK_Signature_Options specifying the hash to use
      ///
      /// Most but not all signture schemes require specifying the hash
      ///
      /// This can be further parameterized by calling with_xxx functions
      PK_Signature_Options(std::string_view hash_fn) : m_hash_fn(hash_fn) {}

      /// Specify the hash function to use for signing/verification
      ///
      /// Most, but not all, schemes require specifying a hash function.
      PK_Signature_Options with_hash(std::string_view hash) &&;

      /// Specify a padding scheme
      ///
      /// This is mostly/only used for RSA
      ///
      /// If the scheme does not support a padding option, it will throw an
      /// exception when presented with such an option.
      PK_Signature_Options with_padding(std::string_view padding) &&;

      /// Specify the signature is prehashed
      ///
      /// Some signature schemes, such as Ed25519, normally sign the
      /// entire message along with some context data. However such
      /// schemes also sometimes offer a prehashing variant where the
      /// message is hashed on its own, then the hash is signed.
      ///
      /// If given this specifies what hash function to use for prehashing.
      /// If prehash is nullopt, this requests prehashing using an algorithm
      /// specific default function
      ///
      /// If the scheme does not support prehashing, it will throw an
      /// exception when presented with such an option.
      PK_Signature_Options with_prehash(std::optional<std::string> prehash = std::nullopt) &&;

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      PK_Signature_Options with_context(std::span<const uint8_t> context) &&;

      /// Specify a context as a string
      ///
      /// Equivalent to the version taking a span above; just uses the bytes
      /// of the string instead.
      PK_Signature_Options with_context(std::string_view context) &&;

      /// Specify the size of salt to be used
      ///
      /// A small number of padding schemes (most importantly RSA-PSS) use a randomized
      /// salt. This allows controlling the size of the salt that is used.
      PK_Signature_Options with_salt_size(size_t salt_size) &&;

      /// Request producing a deterministic signature
      ///
      /// Some signature schemes are always deterministic, or always randomized.
      /// Others support both randomized or deterministic options. This allows
      /// requesting this. For signatures which are always deterministic or
      /// always randomized, this option has no effect.
      ///
      /// This option is ignored for verification
      PK_Signature_Options with_deterministic_signature() &&;

      /// Specify producing or expecting a DER encoded signature
      ///
      /// This is mostly used with ECDSA
      ///
      /// For schemes that do not support such formatting (such as RSA
      /// or post-quantum schemes), an exception will be thrown when the
      /// PK_Signer or PK_Verifier is created.
      PK_Signature_Options with_der_encoded_signature() &&;

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
      PK_Signature_Options with_explicit_trailer_field() &&;

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_Signature_Options with_provider(std::string_view provider) &&;

      /// Return the name of the hash function to use
      ///
      /// This will throw an exception if no hash function was configured
      std::string hash_function_name() const;

      // Getters; these are mostly for internal use

      const std::optional<std::string>& hash_function() const { return m_hash_fn; }

      const std::optional<std::string>& prehash_fn() const { return m_prehash; }

      const std::optional<std::string>& padding() const { return m_padding; }

      const std::optional<std::vector<uint8_t>>& context() const { return m_context; }

      const std::optional<std::string>& provider() const { return m_provider; }

      const std::optional<size_t>& salt_size() const { return m_salt_size; }

      bool using_der_encoded_signature() const { return m_use_der; }

      bool using_deterministic_signature() const { return m_deterministic_sig; }

      bool using_explicit_trailer_field() const { return m_explicit_trailer_field; }

      bool using_hash() const { return hash_function().has_value(); }

      bool using_context() const { return context().has_value(); }

      bool using_prehash() const { return m_using_prehash; }

      bool using_padding() const { return padding().has_value(); }

      bool using_salt_size() const { return salt_size().has_value(); }

      bool using_provider() const { return provider().has_value() && provider().value() != "base"; }

   private:
      std::optional<std::string> m_hash_fn;
      std::optional<std::string> m_prehash;
      std::optional<std::string> m_padding;
      std::optional<std::vector<uint8_t>> m_context;
      std::optional<std::string> m_provider;
      std::optional<size_t> m_salt_size;
      bool m_using_prehash = false;
      bool m_use_der = false;
      bool m_deterministic_sig = false;
      bool m_explicit_trailer_field = false;
};

}  // namespace Botan

#endif
