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
#include <string_view>
#include <vector>

namespace Botan {

/**
* Signature generation/verification options
*/
class BOTAN_PUBLIC_API(3, 6) PK_Signature_Options {
   public:
      PK_Signature_Options(std::string_view hash_fn) : m_hash_fn(hash_fn) {}

      PK_Signature_Options() : PK_Signature_Options("") {}

      /// Specify a padding scheme
      ///
      /// This is mostly/only used for RSA
      ///
      /// If the scheme does not support a padding option, it will throw an
      /// exception when presented with such an option.
      PK_Signature_Options with_padding(std::string_view padding) const;

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
      PK_Signature_Options with_prehash(std::optional<std::string> prehash = std::nullopt) const;

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      PK_Signature_Options with_context(std::span<const uint8_t> context) const;

      /// Specify a context as a string
      ///
      /// Equivalent to the version taking a span above; just uses the bytes
      /// of the string instead.
      PK_Signature_Options with_context(std::string_view context) const;

      /// Request producing a deterministic signature
      ///
      /// Some signature schemes are always deterministic, or always randomized.
      /// Others support both randomized or deterministic options. This allows
      /// requesting this. For signatures which are always deterministic or
      /// always randomized, this option has no effect.
      ///
      /// This option is ignored for verification
      PK_Signature_Options with_deterministic_signature() const;

      /// Specify producing or expecting a DER encoded signature
      ///
      /// This is mostly used with ECDSA
      ///
      /// For schemes that do not support such formatting (such as RSA
      /// or post-quantum schemes), an exception will be thrown when the
      /// PK_Signer or PK_Verifier is created.
      PK_Signature_Options with_der_encoded_signature() const;

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_Signature_Options with_provider(std::string_view provider) const;

      const std::string& hash_function() const { return m_hash_fn; }

      const std::optional<std::string>& prehash_fn() const { return m_prehash; }

      const std::optional<std::string>& padding() const { return m_padding; }

      const std::optional<std::vector<uint8_t>>& context() const { return m_context; }

      const std::optional<std::string>& provider() const { return m_provider; }

      bool using_der_encoded_signature() const { return m_use_der; }

      bool using_deterministic_signature() const { return m_deterministic_sig; }

      bool using_context() const { return context().has_value(); }

      bool using_prehash() const { return m_use_prehash; }

      bool using_padding() const { return padding().has_value(); }

      bool using_provider() const { return provider().has_value() && provider().value() != "base"; }

      // Returns padding plus hash formatted for RSA
      std::string _padding_with_hash() const;

      /// This is a compatability interface that parses padding in the context
      /// of the key type, following internal logic used previously.
      ///
      /// This is an internal library function and should not be called by
      /// applications. It will be removed in Botan4.
      ///
      static PK_Signature_Options _parse(const Public_Key& key, std::string_view padding, Signature_Format format);

   private:
      std::string m_hash_fn;
      std::optional<std::string> m_prehash;
      std::optional<std::string> m_padding;
      std::optional<std::vector<uint8_t>> m_context;
      std::optional<std::string> m_provider;
      bool m_use_der = false;
      bool m_deterministic_sig = false;
      bool m_use_prehash = false;
};

}  // namespace Botan

#endif
