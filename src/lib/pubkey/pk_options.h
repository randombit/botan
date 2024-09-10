/*
* (C) 2024 Jack Lloyd
*     2024 René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPTIONS_H_
#define BOTAN_PK_OPTIONS_H_

#include <botan/base_builder.h>
#include <botan/mem_ops.h>
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
class BOTAN_PUBLIC_API(3, 6) PK_Signature_Options : public Builder<PK_Signature_Options> {
   public:
      /// Create a PK_Signature_Options with no options set
      ///
      /// This can be further parameterized by calling with_xxx functions
      PK_Signature_Options() = default;

      /// Create a PK_Signature_Options specifying the hash to use
      ///
      /// Most but not all signature schemes require specifying the hash
      ///
      /// This can be further parameterized by calling with_xxx functions
      PK_Signature_Options(std::string_view hash_fn) { with_hash(hash_fn); }

      /// Parse the legacy set of parameters that used to be passed to
      /// PK_Signer/PK_Verifier. This should not be used by new code.
      ///
      /// @param algo the public key algorithm name
      /// @param params the legacy parameters string
      /// @param provider the provider to use
      PK_Signature_Options(std::string_view algo, std::string_view params, std::string_view provider);

      /// Specify the hash function to use for signing/verification
      ///
      /// Most, but not all, schemes require specifying a hash function.
      PK_Signature_Options& with_hash(std::string_view hash) & {
         set_or_throw(m_hash_fn, std::string(hash));
         return *this;
      }

      /// Specify the hash function to use for signing/verification
      ///
      /// Most, but not all, schemes require specifying a hash function.
      PK_Signature_Options with_hash(std::string_view hash) && { return std::move(with_hash(hash)); }

      /// Specify a padding scheme
      ///
      /// This is mostly/only used for RSA
      ///
      /// If the scheme does not support a padding option, it will throw an
      /// exception when presented with such an option.
      PK_Signature_Options& with_padding(std::string_view padding) & {
         set_or_throw(m_padding, std::string(padding));
         return *this;
      }

      /// Specify a padding scheme
      ///
      /// This is mostly/only used for RSA
      ///
      /// If the scheme does not support a padding option, it will throw an
      /// exception when presented with such an option.
      PK_Signature_Options with_padding(std::string_view padding) && { return std::move(with_padding(padding)); }

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
      PK_Signature_Options& with_prehash(std::optional<std::string> prehash = std::nullopt) & {
         set_or_throw(m_prehash, std::move(prehash));
         return *this;
      }

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
      PK_Signature_Options with_prehash(std::optional<std::string> prehash = std::nullopt) && {
         return std::move(with_prehash(std::move(prehash)));
      }

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      PK_Signature_Options& with_context(std::span<const uint8_t> context) & {
         set_or_throw(m_context, std::vector<uint8_t>(context.begin(), context.end()));
         return *this;
      }

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      PK_Signature_Options with_context(std::span<const uint8_t> context) && {
         return std::move(with_context(context));
      }

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      PK_Signature_Options& with_context(std::string_view context) & {
         with_context(std::span{cast_char_ptr_to_uint8(context.data()), context.size()});
         return *this;
      }

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      PK_Signature_Options with_context(std::string_view context) && { return std::move(with_context(context)); }

      /// Specify the size of salt to be used
      ///
      /// A small number of padding schemes (most importantly RSA-PSS) use a randomized
      /// salt. This allows controlling the size of the salt that is used.
      PK_Signature_Options& with_salt_size(size_t salt_size) & {
         set_or_throw(m_salt_size, salt_size);
         return *this;
      }

      /// Specify the size of salt to be used
      ///
      /// A small number of padding schemes (most importantly RSA-PSS) use a randomized
      /// salt. This allows controlling the size of the salt that is used.
      PK_Signature_Options with_salt_size(size_t salt_size) && { return std::move(with_salt_size(salt_size)); }

      /// Request producing a deterministic signature
      ///
      /// Some signature schemes are always deterministic, or always randomized.
      /// Others support both randomized or deterministic options. This allows
      /// requesting this. For signatures which are always deterministic or
      /// always randomized, this option has no effect.
      ///
      /// This option is ignored for verification
      PK_Signature_Options& with_deterministic_signature(bool value = true) & {
         set_or_throw(m_deterministic_sig, value);
         return *this;
      }

      /// Request producing a deterministic signature
      ///
      /// Some signature schemes are always deterministic, or always randomized.
      /// Others support both randomized or deterministic options. This allows
      /// requesting this. For signatures which are always deterministic or
      /// always randomized, this option has no effect.
      ///
      /// This option is ignored for verification
      PK_Signature_Options with_deterministic_signature(bool value = true) && {
         return std::move(with_deterministic_signature(value));
      }

      /// Specify producing or expecting a DER encoded signature
      ///
      /// This is mostly used with ECDSA
      ///
      /// For schemes that do not support such formatting (such as RSA
      /// or post-quantum schemes), an exception will be thrown when the
      /// PK_Signer or PK_Verifier is created.
      PK_Signature_Options& with_der_encoded_signature(bool der = true) & {
         set_or_throw(m_use_der, der);
         return *this;
      }

      /// Specify producing or expecting a DER encoded signature
      ///
      /// This is mostly used with ECDSA
      ///
      /// For schemes that do not support such formatting (such as RSA
      /// or post-quantum schemes), an exception will be thrown when the
      /// PK_Signer or PK_Verifier is created.
      PK_Signature_Options with_der_encoded_signature(bool der = true) && {
         return std::move(with_der_encoded_signature(der));
      }

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
      PK_Signature_Options& with_explicit_trailer_field(bool value = true) & {
         set_or_throw(m_explicit_trailer_field, value);
         return *this;
      }

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
      PK_Signature_Options with_explicit_trailer_field(bool value = true) && {
         return std::move(with_explicit_trailer_field(value));
      }

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_Signature_Options& with_provider(std::string_view provider) & {
         set_or_throw(m_provider, std::string(provider));
         return *this;
      }

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      PK_Signature_Options with_provider(std::string_view provider) && { return std::move(with_provider(provider)); }

      /// Return the name of the hash function to use
      ///
      /// This will throw an exception if no hash function was configured
      // std::string hash_function_name() const;

      // Getters; these are mostly for internal use

      [[nodiscard]] std::string hash_function() { return require(m_hash_fn); }

      [[nodiscard]] std::optional<std::string> maybe_hash_function() { return take(m_hash_fn); }

      /// It may be acceptable to provide a hash function, for hash-based
      /// signatures (like SLH-DSA or LMS), but it is not required.
      /// @throws Invalid_Argument if the provided hash is not acceptable
      void validate_for_hash_based_signature_algorithm(std::string_view algo_name,
                                                       std::optional<std::string_view> acceptable_hash = std::nullopt);

      [[nodiscard]] std::pair<bool, std::optional<std::string>> prehash() {
         if(auto prehash = take(m_prehash)) {
            return {true, std::move(prehash.value())};
         } else {
            return {false, std::nullopt};
         }
      }

      [[nodiscard]] std::optional<std::string> padding() { return take(m_padding); }

      [[nodiscard]] std::optional<std::vector<uint8_t>> context() { return take(m_context); }

      [[nodiscard]] std::optional<std::string> provider() { return take(m_provider); }

      /// This is a convenience helper for algorithms that do not support
      /// specifying a provider.
      /// @throws Provider_Not_Found if a provider is set
      void exclude_provider_for_algorithm(std::string_view algo_name) {
         if(auto p = provider()) {
            throw Provider_Not_Found(algo_name, p.value());
         };
      }

      [[nodiscard]] std::optional<size_t> salt_size() { return take(m_salt_size); }

      [[nodiscard]] bool using_der_encoded_signature() { return take(m_use_der).value_or(false); }

      [[nodiscard]] bool using_deterministic_signature() { return take(m_deterministic_sig).value_or(false); }

      [[nodiscard]] bool using_explicit_trailer_field() { return take(m_explicit_trailer_field).value_or(false); }

   private:
      friend class Builder<PK_Signature_Options>;

      auto all_options() const {
         return std::tie(m_hash_fn,
                         m_prehash,
                         m_padding,
                         m_context,
                         m_provider,
                         m_salt_size,
                         m_use_der,
                         m_deterministic_sig,
                         m_explicit_trailer_field);
      }

   private:
      detail::Option<"hash", std::string> m_hash_fn;
      detail::Option<"prehash", std::optional<std::string>> m_prehash;
      detail::Option<"padding", std::string> m_padding;
      detail::Option<"context", std::vector<uint8_t>> m_context;
      detail::Option<"provider", std::string> m_provider;
      detail::Option<"salt size", size_t> m_salt_size;
      detail::Option<"use DER", bool> m_use_der;
      detail::Option<"deterministic", bool> m_deterministic_sig;
      detail::Option<"explicit trailer field", bool> m_explicit_trailer_field;
};

}  // namespace Botan

#endif
