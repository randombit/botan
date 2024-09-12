/*
* (C) 2024 Jack Lloyd
*     2024 René Meusel - Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPTIONS_H_
#define BOTAN_PK_OPTIONS_H_

#include <botan/mem_ops.h>
#include <botan/options_builder.h>
#include <botan/pubkey.h>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class Public_Key;
class Private_Key;

namespace detail {

struct PK_Signature_Options_Container final {
      // NOLINTBEGIN(misc-non-private-member-variables-in-classes)

      Option<"public key", std::reference_wrapper<const Public_Key>> public_key;
      Option<"private key", std::reference_wrapper<const Private_Key>> private_key;
      Option<"random number generator", std::reference_wrapper<RandomNumberGenerator>> rng;
      Option<"hash", std::string> hash_fn;
      Option<"prehash", std::optional<std::string>> prehash;
      Option<"padding", std::string> padding;
      Option<"context", std::vector<uint8_t>> context;
      Option<"provider", std::string> provider;
      Option<"salt size", size_t> salt_size;
      Option<"use DER", bool> use_der;
      Option<"deterministic", bool> deterministic_sig;
      Option<"explicit trailer field", bool> explicit_trailer_field;

      // NOLINTEND(misc-non-private-member-variables-in-classes)

      auto all_options() const {
         return std::tie(public_key,
                         private_key,
                         rng,
                         hash_fn,
                         prehash,
                         padding,
                         context,
                         provider,
                         salt_size,
                         use_der,
                         deterministic_sig,
                         explicit_trailer_field);
      }
};

}  // namespace detail

class BOTAN_UNSTABLE_API PK_Signature_Options final : public Options<detail::PK_Signature_Options_Container> {
   public:
      using Options::Options;

   public:
      [[nodiscard]] auto public_key() { return take(options().public_key); }

      [[nodiscard]] auto private_key() { return take(options().private_key); }

      [[nodiscard]] auto rng() { return take(options().rng); }

      [[nodiscard]] auto hash_function() { return take(options().hash_fn); }

      [[nodiscard]] auto prehash() { return take(options().prehash); }

      [[nodiscard]] auto padding() { return take(options().padding); }

      [[nodiscard]] auto context() { return take(options().context); }

      [[nodiscard]] auto provider() { return take(options().provider); }

      [[nodiscard]] auto salt_size() { return take(options().salt_size); }

      [[nodiscard]] bool using_der_encoded_signature() { return take(options().use_der).or_default(false); }

      [[nodiscard]] bool using_deterministic_signature() { return take(options().deterministic_sig).or_default(false); }

      [[nodiscard]] bool using_explicit_trailer_field() {
         return take(options().explicit_trailer_field).or_default(false);
      }

   public:
      /// It may be acceptable to provide a hash function, for hash-based
      /// signatures (like SLH-DSA or LMS), but it is not required.
      /// @throws Invalid_Argument if the provided hash is not acceptable
      void validate_for_hash_based_signature_algorithm(std::string_view algo_name,
                                                       std::optional<std::string_view> acceptable_hash = std::nullopt);

      /// This is a convenience helper for algorithms that do not support
      /// specifying a provider.
      /// @throws Provider_Not_Found if a provider is set
      void exclude_provider_for_algorithm(std::string_view algo_name) {
         if(auto p = provider().optional()) {
            throw Provider_Not_Found(algo_name, p.value());
         };
      }

   public:
      /// Parse the legacy set of parameters that used to be passed to
      /// PK_Signer. This should not be used by new code.
      ///
      /// @param key the private key to use
      /// @param rng the rng to use
      /// @param params the legacy parameters string
      /// @param format the encoding format to use
      /// @param provider the provider to use
      static PK_Signature_Options from_legacy(const Private_Key& key,
                                              RandomNumberGenerator& rng,
                                              std::string_view params,
                                              Signature_Format format,
                                              std::string_view provider);

      /// Parse the legacy set of parameters that used to be passed to
      /// PK_Verifier. This should not be used by new code.
      ///
      /// @param key the private key to use
      /// @param params the legacy parameters string
      /// @param format the encoding format to use
      /// @param provider the provider to use
      static PK_Signature_Options from_legacy(const Public_Key& key,
                                              std::string_view params,
                                              Signature_Format format,
                                              std::string_view provider);
};

/**
* Signature generation/verification options
*
* The normal usage of this is in a builder style, eg.
*
* auto signer = private_key.signer()
*                          .with_hash("SHA-256")
*                          .with_der_encoded_signature()
*                          .with_context("Foo")
*                          .create();
*
* This is a base class for the common options of 'signing' and 'verification'.
* We use CRTP to track the derived class type, so that the with_xxx functions
* can be chained and return the correct derived type.
*
* To properly handle method chaining even when the builder was transformed into
* an lvalue, we have to provide two overloads for each with_xxx function. The
* first overload is for lvalues and the second overload is for rvalues.
* Typically, the rvalue overload is implemented in terms of the lvalue overload.
*
* TODO: C++23: deducing-this will likely remove the need for CRTP and the
*              lvalue/rvalue overloads. It allows the base class to know the
*              derived type on which its methods were called. Along with the
*              type, each method can also know whether it was called on an
*              lvalue or rvalue and handle the return type accordingly.
*/
template <typename DerivedT>
class PK_Signature_Options_Builder_Base : public OptionsBuilder<PK_Signature_Options> {
   private:
      using Self = DerivedT;

      DerivedT& self() { return static_cast<DerivedT&>(*this); }

   protected:
      PK_Signature_Options_Builder_Base() = default;

   public:
      /// Specify the hash function to use for signing/verification
      ///
      /// Most, but not all, schemes require specifying a hash function.
      Self& with_hash(std::string_view hash) & {
         set_or_throw(options().hash_fn, std::string(hash));
         return self();
      }

      /// Specify the hash function to use for signing/verification
      ///
      /// Most, but not all, schemes require specifying a hash function.
      Self with_hash(std::string_view hash) && { return std::move(with_hash(hash)); }

      /// Specify a padding scheme
      ///
      /// This is mostly/only used for RSA
      ///
      /// If the scheme does not support a padding option, it will throw an
      /// exception when presented with such an option.
      Self& with_padding(std::string_view padding) & {
         set_or_throw(options().padding, std::string(padding));
         return self();
      }

      /// Specify a padding scheme
      ///
      /// This is mostly/only used for RSA
      ///
      /// If the scheme does not support a padding option, it will throw an
      /// exception when presented with such an option.
      Self with_padding(std::string_view padding) && { return std::move(with_padding(padding)); }

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
      Self& with_prehash(std::optional<std::string> prehash = std::nullopt) & {
         set_or_throw(options().prehash, std::move(prehash));
         return self();
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
      Self with_prehash(std::optional<std::string> prehash = std::nullopt) && {
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
      Self& with_context(std::span<const uint8_t> context) & {
         set_or_throw(options().context, std::vector<uint8_t>(context.begin(), context.end()));
         return self();
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
      Self with_context(std::span<const uint8_t> context) && { return std::move(with_context(context)); }

      /// Specify a context
      ///
      /// Some signature schemes allow specifying a context with the signature.
      /// This is typically a fixed string that identifies a protocol or peer.
      ///
      /// For SM2 this context is the user identifier
      ///
      /// If the scheme does not support contextual identifiers, then an exception
      /// will be thrown.
      Self& with_context(std::string_view context) & {
         with_context(std::span{cast_char_ptr_to_uint8(context.data()), context.size()});
         return self();
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
      Self with_context(std::string_view context) && { return std::move(with_context(context)); }

      /// Specify the size of salt to be used
      ///
      /// A small number of padding schemes (most importantly RSA-PSS) use a randomized
      /// salt. This allows controlling the size of the salt that is used.
      Self& with_salt_size(size_t salt_size) & {
         set_or_throw(options().salt_size, salt_size);
         return self();
      }

      /// Specify the size of salt to be used
      ///
      /// A small number of padding schemes (most importantly RSA-PSS) use a randomized
      /// salt. This allows controlling the size of the salt that is used.
      Self with_salt_size(size_t salt_size) && { return std::move(with_salt_size(salt_size)); }

      /// Specify producing or expecting a DER encoded signature
      ///
      /// This is mostly used with ECDSA
      ///
      /// For schemes that do not support such formatting (such as RSA
      /// or post-quantum schemes), an exception will be thrown when the
      /// PK_Signer or PK_Verifier is created.
      Self& with_der_encoded_signature(bool der = true) & {
         set_or_throw(options().use_der, der);
         return self();
      }

      /// Specify producing or expecting a DER encoded signature
      ///
      /// This is mostly used with ECDSA
      ///
      /// For schemes that do not support such formatting (such as RSA
      /// or post-quantum schemes), an exception will be thrown when the
      /// PK_Signer or PK_Verifier is created.
      Self with_der_encoded_signature(bool der = true) && { return std::move(with_der_encoded_signature(der)); }

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
      Self& with_explicit_trailer_field(bool value = true) & {
         set_or_throw(options().explicit_trailer_field, value);
         return self();
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
      Self with_explicit_trailer_field(bool value = true) && { return std::move(with_explicit_trailer_field(value)); }

      /// Specify a provider that should be used
      ///
      /// The default provider used to be referred to as "base". There's no
      /// need to specify the default provider explicitly and setting a
      /// provider is rarely relevant in general.
      Self& with_provider(std::string_view provider) & {
         if(!provider.empty() && provider != "base") {
            set_or_throw(options().provider, std::string(provider));
         }
         return self();
      }

      /// Specify a provider that should be used
      ///
      /// This is rarely relevant
      Self with_provider(std::string_view provider) && { return std::move(with_provider(provider)); }
};

class BOTAN_PUBLIC_API(3, 6) PK_Signature_Options_Builder final
      : public PK_Signature_Options_Builder_Base<PK_Signature_Options_Builder> {
   public:
      using Self = PK_Signature_Options_Builder;

   public:
      /// Create a PK_Signature_Options_Builder with no options set
      ///
      /// This can be further parameterized by calling with_xxx functions
      PK_Signature_Options_Builder() = default;

      /// Specify the private key to use for verification
      Self& with_private_key(const Private_Key& key) &;

      /// Specify the private key to use for verification
      Self with_private_key(const Private_Key& key) && { return std::move(with_private_key(key)); }

      /// Specify the random number generator to use
      ///
      /// If the signature scheme requires randomness, this RNG will be used.
      /// Some schemes have a deterministic and a randomized mode, an RNG does
      /// not need to be provided in the deterministic case.
      Self& with_rng(RandomNumberGenerator& rng) & {
         set_or_throw(options().rng, rng);
         return *this;
      }

      /// Specify the random number generator to use
      ///
      /// If the signature scheme requires randomness, this RNG will be used.
      /// Some schemes have a deterministic and a randomized mode, an RNG does
      /// not need to be provided in the deterministic case.
      Self with_rng(RandomNumberGenerator& rng) && { return std::move(with_rng(rng)); }

      /// Request producing a deterministic signature
      ///
      /// Some signature schemes are always deterministic, or always randomized.
      /// Others support both randomized or deterministic options. This allows
      /// requesting this. For signatures which are always deterministic or
      /// always randomized, this option has no effect.
      ///
      /// This option is ignored for verification
      Self& with_deterministic_signature(bool value = true) & {
         set_or_throw(options().deterministic_sig, value);
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
      Self with_deterministic_signature(bool value = true) && { return std::move(with_deterministic_signature(value)); }

      /// Commit the options and create a PK_Signer object
      PK_Signer create() { return PK_Signer(commit()); }
};

class BOTAN_PUBLIC_API(3, 6) PK_Verification_Options_Builder final
      : public PK_Signature_Options_Builder_Base<PK_Verification_Options_Builder> {
   public:
      using Self = PK_Verification_Options_Builder;

   public:
      /// Create a PK_Verification_Options_Builder with no options set
      ///
      /// This can be further parameterized by calling with_xxx functions
      PK_Verification_Options_Builder() = default;

      /// Specify the public key to use for verification
      Self& with_public_key(const Public_Key& key) &;

      /// Specify the public key to use for verification
      Self with_public_key(const Public_Key& key) && { return std::move(with_public_key(key)); }

      /// Commit the options and create a PK_Verifier object
      PK_Verifier create() { return PK_Verifier(commit()); }
};

}  // namespace Botan

#endif
