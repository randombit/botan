/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PK_OPTIONS_IMPL_H_
#define BOTAN_PK_OPTIONS_IMPL_H_

#include <botan/exceptn.h>
#include <botan/pk_options_readers.h>
#include <optional>
#include <string>
#include <string_view>

namespace Botan {

class Public_Key;

PK_Signature_Options parse_legacy_sig_options(const Public_Key& key, std::string_view params);

PK_Encryption_Options parse_legacy_enc_options(const Public_Key& key, std::string_view params);

PK_KEM_Options parse_legacy_kem_options(std::string_view params);

PK_Key_Agreement_Options parse_legacy_ka_options(std::string_view params);

/**
* Creates option readers for library code which builds its own options,
* for example when verifying an X.509 signature
*/
class PK_Options_Reader_Access final {
   public:
      static PK_Signature_Options_Reader for_signing(const PK_Signature_Options& options) {
         return PK_Signature_Options_Reader(options, PK_Signature_Options_Reader::Usage::Signing);
      }

      static PK_Signature_Options_Reader for_verification(const PK_Signature_Options& options) {
         return PK_Signature_Options_Reader(options, PK_Signature_Options_Reader::Usage::Verification);
      }

      static PK_Encryption_Options_Reader read(const PK_Encryption_Options& options) {
         return PK_Encryption_Options_Reader(options);
      }

      static PK_KEM_Options_Reader read(const PK_KEM_Options& options) { return PK_KEM_Options_Reader(options); }

      static PK_Key_Agreement_Options_Reader read(const PK_Key_Agreement_Options& options) {
         return PK_Key_Agreement_Options_Reader(options);
      }

      template <typename ReaderT>
      static void throw_if_unexamined(const ReaderT& reader, std::string_view algo_name) {
         reader.throw_if_unexamined(algo_name);
      }
};

/**
* For schemes where the hash function is fixed by the key (XMSS, SLH-DSA, ...)
*
* Accepts the hash option only if it names the hash the key already uses.
*/
void validate_for_hash_based_signature(const PK_Signature_Options_Reader& options,
                                       std::string_view algo_name,
                                       std::string_view hash_fn);

/**
* For schemes which can sign an externally computed prehash
*
* Returns the name of the hash function the caller used, if it was named
* (either in the prehash option or via with_hash; if both were given they
* must agree), or nullopt if the input is an unidentified digest.
*
* Must only be called if using_externally_computed_prehash() is true.
*/
std::optional<std::string> externally_computed_prehash_name(const PK_Signature_Options_Reader& options);

/**
* For keys implemented in software
*
* Such keys have only the "base" provider, so any other provider request is
* rejected. Reading the option here also acknowledges it.
*
* @throws Provider_Not_Found if a different provider was requested
*/
template <typename OptionsT>
void require_software_provider(const OptionsT& options, std::string_view algo_name) {
   if(options.using_provider()) {
      throw Provider_Not_Found(algo_name, options.provider().value());
   }
}

/**
* For keys held in hardware (PKCS #11, TPM)
*
* Such keys have exactly one implementation, so the provider option must be
* unset or name that provider. In particular "base", which names the software
* implementation, is not available for them.
*
* @throws Provider_Not_Found otherwise
*/
template <typename OptionsT>
void require_hardware_provider(const OptionsT& options, std::string_view algo_name, std::string_view provider_name) {
   const auto& provider = options.provider();
   if(provider.has_value() && *provider != provider_name) {
      throw Provider_Not_Found(algo_name, *provider);
   }
}

/**
* For schemes whose signatures are always deterministic
*
* Any request for a deterministic signature is trivially satisfied, so this
* just examines (and thereby acknowledges) the option.
*/
void acknowledge_always_deterministic(const PK_Signature_Options_Reader& options);

}  // namespace Botan

#endif
