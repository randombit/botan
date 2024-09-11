/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_options.h>

#include <botan/pk_keys.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

namespace Botan {

namespace {

template <typename SigOptsBaseT>
void retrofit_legacy_parameters(SigOptsBaseT& builder,
                                const Public_Key& key,
                                std::string_view params,
                                Signature_Format format,
                                std::string_view provider) {
   /*
   * This is a convoluted mess because we must handle dispatch for every algorithm
   * specific detail of how padding strings were formatted in versions prior to 3.6.
   *
   * This will all go away once the deprecated constructors of PK_Signer and PK_Verifier
   * are removed in Botan4.
   */

   const auto algo = key.algo_name();

   if(key.message_parts() != 1) {
      builder.with_der_encoded_signature(format == Signature_Format::DerSequence);
   }

   if(!provider.empty() && provider != "base") {
      builder.with_provider(provider);
   }

   if(algo.starts_with("Dilithium") || algo == "SPHINCS+") {
      if(!params.empty() && params != "Randomized" && params != "Deterministic") {
         throw Invalid_Argument(fmt("Unexpected parameters for signing with {}", algo));
      }

      if constexpr(std::is_same_v<SigOptsBaseT, PK_Signature_Options_Builder>) {
         if(params == "Deterministic") {
            builder.with_deterministic_signature();
         }
      }
   } else if(algo == "SM2") {
      /*
      * SM2 parameters have the following possible formats:
      * Ident [since 2.2.0]
      * Ident,Hash [since 2.3.0]
      */
      if(params.empty()) {
         builder.with_hash("SM3");
      } else {
         const auto [userid, hash] = [&]() -> std::pair<std::string_view, std::string_view> {
            if(const auto comma = params.find(','); comma != std::string::npos) {
               return {params.substr(0, comma), params.substr(comma + 1)};
            } else {
               return {params, "SM3"};
            }
         }();

         builder.with_hash(hash);
         if(hash != "Raw") {
            builder.with_context(userid);
         }
      }
   } else if(algo == "Ed25519") {
      if(!params.empty() && params != "Identity" && params != "Pure") {
         if(params == "Ed25519ph") {
            builder.with_prehash();
         } else {
            builder.with_prehash(std::string(params));
         }
      }
   } else if(algo == "Ed448") {
      if(!params.empty() && params != "Identity" && params != "Pure" && params != "Ed448") {
         if(params == "Ed448ph") {
            builder.with_prehash();
         } else {
            builder.with_prehash(std::string(params));
         }
      }
   } else if(algo == "RSA") {
      SCAN_Name req(params);

      // handling various deprecated aliases that have accumulated over the years ...
      auto padding = [](std::string_view alg) -> std::string_view {
         if(alg == "EMSA_PKCS1" || alg == "EMSA-PKCS1-v1_5" || alg == "EMSA3") {
            return "PKCS1v15";
         }

         if(alg == "PSSR_Raw") {
            return "PSS_Raw";
         }

         if(alg == "PSSR" || alg == "EMSA-PSS" || alg == "PSS-MGF1" || alg == "EMSA4") {
            return "PSS";
         }

         if(alg == "EMSA_X931" || alg == "EMSA2" || alg == "X9.31") {
            return "X9.31";
         }

         return alg;
      }(req.algo_name());

      if(padding == "Raw") {
         if(req.arg_count() == 0) {
            builder.with_padding(padding);
         } else if(req.arg_count() == 1) {
            builder.with_padding(padding).with_prehash(req.arg(0));
         } else {
            throw Invalid_Argument("Raw padding with more than one parameter");
         }
      } else if(padding == "PKCS1v15") {
         if(req.arg_count() == 2 && req.arg(0) == "Raw") {
            builder.with_padding(padding).with_hash(req.arg(0)).with_prehash(req.arg(1));
         } else if(req.arg_count() == 1) {
            builder.with_padding(padding).with_hash(req.arg(0));
         } else {
            throw Lookup_Error("PKCS1v15 padding with unexpected parameters");
         }
      } else if(padding == "PSS_Raw" || padding == "PSS") {
         if(req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1") {
            builder.with_padding(padding).with_hash(req.arg(0));

            if(req.arg_count() == 3) {
               builder.with_salt_size(req.arg_as_integer(2));
            }
         } else {
            throw Lookup_Error("PSS padding with unexpected parameters");
         }
      } else if(padding == "ISO_9796_DS2") {
         if(req.arg_count_between(1, 3)) {
            // FIXME
            const bool implicit = req.arg(1, "exp") == "imp";

            builder.with_padding(padding).with_hash(req.arg(0));

            if(req.arg_count() == 3) {
               if(implicit) {
                  builder.with_salt_size(req.arg_as_integer(2));
               } else {
                  builder.with_salt_size(req.arg_as_integer(2)).with_explicit_trailer_field();
               }
            } else if(!implicit) {
               builder.with_explicit_trailer_field();
            }
         } else {
            throw Lookup_Error("ISO-9796-2 DS2 padding with unexpected parameters");
         }
      } else if(padding == "ISO_9796_DS3") {
         //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
         builder.with_padding(padding);
         if(req.arg_count_between(1, 2)) {
            builder.with_hash(req.arg(0));
            if(req.arg(1, "exp") != "imp") {
               builder.with_explicit_trailer_field();
            }
         } else {
            throw Lookup_Error("ISO-9796-2 DS3 padding with unexpected parameters");
         }
      } else if(padding == "X9.31") {
         if(req.arg_count() == 1) {
            builder.with_padding(padding).with_hash(req.arg(0));
         } else {
            throw Lookup_Error("X9.31 padding with unexpected parameters");
         }
      }
      // end of RSA block
   } else {
      if(!params.empty()) {
         // ECDSA/DSA/ECKCDSA/etc
         auto hash = [&]() {
            if(params.starts_with("EMSA1")) {
               SCAN_Name req(params);
               return req.arg(0);
            } else {
               return std::string(params);
            }
         };

         builder.with_hash(hash());
      }
   }
}

}  // namespace

PK_Signature_Options_Builder::PK_Signature_Options_Builder(const Private_Key& key,
                                                           RandomNumberGenerator& rng,
                                                           std::string_view params,
                                                           Signature_Format format,
                                                           std::string_view provider) {
   with_private_key(key);
   with_rng(rng);
   retrofit_legacy_parameters(*this, key, params, format, provider);
}

PK_Verification_Options_Builder::PK_Verification_Options_Builder(const Public_Key& key,
                                                                 std::string_view params,
                                                                 Signature_Format format,
                                                                 std::string_view provider) {
   with_public_key(key);
   retrofit_legacy_parameters(*this, key, params, format, provider);
}

PK_Signature_Options_Builder& PK_Signature_Options_Builder::with_private_key(const Private_Key& key) & {
   with_product_name(key.algo_name());
   set_or_throw(options().private_key, std::cref(key));
   return *this;
}

PK_Verification_Options_Builder& PK_Verification_Options_Builder::with_public_key(const Public_Key& key) & {
   with_product_name(key.algo_name());
   set_or_throw(options().public_key, std::cref(key));
   return *this;
}

void PK_Signature_Options::validate_for_hash_based_signature_algorithm(
   std::string_view algo_name, std::optional<std::string_view> acceptable_hash) {
   if(auto hash = hash_function().optional()) {
      if(!acceptable_hash.has_value()) {
         throw Invalid_Argument(fmt("This {} key does not support explicit hash function choice", algo_name));
      }

      if(hash != acceptable_hash.value()) {
         throw Invalid_Argument(
            fmt("This {} key can only be used with {}, not {}", algo_name, acceptable_hash.value(), hash.value()));
      }
   }
}

}  // namespace Botan
