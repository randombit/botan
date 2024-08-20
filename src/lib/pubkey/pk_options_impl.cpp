/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_options_impl.h>

#include <botan/exceptn.h>
#include <botan/pk_options.h>
#include <botan/internal/fmt.h>
#include <botan/internal/scan_name.h>

namespace Botan {

PK_Signature_Options parse_legacy_sig_options(const Public_Key& key, std::string_view params) {
   /*
   * This is a convoluted mess because we must handle dispatch for every algorithm
   * specific detail of how padding strings were formatted in versions prior to 3.6.
   *
   * This will all go away once the deprecated constructors of PK_Signer and PK_Verifier
   * are removed in Botan4.
   */

   const std::string algo = key.algo_name();

   if(algo.starts_with("Dilithium") || algo == "SPHINCS+") {
      if(!params.empty() && params != "Randomized" && params != "Deterministic") {
         throw Invalid_Argument(fmt("Unexpected parameters for signing with {}", algo));
      }

      if(params == "Deterministic") {
         return PK_Signature_Options().with_deterministic_signature();
      } else {
         return PK_Signature_Options();
      }
   }

   if(algo == "SM2") {
      /*
      * SM2 parameters have the following possible formats:
      * Ident [since 2.2.0]
      * Ident,Hash [since 2.3.0]
      */
      if(params.empty()) {
         return PK_Signature_Options().with_hash("SM3");
      } else {
         std::string userid;
         std::string hash = "SM3";
         auto comma = params.find(',');
         if(comma == std::string::npos) {
            userid = params;
         } else {
            userid = params.substr(0, comma);
            hash = params.substr(comma + 1, std::string::npos);
         }
         return PK_Signature_Options(hash).with_context(userid);
      }
   }

   if(algo == "Ed25519") {
      if(params.empty() || params == "Identity" || params == "Pure") {
         return PK_Signature_Options();
      } else if(params == "Ed25519ph") {
         return PK_Signature_Options().with_prehash();
      } else {
         return PK_Signature_Options().with_prehash(std::string(params));
      }
   }

   if(algo == "Ed448") {
      if(params.empty() || params == "Identity" || params == "Pure" || params == "Ed448") {
         return PK_Signature_Options();
      } else if(params == "Ed448ph") {
         return PK_Signature_Options().with_prehash();
      } else {
         return PK_Signature_Options().with_prehash(std::string(params));
      }
   }

   if(algo == "RSA") {
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
            return PK_Signature_Options().with_padding(padding);
         } else if(req.arg_count() == 1) {
            return PK_Signature_Options().with_padding(padding).with_prehash(req.arg(0));
         }
      }

      if(padding == "PKCS1v15") {
         if(req.arg_count() == 2 && req.arg(0) == "Raw") {
            return PK_Signature_Options().with_padding(padding).with_hash(req.arg(0)).with_prehash(req.arg(1));
         } else if(req.arg_count() == 1) {
            return PK_Signature_Options().with_padding(padding).with_hash(req.arg(0));
         }
      }

      if(padding == "PSS_Raw" || padding == "PSS") {
         if(req.arg_count_between(1, 3) && req.arg(1, "MGF1") == "MGF1") {
            auto pss_opt = PK_Signature_Options().with_padding(padding).with_hash(req.arg(0));

            if(req.arg_count() == 3) {
               return std::move(pss_opt).with_salt_size(req.arg_as_integer(2));
            } else {
               return pss_opt;
            }
         }
      }

      if(padding == "ISO_9796_DS2") {
         if(req.arg_count_between(1, 3)) {
            // FIXME
            const bool implicit = req.arg(1, "exp") == "imp";

            auto opt = PK_Signature_Options().with_padding(padding).with_hash(req.arg(0));

            if(req.arg_count() == 3) {
               if(implicit) {
                  return std::move(opt).with_salt_size(req.arg_as_integer(2));
               } else {
                  return std::move(opt).with_salt_size(req.arg_as_integer(2)).with_explicit_trailer_field();
               }
            } else {
               if(implicit) {
                  return opt;
               } else {
                  return std::move(opt).with_explicit_trailer_field();
               }
            }
         }
      }

      //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
      if(padding == "ISO_9796_DS3") {
         if(req.arg_count_between(1, 2)) {
            if(req.arg(1, "exp") == "imp") {
               return PK_Signature_Options().with_padding(padding).with_hash(req.arg(0));
            } else {
               return PK_Signature_Options().with_padding(padding).with_hash(req.arg(0)).with_explicit_trailer_field();
            }
         }
      }

      if(padding == "X9.31" && req.arg_count() == 1) {
         return PK_Signature_Options().with_padding(padding).with_hash(req.arg(0));
      }
   }  // RSA block

   if(params.empty()) {
      return PK_Signature_Options();
   }

   // ECDSA/DSA/ECKCDSA/etc
   auto hash = [&]() {
      if(params.starts_with("EMSA1")) {
         SCAN_Name req(params);
         return req.arg(0);
      } else {
         return std::string(params);
      }
   }();

   return PK_Signature_Options().with_hash(hash);
}

void validate_for_hash_based_signature(const PK_Signature_Options& options,
                                       std::string_view algo_name,
                                       std::string_view hash_fn) {
   if(options.using_hash()) {
      if(hash_fn.empty()) {
         throw Invalid_Argument(fmt("This {} key does not support explicit hash function choice", algo_name));
      } else if(options.hash_function_name() != hash_fn) {
         throw Invalid_Argument(
            fmt("This {} key can only be used with {}, not {}", algo_name, hash_fn, options.hash_function_name()));
      }
   }

   if(options.using_padding()) {
      throw Invalid_Argument(fmt("{} does not support padding modes", algo_name));
   }

   if(options.using_prehash()) {
      throw Invalid_Argument(fmt("{} does not support prehashing"));
   }
}

}  // namespace Botan
