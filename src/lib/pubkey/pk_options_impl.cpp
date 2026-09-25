/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_options_impl.h>

#include <botan/assert.h>
#include <botan/exceptn.h>
#include <botan/internal/algorithm_spec.h>
#include <botan/internal/fmt.h>

namespace Botan {

PK_Signature_Options parse_legacy_sig_options(const Public_Key& key, std::string_view params) {
   /*
   * This is a convoluted mess because we must handle dispatch for every algorithm
   * specific detail of how padding strings were formatted in versions prior to the
   * introduction of PK_Signature_Options.
   *
   * This will all go away once the deprecated constructors of PK_Signer and PK_Verifier
   * are removed in Botan4.
   */

   const std::string algo = key.algo_name();

   if(algo.starts_with("Dilithium") || algo.starts_with("ML-DSA") || algo == "SLH-DSA" || algo == "SPHINCS+") {
      if(!params.empty() && params != "Randomized" && params != "Deterministic" && params != "Pure") {
         throw Invalid_Argument(fmt("Unexpected parameters '{}' for signing with {}", params, algo));
      }

      if(params == "Deterministic" || params == "Pure") {
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
      *
      * Historically a completely empty parameter string was treated as
      * if the identity was empty. This probably should have instead been
      * treated as if it was the "default userid" ("1234567812345678") but
      * there was a bug and it wasn't.
      *
      * TODO(Botan4) evaluate if this should be changed
      */
      std::string userid;
      std::string hash = "SM3";
      auto comma = params.find(',');
      if(comma == std::string::npos) {
         userid = params;
      } else {
         userid = params.substr(0, comma);
         hash = params.substr(comma + 1, std::string::npos);
      }

      // With a "Raw" hash there is no ZA computation, and the identity was always ignored
      if(hash == "Raw") {
         return PK_Signature_Options().with_externally_computed_prehash();
      }

      return PK_Signature_Options().with_hash(hash).with_context(userid);
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
      // handling various deprecated aliases that have accumulated over the years ...
      auto canonical_padding = [](std::string_view alg) -> std::string_view {
         // TODO(Botan4) Remove all but "PKCSv15"
         if(alg == "EMSA_PKCS1" || alg == "EMSA-PKCS1-v1_5" || alg == "EMSA3") {
            return "PKCS1v15";
         }

         // TODO(Botan4) Remove this alias
         if(alg == "PSSR_Raw") {
            return "PSS_Raw";
         }

         // TODO(Botan4) Remove all but "PSS"
         if(alg == "PSSR" || alg == "EMSA-PSS" || alg == "PSS-MGF1" || alg == "EMSA4") {
            return "PSS";
         }

         // TODO(Botan4) Remove all but "X9.31"
         if(alg == "EMSA_X931" || alg == "EMSA2" || alg == "X9.31") {
            return "X9.31";
         }

         return alg;
      };

      const AlgorithmSpec given(params);
      const AlgorithmSpec req = given.with_head(canonical_padding(given.head()));

      if(auto m = req.match("Raw({hash?})")) {
         if(m->has("hash")) {
            return PK_Signature_Options().with_padding("Raw").with_externally_computed_prehash(
               std::string(m->str("hash")));
         }
         return PK_Signature_Options().with_padding("Raw");
      }

      if(auto m = req.match("PKCS1v15(Raw,{hash?})")) {
         if(m->has("hash")) {
            return PK_Signature_Options()
               .with_padding("PKCS1v15")
               .with_externally_computed_prehash(std::string(m->str("hash")));
         }
         return PK_Signature_Options().with_padding("PKCS1v15").with_externally_computed_prehash();
      }

      if(auto m = req.match("PKCS1v15({hash})")) {
         return PK_Signature_Options().with_padding("PKCS1v15").with_hash(m->str("hash"));
      }

      // Only supported by PKCS#11 (CKM_RSA_9796)
      if(req.matches("ISO9796")) {
         return PK_Signature_Options().with_padding("ISO9796");
      }

      if(req.matches("PSS(Raw)")) {
         return PK_Signature_Options().with_padding("PSS").with_externally_computed_prehash();
      }

      if(auto m = req.match("PSS|PSS_Raw({hash})")) {
         return PK_Signature_Options().with_padding(m->head()).with_hash(m->str("hash"));
      }

      if(auto m = req.match("PSS|PSS_Raw({hash},MGF1,{salt_len:int?})")) {
         auto pss_opt = PK_Signature_Options().with_padding(m->head()).with_hash(m->str("hash"));

         if(m->has("salt_len")) {
            return std::move(pss_opt).with_salt_size(m->integer("salt_len"));
         }
         return pss_opt;
      }

      if(auto m = req.match("ISO_9796_DS2({hash},{trailer:str=exp},{salt_len:int?})")) {
         const auto trailer = m->str("trailer");
         if(trailer != "imp" && trailer != "exp") {
            throw Invalid_Argument(fmt("Unexpected parameters '{}' for signing with {}", params, algo));
         }

         auto opt = PK_Signature_Options()
                       .with_padding("ISO_9796_DS2")
                       .with_hash(m->str("hash"))
                       .with_explicit_trailer_field(trailer == "exp");

         if(m->has("salt_len")) {
            return std::move(opt).with_salt_size(m->integer("salt_len"));
         }
         return opt;
      }

      //ISO-9796-2 DS 3 is deterministic and DS2 without a salt
      if(auto m = req.match("ISO_9796_DS3({hash},{trailer:str=exp})")) {
         const auto trailer = m->str("trailer");
         if(trailer != "imp" && trailer != "exp") {
            throw Invalid_Argument(fmt("Unexpected parameters '{}' for signing with {}", params, algo));
         }

         return PK_Signature_Options()
            .with_padding("ISO_9796_DS3")
            .with_hash(m->str("hash"))
            .with_explicit_trailer_field(trailer == "exp");
      }

      if(req.matches("X9.31(Raw)")) {
         return PK_Signature_Options().with_padding("X9.31").with_externally_computed_prehash();
      }

      if(auto m = req.match("X9.31({hash})")) {
         return PK_Signature_Options().with_padding("X9.31").with_hash(m->str("hash"));
      }
   }  // RSA block

   if(params.empty()) {
      return PK_Signature_Options();
   }

   // ECDSA/DSA/ECKCDSA/etc

   /*
   * Stopgap until PK_Signature_Options is exposed through the FFI: a
   * trailing ",Deterministic" (eg "SHA-256,Deterministic") requests a
   * deterministic signature, so that RFC 6979 ECDSA remains reachable
   * through the string based interfaces.
   */
   const std::string_view det_suffix = ",Deterministic";
   const bool deterministic = params.ends_with(det_suffix);
   const std::string_view hash_params = deterministic ? params.substr(0, params.size() - det_suffix.size()) : params;

   // "Raw" or "Raw(hash)" means the caller provides the digest
   if(hash_params.starts_with("Raw")) {
      const AlgorithmSpec req(hash_params);
      const auto m = req.match("Raw({hash?})");
      if(!m) {
         throw Invalid_Argument(fmt("Unexpected parameters '{}' for signing with {}", params, algo));
      }
      auto raw_opt = PK_Signature_Options().with_deterministic_signature(deterministic);
      if(m->has("hash")) {
         return std::move(raw_opt).with_externally_computed_prehash(std::string(m->str("hash")));
      }
      return std::move(raw_opt).with_externally_computed_prehash();
   }

   auto hash = [&]() -> std::string {
      if(hash_params.starts_with("EMSA1")) {
         const AlgorithmSpec req(hash_params);
         const auto m = req.match("EMSA1({hash})");
         if(!m) {
            throw Invalid_Argument(fmt("Unexpected parameters '{}' for signing with {}", params, algo));
         }
         return std::string(m->str("hash"));
      } else {
         return std::string(hash_params);
      }
   }();

   return PK_Signature_Options().with_hash(hash).with_deterministic_signature(deterministic);
}

PK_Encryption_Options parse_legacy_enc_options(const Public_Key& key, std::string_view params) {
   /*
   * As with parse_legacy_sig_options, this handles the padding strings accepted
   * prior to the introduction of PK_Encryption_Options.
   */

   if(key.algo_name() == "SM2") {
      // The only parameter is the hash function, which defaults to SM3
      return PK_Encryption_Options().with_hash(params);
   }

   /*
   * Everything else (RSA, ElGamal, and the RSA implementations of the hardware
   * providers) takes an EME specification:
   *
   * Raw
   * PKCS1v15 (or the alias EME-PKCS1-v1_5)
   * OAEP(hash), OAEP(hash,MGF1), OAEP(hash,MGF1,label), OAEP(hash,MGF1(mgf_hash)),
   * OAEP(hash,MGF1(mgf_hash),label) (or the aliases EME-OAEP and EME1)
   */

   // TODO(Botan4) Remove all but "PKCS1v15"
   if(params == "PKCS1v15" || params == "EME-PKCS1-v1_5") {
      return PK_Encryption_Options().with_padding("PKCS1v15");
   }

   // Schemes which require a padding reject this when the operation is created
   if(params.empty()) {
      return PK_Encryption_Options();
   }

   // TODO(Botan4) Remove all but "OAEP" here
   if(params.starts_with("OAEP") || params.starts_with("EME-OAEP") || params.starts_with("EME1")) {
      const AlgorithmSpec req(params);

      auto oaep_opt = PK_Encryption_Options().with_padding("OAEP");

      if(auto m = req.match("OAEP|EME-OAEP|EME1({hash})")) {
         return oaep_opt.with_hash(m->str("hash"));
      }

      if(auto m = req.match("OAEP|EME-OAEP|EME1({hash},MGF1,{label:str=})")) {
         return oaep_opt.with_hash(m->str("hash")).with_context(m->str("label"));
      }

      if(auto m = req.match("OAEP|EME-OAEP|EME1({hash},MGF1({mgf_hash}),{label:str=})")) {
         return oaep_opt.with_hash(m->str("hash")).with_mgf1_hash(m->str("mgf_hash")).with_context(m->str("label"));
      }
   }

   // Anything else, including "Raw", is treated as the name of a padding scheme
   return PK_Encryption_Options().with_padding(params);
}

PK_KEM_Options parse_legacy_kem_options(std::string_view params) {
   // The string interface has always required naming a KDF (or "Raw")
   if(params.empty()) {
      throw Invalid_Argument("KEM requires specifying a KDF, or Raw to use the shared key directly");
   } else if(params == "Raw") {
      return PK_KEM_Options().with_raw_shared_key();
   } else {
      return PK_KEM_Options().with_kdf(params);
   }
}

PK_Key_Agreement_Options parse_legacy_ka_options(std::string_view params) {
   // The string interface has always required naming a KDF (or "Raw")
   if(params.empty()) {
      throw Invalid_Argument("Key agreement requires specifying a KDF, or Raw to use the agreed value directly");
   } else if(params == "Raw") {
      return PK_Key_Agreement_Options().with_raw_shared_key();
   } else {
      return PK_Key_Agreement_Options().with_kdf(params);
   }
}

void validate_for_hash_based_signature(const PK_Signature_Options_Reader& options,
                                       std::string_view algo_name,
                                       std::string_view hash_fn) {
   if(options.using_hash() && options.hash_function_name() != hash_fn) {
      throw Invalid_Argument(
         fmt("This {} key can only be used with {}, not {}", algo_name, hash_fn, options.hash_function_name()));
   }
}

std::optional<std::string> externally_computed_prehash_name(const PK_Signature_Options_Reader& options) {
   BOTAN_STATE_CHECK(options.using_externally_computed_prehash());

   const auto& prehash = options.externally_computed_prehash_function();
   const auto& hash = options.hash_function();

   if(prehash.has_value() && hash.has_value() && *prehash != *hash) {
      throw Invalid_Argument(
         fmt("Externally computed prehash was named as {} but the hash option specified {}", *prehash, *hash));
   }

   return prehash.has_value() ? prehash : hash;
}

void acknowledge_always_deterministic(const PK_Signature_Options_Reader& options) {
   BOTAN_UNUSED(options.using_deterministic_signature());
}

}  // namespace Botan
