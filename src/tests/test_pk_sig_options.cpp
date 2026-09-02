/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

   #include <botan/hash.h>
   #include <botan/pk_algs.h>
   #include <botan/pk_options.h>
   #include <botan/pubkey.h>
   #include <botan/internal/fmt.h>
   #include <algorithm>
   #include <optional>
   #include <sstream>

namespace Botan_Tests {

namespace {

std::string_view strip_ws(std::string_view s) {
   while(!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
      s.remove_prefix(1);
   }
   while(!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
      s.remove_suffix(1);
   }
   return s;
}

struct AlgoTestConfig {
      std::string algo_name;
      std::string key_params;
      std::string hash;
      std::string padding;
      std::vector<std::pair<std::string, bool>> option_support;
};

bool has_expectation_for(const AlgoTestConfig& config, std::string_view option) {
   if(option == "Hash" && !config.hash.empty()) {
      return true;
   }
   if(option == "Padding" && !config.padding.empty()) {
      return true;
   }
   for(const auto& [name, supported] : config.option_support) {
      if(name == option) {
         return true;
      }
   }
   return false;
}

std::vector<AlgoTestConfig> parse_sig_options_vec(const std::string& contents) {
   /*
   * Every option which can be set on a PK_Signature_Options
   *
   * Each algorithm section in the data file must either use an option in its
   * baseline (Hash/Padding) or state via Supports<Option> whether it is accepted.
   * This way adding a new option without deciding its status for every algorithm
   * fails the test, rather than the option being silently ignored somewhere.
   */
   const std::vector<std::string> ALL_OPTIONS = {"Hash",
                                                 "Padding",
                                                 "Prehash",
                                                 "ExternalPrehash",
                                                 "Context",
                                                 "DER",
                                                 "SaltSize",
                                                 "Deterministic",
                                                 "ExplicitTrailer"};

   std::vector<AlgoTestConfig> configs;
   AlgoTestConfig* current = nullptr;

   std::istringstream iss(contents);
   std::string line;

   while(std::getline(iss, line)) {
      // Strip inline comments
      if(auto pos = line.find('#'); pos != std::string::npos) {
         line.erase(pos);
      }

      const auto sv = strip_ws(line);
      if(sv.empty()) {
         continue;
      }

      if(sv.front() == '[' && sv.back() == ']') {
         configs.emplace_back();
         current = &configs.back();
         current->algo_name = std::string(sv.substr(1, sv.size() - 2));
         continue;
      }

      if(current == nullptr) {
         throw Test_Error("Key-value pair outside of section");
      }

      const auto eq = sv.find('=');
      if(eq == std::string_view::npos) {
         throw Test_Error(std::string("Line missing '=': ") + std::string(sv));
      }

      const auto key = strip_ws(sv.substr(0, eq));
      const auto value = strip_ws(sv.substr(eq + 1));

      if(key == "KeyParams") {
         current->key_params = std::string(value);
      } else if(key == "Hash") {
         current->hash = std::string(value);
      } else if(key == "Padding") {
         current->padding = std::string(value);
      } else if(key.starts_with("Supports")) {
         const auto opt_name = key.substr(8);  // strip "Supports" prefix
         if(std::find(ALL_OPTIONS.begin(), ALL_OPTIONS.end(), opt_name) == ALL_OPTIONS.end()) {
            throw Test_Error(std::string("Unknown option: '") + std::string(opt_name) + "'");
         }
         bool supported = false;
         if(value == "true") {
            supported = true;
         } else if(value == "false") {
            supported = false;
         } else {
            throw Test_Error(std::string("Invalid boolean: '") + std::string(value) + "'");
         }
         current->option_support.emplace_back(std::string(opt_name), supported);
      } else {
         throw Test_Error(std::string("Unknown key: '") + std::string(key) + "'");
      }
   }

   for(const auto& config : configs) {
      for(const auto& option : ALL_OPTIONS) {
         if(!has_expectation_for(config, option)) {
            throw Test_Error(Botan::fmt("[{}] does not state if option {} is supported", config.algo_name, option));
         }
      }
   }

   return configs;
}

Botan::PK_Signature_Options make_baseline(const AlgoTestConfig& config) {
   Botan::PK_Signature_Options opts;
   if(!config.hash.empty()) {
      opts = opts.with_hash(config.hash);
   }
   if(!config.padding.empty()) {
      opts = opts.with_padding(config.padding);
   }
   return opts;
}

Botan::PK_Signature_Options with_added_option(Botan::PK_Signature_Options baseline, std::string_view option) {
   if(option == "Padding") {
      return baseline.with_padding("PKCS1v15");
   }
   if(option == "Prehash") {
      return baseline.with_prehash();
   }
   if(option == "ExternalPrehash") {
      return baseline.with_externally_computed_prehash();
   }
   if(option == "Context") {
      return baseline.with_context("test context");
   }
   if(option == "DER") {
      return baseline.with_der_encoded_signature();
   }
   if(option == "SaltSize") {
      return baseline.with_salt_size(32);
   }
   if(option == "Deterministic") {
      return baseline.with_deterministic_signature();
   }
   if(option == "ExplicitTrailer") {
      return baseline.with_explicit_trailer_field();
   }
   if(option == "Hash") {
      return baseline.with_hash("SHA-256");
   }
   throw Test_Error(std::string("Unknown option name: '") + std::string(option) + "'");
}

/*
* Verifier options which conflict with a signature created using the given
* option; verifying with these must fail (or the verifier must refuse them),
* otherwise the option was accepted by the signer but not actually applied.
*/
std::optional<Botan::PK_Signature_Options> conflicting_verifier_options(Botan::PK_Signature_Options baseline,
                                                                        std::string_view option) {
   if(option == "Context") {
      return baseline.with_context("a different context");
   }
   if(option == "SaltSize") {
      return baseline.with_salt_size(16);
   }
   if(option == "Prehash" || option == "ExternalPrehash" || option == "DER" || option == "ExplicitTrailer") {
      // The baseline itself does not use the option
      return baseline;
   }
   return std::nullopt;
}

class PK_Signature_Options_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         const auto file_contents = Test::read_data_file("pubkey/pk_sig_options.vec");
         const auto configs = parse_sig_options_vec(file_contents);

         std::vector<Test::Result> results;

         for(const auto& config : configs) {
            Test::Result result("PK_Sig_Options " + config.algo_name);
            result.start_timer();

            std::unique_ptr<Botan::Private_Key> key;
            try {
               // For entries like "RSA/PSS", use just "RSA" for key generation
               auto key_algo = config.algo_name;
               if(auto slash = key_algo.find('/'); slash != std::string::npos) {
                  key_algo = key_algo.substr(0, slash);
               }
               key = Botan::create_private_key(key_algo, rng(), config.key_params);
            } catch(const Botan::Lookup_Error&) {
               result.test_note("Skipping - algorithm not available");
               result.end_timer();
               results.push_back(std::move(result));
               continue;
            }

            if(!key) {
               result.test_note("Key generation unavailable");
               result.end_timer();
               results.push_back(std::move(result));
               continue;
            }

            const auto pub = key->public_key();

            // Test that the baseline options produce valid signatures; if the
            // baseline itself is not available in this build (eg the padding
            // scheme or hash was disabled) there is nothing further to test
            if(!test_baseline(result, *key, *pub, config)) {
               result.end_timer();
               results.push_back(std::move(result));
               continue;
            }

            // Test each option individually
            for(const auto& [opt_name, supported] : config.option_support) {
               if(supported) {
                  test_option_accepted(result, *key, *pub, config, opt_name);
               } else {
                  test_option_rejected(result, *key, *pub, config, opt_name);
               }
            }

            result.end_timer();
            results.push_back(std::move(result));
         }

         return results;
      }

   private:
      /*
      * Return true if the exception indicates the configuration is not
      * available in this build (as opposed to being rejected as invalid)
      */
      static bool is_unavailable(const Botan::Exception& e) {
         return dynamic_cast<const Botan::Lookup_Error*>(&e) != nullptr ||
                dynamic_cast<const Botan::Not_Implemented*>(&e) != nullptr;
      }

      bool test_baseline(Test::Result& result,
                         const Botan::Private_Key& key,
                         const Botan::Public_Key& pub,
                         const AlgoTestConfig& config) {
         try {
            const auto opts = make_baseline(config);
            Botan::PK_Signer signer(key, rng(), opts);
            Botan::PK_Verifier verifier(pub, make_baseline(config));

            const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};
            auto sig = signer.sign_message(message, rng());
            result.test_is_true("Baseline sign/verify", verifier.verify_message(message, sig));
            return true;
         } catch(const Botan::Exception& e) {
            if(is_unavailable(e)) {
               result.test_note(std::string("Skipping - baseline not available in this build: ") + e.what());
               return false;
            }
            result.test_failure("Baseline signer creation", e.what());
            return false;
         }
      }

      void test_option_accepted(Test::Result& result,
                                const Botan::Private_Key& key,
                                const Botan::Public_Key& pub,
                                const AlgoTestConfig& config,
                                const std::string& opt_name) {
         try {
            const auto opts = with_added_option(make_baseline(config), opt_name);
            Botan::PK_Signer signer(key, rng(), opts);
            Botan::PK_Verifier verifier(pub, with_added_option(make_baseline(config), opt_name));

            const std::vector<uint8_t> original_message = {0x61, 0x62, 0x63, 0x64};

            // With an external prehash the input must be a digest of the baseline hash
            const bool prehashed = (opt_name == "ExternalPrehash" && !config.hash.empty());
            const std::vector<uint8_t> message = [&]() {
               if(prehashed) {
                  return Botan::HashFunction::create_or_throw(config.hash)
                     ->process<std::vector<uint8_t>>(original_message);
               }
               return original_message;  // NOLINT(*-no-automatic-move)
            }();

            auto sig = signer.sign_message(message, rng());
            result.test_is_true(opt_name + " sign/verify", verifier.verify_message(message, sig));

            if(prehashed) {
               // Signing the digest must produce the same signature type as hashing the message
               Botan::PK_Verifier baseline_verifier(pub, make_baseline(config));
               result.test_is_true("ExternalPrehash signature verifies over the original message",
                                   baseline_verifier.verify_message(original_message, sig));
            }

            // Now check that the option actually took effect
            if(opt_name == "Deterministic") {
               // Stateful schemes never produce the same signature twice
               if(!key.stateful_operation()) {
                  auto sig2 = signer.sign_message(message, rng());
                  result.test_bin_eq("Deterministic signatures are identical", sig, sig2);
               }
            } else if(auto conflicting = conflicting_verifier_options(make_baseline(config), opt_name)) {
               bool rejected = false;
               try {
                  Botan::PK_Verifier other_verifier(pub, *conflicting);
                  rejected = !other_verifier.verify_message(message, sig);
               } catch(Botan::Exception&) {
                  rejected = true;
               }
               result.test_is_true(opt_name + " is applied (conflicting verifier rejects)", rejected);
            }
            result.test_success(opt_name + " accepted");
         } catch(const Botan::Exception& e) {
            if(is_unavailable(e)) {
               // eg deterministic ECDSA in a build without RFC 6979
               result.test_note(opt_name + " not available in this build: " + e.what());
            } else {
               result.test_failure(opt_name + " accepted", e.what());
            }
         }
      }

      void test_option_rejected(Test::Result& result,
                                const Botan::Private_Key& key,
                                const Botan::Public_Key& pub,
                                const AlgoTestConfig& config,
                                const std::string& opt_name) {
         const auto opts = with_added_option(make_baseline(config), opt_name);

         result.test_throws(opt_name + " rejected by signer", [&] { Botan::PK_Signer(key, rng(), opts); });

         // Deterministic is a signing-only option; verifiers don't check it
         if(opt_name == "Deterministic") {
            return;
         }

         result.test_throws(opt_name + " rejected by verifier", [&] { Botan::PK_Verifier(pub, opts); });
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options", PK_Signature_Options_Test);

   #if defined(BOTAN_HAS_ED25519)

/*
* An option which no part of the signature scheme examines must be rejected,
* naming the offending option, without any scheme specific code.
*/
class PK_Signature_Options_Unexamined_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Signature_Options rejects unexamined options");

         auto key = Botan::create_private_key("Ed25519", rng());
         if(!key) {
            result.test_note("Skipping - Ed25519 not available");
            return {result};
         }
         const auto pub = key->public_key();

         const auto opts = Botan::PK_Signature_Options().with_salt_size(32).with_explicit_trailer_field();

         auto check_message = [&](const std::string& what, const std::exception& e) {
            const std::string msg = e.what();
            result.test_is_true(what + " names the unexamined options",
                                msg.find("Ed25519 does not support the signature option(s): salt size, explicit "
                                         "trailer field") != std::string::npos);
         };

         try {
            const Botan::PK_Signer signer(*key, rng(), opts);
            result.test_failure("PK_Signer accepted unexamined options");
         } catch(Botan::Invalid_Argument& e) {
            check_message("PK_Signer", e);
         }

         try {
            const Botan::PK_Verifier verifier(*pub, opts);
            result.test_failure("PK_Verifier accepted unexamined options");
         } catch(Botan::Invalid_Argument& e) {
            check_message("PK_Verifier", e);
         }

         // Every option must be named in the message, so the name table cannot
         // silently fall out of sync with the set of options
         try {
            const Botan::PK_Verifier verifier(*pub,
                                              Botan::PK_Signature_Options()
                                                 .with_hash("SHA-256")
                                                 .with_padding("PSS")
                                                 .with_externally_computed_prehash()
                                                 .with_context("ctx")
                                                 .with_salt_size(16)
                                                 .with_explicit_trailer_field());
            result.test_failure("PK_Verifier accepted unexamined options");
         } catch(Botan::Invalid_Argument& e) {
            result.test_str_eq("All unexamined options are named",
                               e.what(),
                               "Ed25519 does not support the signature option(s): hash, padding, context, "
                               "salt size, explicit trailer field, externally computed prehash");
         }

         // The deterministic option is only meaningful for signing; verifiers accept it
         result.test_no_throw("Verifier ignores deterministic option", [&] {
            const Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options().with_deterministic_signature());
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options_unexamined", PK_Signature_Options_Unexamined_Test);

   #endif

   #if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EMSA_PKCS1) && defined(BOTAN_HAS_EMSA_RAW) && defined(BOTAN_HAS_PSS)

/*
* RSA must never fall back to raw or hashless signing when options are missing
*/
class PK_Signature_Options_RSA_Explicit_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Signature_Options RSA requires explicit padding");

         auto key = Botan::create_private_key("RSA", rng(), "1024");
         if(!key) {
            result.test_note("Skipping - RSA not available");
            return {result};
         }
         const auto pub = key->public_key();

         auto rejected = [&](const std::string& what, const Botan::PK_Signature_Options& opts) {
            result.test_throws(what + " rejected by signer", [&] { Botan::PK_Signer(*key, rng(), opts); });
            result.test_throws(what + " rejected by verifier", [&] { Botan::PK_Verifier(*pub, opts); });
         };

         rejected("No options", Botan::PK_Signature_Options());
         rejected("Hash without padding", Botan::PK_Signature_Options().with_hash("SHA-256"));
         rejected("PKCS1v15 without hash", Botan::PK_Signature_Options().with_padding("PKCS1v15"));
         rejected("PSS without hash", Botan::PK_Signature_Options().with_padding("PSS"));
         rejected("Raw with unknown external prehash",
                  Botan::PK_Signature_Options().with_padding("Raw").with_externally_computed_prehash("NoSuchHash"));
         rejected("Raw with internal prehash", Botan::PK_Signature_Options().with_padding("Raw").with_prehash());
         rejected("Raw with a hash but no external prehash",
                  Botan::PK_Signature_Options().with_padding("Raw").with_hash("SHA-256"));
         rejected("PKCS1v15 with internal prehash",
                  Botan::PK_Signature_Options().with_padding("PKCS1v15").with_hash("SHA-256").with_prehash());
         rejected("PKCS1v15 with Raw as the hash name",
                  Botan::PK_Signature_Options().with_padding("PKCS1v15").with_hash("Raw"));
         rejected("PKCS1v15 with mismatched external prehash",
                  Botan::PK_Signature_Options()
                     .with_padding("PKCS1v15")
                     .with_hash("SHA-256")
                     .with_externally_computed_prehash("SHA-384"));
         rejected(
            "PSS with external prehash",
            Botan::PK_Signature_Options().with_padding("PSS").with_hash("SHA-256").with_externally_computed_prehash());

         // Raw signing is still available, but only when asked for explicitly
         result.test_no_throw("Explicit raw padding accepted", [&] {
            Botan::PK_Signer signer(*key, rng(), Botan::PK_Signature_Options().with_padding("Raw"));
            Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options().with_padding("Raw"));
            const std::vector<uint8_t> msg(32, 0x42);
            const auto sig = signer.sign_message(msg, rng());
            result.test_is_true("Raw roundtrip", verifier.verify_message(msg, sig));
         });

         // Naming the hash of an external prehash enforces the digest length
         result.test_no_throw("Raw padding with named external prehash", [&] {
            const auto raw_sha256 =
               Botan::PK_Signature_Options().with_padding("Raw").with_externally_computed_prehash("SHA-256");
            Botan::PK_Signer signer(*key, rng(), raw_sha256);
            Botan::PK_Verifier verifier(*pub, raw_sha256);
            const std::vector<uint8_t> digest(32, 0x42);
            const auto sig = signer.sign_message(digest, rng());
            result.test_is_true("Raw(SHA-256) roundtrip", verifier.verify_message(digest, sig));

            const std::vector<uint8_t> short_digest(20, 0x42);
            result.test_throws("Raw(SHA-256) rejects a 20 byte input",
                               [&] { signer.sign_message(short_digest, rng()); });
         });

         result.test_no_throw("PKCS1v15 with unnamed external prehash", [&] {
            const auto pkcs1_raw =
               Botan::PK_Signature_Options().with_padding("PKCS1v15").with_externally_computed_prehash();
            Botan::PK_Signer signer(*key, rng(), pkcs1_raw);
            Botan::PK_Verifier verifier(*pub, pkcs1_raw);
            const std::vector<uint8_t> digest(20, 0x42);
            const auto sig = signer.sign_message(digest, rng());
            result.test_is_true("PKCS1v15(Raw) roundtrip", verifier.verify_message(digest, sig));
         });

         // The deterministic option is ignored for verification, even where the
         // padding scheme would reject it for signing
         auto pss = Botan::PK_Signature_Options().with_padding("PSS").with_hash("SHA-256");
         result.test_throws("PSS with salt cannot be deterministic when signing",
                            [&] { Botan::PK_Signer(*key, rng(), pss.with_deterministic_signature()); });
         result.test_no_throw("Verifier ignores deterministic for PSS", [&] {
            Botan::PK_Signer signer(*key, rng(), pss);
            Botan::PK_Verifier verifier(*pub, pss.with_deterministic_signature());
            const std::vector<uint8_t> msg(32, 0x42);
            const auto sig = signer.sign_message(msg, rng());
            result.test_is_true("PSS roundtrip", verifier.verify_message(msg, sig));
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options_rsa_explicit", PK_Signature_Options_RSA_Explicit_Test);

   #endif

/*
* Each boolean option can be requested at most once, matching the other setters
*/
class PK_Signature_Options_Duplicate_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Signature_Options rejects duplicate options");

         result.test_throws<Botan::Invalid_State>("DER encoding twice", [] {
            Botan::PK_Signature_Options().with_der_encoded_signature().with_der_encoded_signature();
         });

         result.test_throws<Botan::Invalid_State>("deterministic twice", [] {
            Botan::PK_Signature_Options().with_deterministic_signature().with_deterministic_signature();
         });

         result.test_throws<Botan::Invalid_State>("explicit trailer twice", [] {
            Botan::PK_Signature_Options().with_explicit_trailer_field().with_explicit_trailer_field();
         });

         result.test_throws<Botan::Invalid_State>(
            "hash twice", [] { Botan::PK_Signature_Options().with_hash("SHA-256").with_hash("SHA-512"); });

         result.test_throws<Botan::Invalid_State>("external prehash twice", [] {
            Botan::PK_Signature_Options().with_externally_computed_prehash().with_externally_computed_prehash();
         });

         // The library either computes the prehash or the caller does, not both
         result.test_throws<Botan::Invalid_State>("prehash then external prehash", [] {
            Botan::PK_Signature_Options().with_prehash().with_externally_computed_prehash();
         });

         result.test_throws<Botan::Invalid_State>("external prehash then prehash", [] {
            Botan::PK_Signature_Options().with_externally_computed_prehash().with_prehash();
         });

         result.test_no_throw("flags default off can be set once", [&] {
            const auto opts = Botan::PK_Signature_Options()
                                 .with_der_encoded_signature(false)
                                 .with_der_encoded_signature()
                                 .with_deterministic_signature(false)
                                 .with_deterministic_signature()
                                 .with_explicit_trailer_field(false)
                                 .with_explicit_trailer_field();
            result.test_is_true("DER flag set", opts.using_der_encoded_signature());
            result.test_is_true("deterministic flag set", opts.using_deterministic_signature());
            result.test_is_true("explicit trailer flag set", opts.using_explicit_trailer_field());
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options_duplicate", PK_Signature_Options_Duplicate_Test);

   #if defined(BOTAN_HAS_ECDSA)

/*
* The deprecated string forms "EMSA1(hash)" and "Raw(hash)" must be well formed
*/
class PK_Signature_Options_Legacy_EMSA1_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Signature_Options legacy string parsing");

         auto key = Botan::create_private_key("ECDSA", rng(), "secp256r1");
         if(!key) {
            result.test_note("Skipping - ECDSA not available");
            return {result};
         }
         const auto pub = key->public_key();

         const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};

         result.test_no_throw("EMSA1(SHA-256) is accepted", [&] {
            Botan::PK_Signer signer(*key, rng(), "EMSA1(SHA-256)");
            Botan::PK_Verifier verifier(*pub, "SHA-256");
            const auto sig = signer.sign_message(message, rng());
            result.test_is_true("EMSA1(SHA-256) signs with SHA-256", verifier.verify_message(message, sig));
         });

         for(const auto* params : {"EMSA1(SHA-256,extra)", "EMSA1", "EMSA1()", "EMSA1X(SHA-256)"}) {
            const std::string what = std::string("'") + params + "' is rejected";
            result.test_throws<Botan::Invalid_Argument>(what + " by signer",
                                                        [&] { const Botan::PK_Signer signer(*key, rng(), params); });
            result.test_throws<Botan::Invalid_Argument>(what + " by verifier",
                                                        [&] { const Botan::PK_Verifier verifier(*pub, params); });
         }

      #if defined(BOTAN_HAS_RAW_HASH_FN)
         // "Raw(hash)" signs a digest the caller computed, and must agree with signing the message
         result.test_no_throw("Raw(SHA-256) is accepted", [&] {
            Botan::PK_Signer signer(*key, rng(), "Raw(SHA-256)");
            Botan::PK_Verifier verifier(*pub, "SHA-256");
            const auto digest = Botan::HashFunction::create_or_throw("SHA-256")->process<std::vector<uint8_t>>(message);
            const auto sig = signer.sign_message(digest, rng());
            result.test_is_true("Raw(SHA-256) signature verifies over the message",
                                verifier.verify_message(message, sig));
            result.test_throws("Raw(SHA-256) rejects a 4 byte input", [&] { signer.sign_message(message, rng()); });
         });

         for(const auto* params : {"Raw(SHA-256,extra)", "Raw()", "RawX(SHA-256)"}) {
            const std::string what = std::string("'") + params + "' is rejected";
            result.test_throws<Botan::Invalid_Argument>(what + " by signer",
                                                        [&] { const Botan::PK_Signer signer(*key, rng(), params); });
            result.test_throws<Botan::Invalid_Argument>(what + " by verifier",
                                                        [&] { const Botan::PK_Verifier verifier(*pub, params); });
         }
      #endif

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options_legacy_emsa1", PK_Signature_Options_Legacy_EMSA1_Test);

   #endif

/*
* Hash-based schemes fix the hash in the key; the hash option is accepted only
* if it names the hash the operation reports, so that a signer's hash_function()
* can always be handed to a verifier, and every such scheme must behave the same way
*/
class PK_Signature_Options_Fixed_Hash_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         struct FixedHashScheme {
               std::string algo;
               std::string key_params;
               std::string expected_hash;
         };

         const std::vector<FixedHashScheme> schemes = {
   #if defined(BOTAN_HAS_HSS_LMS)
            {"HSS-LMS", "SHA-256,HW(5,1)", "SHA-256"},
            {"HSS-LMS", "Truncated(SHA-256,192),HW(5,1)", "Truncated(SHA-256,192)"},
            {"HSS-LMS", "SHAKE-256(256),HW(5,1)", "SHAKE-256(256)"},
   #endif
   #if defined(BOTAN_HAS_XMSS_RFC8391)
            {"XMSS", "XMSS-SHA2_10_256", "SHA-256"},
            {"XMSS", "XMSS-SHA2_10_192", "Truncated(SHA-256,192)"},
            {"XMSS", "XMSS-SHAKE_10_256", "SHAKE-128(256)"},
   #endif
   #if defined(BOTAN_HAS_SLH_DSA_WITH_SHA2)
            {"SLH-DSA", "SLH-DSA-SHA2-128s", "SHA-256"},
            // For n > 16 the SHA-2 parameter sets hash the message with SHA-512
            {"SLH-DSA", "SLH-DSA-SHA2-192s", "SHA-512"},
   #endif
   #if defined(BOTAN_HAS_SLH_DSA_WITH_SHAKE)
            // The message digest is longer than n
            {"SLH-DSA", "SLH-DSA-SHAKE-128s", "SHAKE-256(240)"},
   #endif
         };

         std::vector<Test::Result> results;

         for(const auto& scheme : schemes) {
            Test::Result result("PK_Signature_Options fixed hash " + scheme.key_params);

            auto key = Botan::create_private_key(scheme.algo, rng(), scheme.key_params);
            if(!key) {
               result.test_note("Skipping - " + scheme.algo + " not available");
               results.push_back(std::move(result));
               continue;
            }
            const auto pub = key->public_key();

            const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};

            const std::string reported = Botan::PK_Signer(*key, rng()).hash_function();
            result.test_str_eq("Reported hash", reported, scheme.expected_hash);

            result.test_no_throw("Reported hash accepted", [&] {
               Botan::PK_Signer signer(*key, rng(), Botan::PK_Signature_Options().with_hash(reported));
               Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options().with_hash(reported));
               result.test_str_eq("Verifier reports the same hash", verifier.hash_function(), reported);
               const auto sig = signer.sign_message(message, rng());
               result.test_is_true("Matching hash sign/verify", verifier.verify_message(message, sig));
            });

            const std::string other_hash = (reported == "SHA-512") ? "SHA-256" : "SHA-512";

            result.test_throws<Botan::Invalid_Argument>("Mismatched hash rejected by signer", [&] {
               const Botan::PK_Signer signer(*key, rng(), Botan::PK_Signature_Options().with_hash(other_hash));
            });

            result.test_throws<Botan::Invalid_Argument>("Mismatched hash rejected by verifier", [&] {
               const Botan::PK_Verifier verifier(*pub, Botan::PK_Signature_Options().with_hash(other_hash));
            });

            results.push_back(std::move(result));
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_sig_options_fixed_hash", PK_Signature_Options_Fixed_Hash_Test);

}  // namespace

}  // namespace Botan_Tests

#endif
