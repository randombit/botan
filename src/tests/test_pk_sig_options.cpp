/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

   #include <botan/pk_algs.h>
   #include <botan/pk_options.h>
   #include <botan/pubkey.h>
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

std::vector<AlgoTestConfig> parse_sig_options_vec(const std::string& contents) {
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
               result.test_failure("Key generation returned null");
               result.end_timer();
               results.push_back(std::move(result));
               continue;
            }

            const auto pub = key->public_key();

            // Test that the baseline options produce valid signatures
            test_baseline(result, *key, *pub, config);

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
      void test_baseline(Test::Result& result,
                         const Botan::Private_Key& key,
                         const Botan::Public_Key& pub,
                         const AlgoTestConfig& config) {
         result.test_no_throw("Baseline signer creation", [&] {
            const auto opts = make_baseline(config);
            Botan::PK_Signer signer(key, rng(), opts);
            Botan::PK_Verifier verifier(pub, make_baseline(config));

            const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};
            auto sig = signer.sign_message(message, rng());
            result.test_is_true("Baseline sign/verify", verifier.verify_message(message, sig));
         });
      }

      void test_option_accepted(Test::Result& result,
                                const Botan::Private_Key& key,
                                const Botan::Public_Key& pub,
                                const AlgoTestConfig& config,
                                const std::string& opt_name) {
         result.test_no_throw(opt_name + " accepted", [&] {
            const auto opts = with_added_option(make_baseline(config), opt_name);
            Botan::PK_Signer signer(key, rng(), opts);
            Botan::PK_Verifier verifier(pub, with_added_option(make_baseline(config), opt_name));

            const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};
            auto sig = signer.sign_message(message, rng());
            result.test_is_true(opt_name + " sign/verify", verifier.verify_message(message, sig));
         });
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

}  // namespace

}  // namespace Botan_Tests

#endif
