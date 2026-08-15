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
   #include <botan/internal/fmt.h>
   #include <botan/internal/pk_options_impl.h>
   #include <algorithm>
   #include <array>
   #include <optional>

namespace Botan_Tests {

namespace {

/*
* Every option which can be set on a PK_Encryption_Options
*
* Each section in the data file must either use an option in its baseline
* (Padding/Hash) or state via Supports<Option> whether it is accepted, so that
* adding a new option without deciding its status for every algorithm fails
* here rather than being silently ignored somewhere.
*/
constexpr std::array<std::string_view, 4> ALL_ENC_OPTIONS = {"Padding", "Hash", "MGF1Hash", "Context"};

Botan::PK_Encryption_Options with_added_option(Botan::PK_Encryption_Options baseline, std::string_view option) {
   if(option == "Padding") {
      return baseline.with_padding("PKCS1v15");
   }
   if(option == "Hash") {
      return baseline.with_hash("SHA-256");
   }
   if(option == "MGF1Hash") {
      return baseline.with_mgf1_hash("SHA-512");
   }
   if(option == "Context") {
      return baseline.with_context("test label");
   }
   throw Test_Error(std::string("Unknown option name: '") + std::string(option) + "'");
}

/*
* Decryptor options which conflict with a ciphertext created using the given
* option; decrypting with these must fail, otherwise the option was accepted
* by the encryptor but not actually applied.
*/
std::optional<Botan::PK_Encryption_Options> conflicting_decryptor_options(Botan::PK_Encryption_Options baseline,
                                                                          std::string_view option) {
   if(option == "Context") {
      return baseline.with_context("a different label");
   }
   if(option == "MGF1Hash") {
      return baseline.with_mgf1_hash("SHA-384");
   }
   if(option == "Hash") {
      // The baseline itself does not use the option
      return baseline;
   }
   return std::nullopt;
}

class PK_Encryption_Options_Test final : public Text_Based_Test {
   public:
      PK_Encryption_Options_Test() :
            // SupportsContext is the last key of each block, and so triggers the test
            Text_Based_Test("pubkey/pk_enc_options.vec",
                            "KeyParams,SupportsContext",
                            "Padding,Hash,SupportsPadding,SupportsHash,SupportsMGF1Hash") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("PK_Enc_Options " + header);

         const std::string padding = vars.get_opt_str("Padding", "");
         const std::string hash = vars.get_opt_str("Hash", "");

         for(const auto option_sv : ALL_ENC_OPTIONS) {
            const std::string option(option_sv);
            const bool in_baseline = (option == "Padding" && !padding.empty()) || (option == "Hash" && !hash.empty());
            if(!in_baseline && !vars.has_key("Supports" + option)) {
               throw Test_Error(Botan::fmt("[{}] does not state if option {} is supported", header, option));
            }
         }

         // For entries like "RSA/OAEP", use just "RSA" for key generation
         auto key_algo = header;
         if(auto slash = key_algo.find('/'); slash != std::string::npos) {
            key_algo = key_algo.substr(0, slash);
         }

         std::unique_ptr<Botan::Private_Key> key;
         try {
            key = Botan::create_private_key(key_algo, rng(), vars.get_req_str("KeyParams"));
         } catch(const Botan::Lookup_Error&) {
            result.test_note("Skipping - algorithm not available");
            return result;
         }

         if(!key) {
            result.test_note("Skipping - algorithm not available");
            return result;
         }

         const auto pub = key->public_key();

         auto make_baseline = [&]() { return Botan::PK_Encryption_Options().with_padding(padding).with_hash(hash); };

         const std::vector<uint8_t> message = {0x61, 0x62, 0x63, 0x64};

         // If the baseline itself is not available in this build (eg the padding
         // scheme was disabled) there is nothing further to test
         try {
            const Botan::PK_Encryptor_EME enc(*pub, rng(), make_baseline());
            const Botan::PK_Decryptor_EME dec(*key, rng(), make_baseline());
            const auto ctext = enc.encrypt(message, rng());
            result.test_bin_eq("Baseline roundtrip", dec.decrypt(ctext), message);
         } catch(const Botan::Lookup_Error& e) {
            result.test_note(std::string("Skipping - baseline not available in this build: ") + e.what());
            return result;
         } catch(const Botan::Not_Implemented& e) {
            result.test_note(std::string("Skipping - baseline not available in this build: ") + e.what());
            return result;
         } catch(const std::exception& e) {
            result.test_failure("Baseline encrypt/decrypt", e.what());
            return result;
         }

         for(const auto opt_name_sv : ALL_ENC_OPTIONS) {
            const std::string opt_name(opt_name_sv);
            if(!vars.has_key("Supports" + opt_name)) {
               continue;
            }

            const bool supported = vars.get_req_bool("Supports" + opt_name);

            if(supported) {
               result.test_no_throw(opt_name + " accepted", [&] {
                  const Botan::PK_Encryptor_EME enc(*pub, rng(), with_added_option(make_baseline(), opt_name));
                  const Botan::PK_Decryptor_EME dec(*key, rng(), with_added_option(make_baseline(), opt_name));
                  const auto ctext = enc.encrypt(message, rng());
                  result.test_bin_eq(opt_name + " roundtrip", dec.decrypt(ctext), message);

                  // Now check that the option actually took effect
                  if(auto conflicting = conflicting_decryptor_options(make_baseline(), opt_name)) {
                     bool rejected = false;
                     try {
                        const Botan::PK_Decryptor_EME other_dec(*key, rng(), *conflicting);
                        const auto ptext = other_dec.decrypt(ctext);
                        rejected = !std::equal(ptext.begin(), ptext.end(), message.begin(), message.end());
                     } catch(Botan::Exception&) {
                        rejected = true;
                     }
                     result.test_is_true(opt_name + " is applied (conflicting decryptor fails)", rejected);
                  }
               });
            } else {
               const auto opts = with_added_option(make_baseline(), opt_name);
               result.test_throws(opt_name + " rejected by encryptor",
                                  [&] { Botan::PK_Encryptor_EME(*pub, rng(), opts); });
               result.test_throws(opt_name + " rejected by decryptor",
                                  [&] { Botan::PK_Decryptor_EME(*key, rng(), opts); });
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_enc_options", PK_Encryption_Options_Test);

class PK_KEM_Options_Test final : public Text_Based_Test {
   public:
      PK_KEM_Options_Test() : Text_Based_Test("pubkey/pk_kem_options.vec", "KeyParams,RawSharedKeyByDefault") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("PK_KEM_Options " + header);

         std::unique_ptr<Botan::Private_Key> key;
         try {
            key = Botan::create_private_key(header, rng(), vars.get_req_str("KeyParams"));
         } catch(const Botan::Lookup_Error&) {
            result.test_note("Skipping - algorithm not available");
            return result;
         }

         if(!key) {
            result.test_note("Skipping - algorithm not available");
            return result;
         }

         const auto pub = key->public_key();

         auto roundtrip = [&](const Botan::PK_KEM_Options& options,
                              size_t desired_len = 32) -> std::optional<Botan::secure_vector<uint8_t>> {
            Botan::PK_KEM_Encryptor enc(*pub, options);
            Botan::PK_KEM_Decryptor dec(*key, rng(), options);
            const auto encap = enc.encrypt(rng(), desired_len);
            auto shared = dec.decrypt(encap.encapsulated_shared_key(), desired_len);
            if(shared != encap.shared_key()) {
               return std::nullopt;
            }
            return shared;
         };

         const bool raw_by_default = vars.get_req_bool("RawSharedKeyByDefault");

         std::optional<Botan::secure_vector<uint8_t>> raw_key;
         result.test_no_throw("Explicit raw shared key accepted", [&] {
            raw_key = roundtrip(Botan::PK_KEM_Options().with_raw_shared_key());
            result.test_is_true("Raw shared key roundtrip", raw_key.has_value());
         });

         if(raw_by_default) {
            result.test_no_throw("No options gives the raw shared key", [&] {
               const auto default_key = roundtrip(Botan::PK_KEM_Options());
               result.test_is_true("Default roundtrip", default_key.has_value());
               if(default_key && raw_key) {
                  result.test_sz_eq(
                     "Default and raw shared keys have same length", default_key->size(), raw_key->size());
               }
            });
         } else {
            result.test_throws("No options rejected as no KDF was specified",
                               [&] { const Botan::PK_KEM_Encryptor enc(*pub, Botan::PK_KEM_Options()); });
            result.test_throws("No options rejected by decryptor",
                               [&] { const Botan::PK_KEM_Decryptor dec(*key, rng(), Botan::PK_KEM_Options()); });
         }

         result.test_no_throw("KDF accepted", [&] {
            const auto kdf_key = roundtrip(Botan::PK_KEM_Options().with_kdf("HKDF(SHA-256)"), 48);
            result.test_is_true("KDF roundtrip", kdf_key.has_value());
            if(kdf_key) {
               result.test_sz_eq("KDF output has requested length", kdf_key->size(), 48);
            }

            // Different KDFs must give different keys, ie the option is applied
            const auto other_kdf_key = roundtrip(Botan::PK_KEM_Options().with_kdf("HKDF(SHA-512)"), 48);
            result.test_is_true("Other KDF roundtrip", other_kdf_key.has_value());
            if(kdf_key && other_kdf_key) {
               result.test_is_true("Different KDFs give different keys", *kdf_key != *other_kdf_key);
            }
         });

         result.test_throws("Unknown KDF rejected", [&] {
            const Botan::PK_KEM_Encryptor enc(*pub, Botan::PK_KEM_Options().with_kdf("NoSuchKDF"));
         });

         // The string interface never allowed omitting the KDF, even for KEMs
         // which return the raw shared key by default
         result.test_throws<Botan::Invalid_Argument>("Legacy empty KDF string rejected by encryptor",
                                                     [&] { const Botan::PK_KEM_Encryptor enc(*pub, ""); });
         result.test_throws<Botan::Invalid_Argument>("Legacy empty KDF string rejected by decryptor",
                                                     [&] { const Botan::PK_KEM_Decryptor dec(*key, rng(), ""); });

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_kem_options", PK_KEM_Options_Test);

   #if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_EME_OAEP) && defined(BOTAN_HAS_EME_PKCS1) && \
      defined(BOTAN_HAS_EME_RAW)

/*
* RSA encryption must never fall back to raw or hashless padding when options are missing
*/
class PK_Encryption_Options_RSA_Explicit_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Encryption_Options RSA requires explicit padding");

         auto key = Botan::create_private_key("RSA", rng(), "1024");
         if(!key) {
            result.test_note("Skipping - RSA not available");
            return {result};
         }
         const auto pub = key->public_key();

         auto rejected = [&](const std::string& what, const Botan::PK_Encryption_Options& opts) {
            result.test_throws(what + " rejected by encryptor", [&] { Botan::PK_Encryptor_EME(*pub, rng(), opts); });
            result.test_throws(what + " rejected by decryptor", [&] { Botan::PK_Decryptor_EME(*key, rng(), opts); });
         };

         rejected("No options", Botan::PK_Encryption_Options());
         rejected("Hash without padding", Botan::PK_Encryption_Options().with_hash("SHA-256"));
         rejected("OAEP without hash", Botan::PK_Encryption_Options().with_padding("OAEP"));
         rejected("OAEP with unknown hash",
                  Botan::PK_Encryption_Options().with_padding("OAEP").with_hash("NoSuchHash"));
         rejected(
            "OAEP with unknown MGF1 hash",
            Botan::PK_Encryption_Options().with_padding("OAEP").with_hash("SHA-256").with_mgf1_hash("NoSuchHash"));
         rejected("Unknown padding", Botan::PK_Encryption_Options().with_padding("NoSuchPadding"));

         // The unexamined option error names the option
         try {
            const Botan::PK_Encryptor_EME enc(
               *pub, rng(), Botan::PK_Encryption_Options().with_padding("Raw").with_context("x"));
            result.test_failure("Raw padding accepted a label");
         } catch(Botan::Invalid_Argument& e) {
            result.test_is_true(
               "Error names the unexamined option",
               std::string(e.what()).find("does not support the encryption option(s): context") != std::string::npos);
         }

         // Legacy strings still work and map onto the same options
         result.test_no_throw("Legacy OAEP string with label", [&] {
            const Botan::PK_Encryptor_EME enc(*pub, rng(), "OAEP(SHA-256,MGF1,label)");
            const Botan::PK_Decryptor_EME dec(
               *key,
               rng(),
               Botan::PK_Encryption_Options().with_padding("OAEP").with_hash("SHA-256").with_context("label"));
            const std::vector<uint8_t> msg(16, 0x42);
            result.test_bin_eq("Legacy label roundtrip", dec.decrypt(enc.encrypt(msg, rng())), msg);
         });

         result.test_no_throw("Legacy OAEP string with distinct MGF1 hash", [&] {
            const Botan::PK_Encryptor_EME enc(*pub, rng(), "OAEP(SHA-256,MGF1(SHA-1))");
            const Botan::PK_Decryptor_EME dec(
               *key,
               rng(),
               Botan::PK_Encryption_Options().with_padding("OAEP").with_hash("SHA-256").with_mgf1_hash("SHA-1"));
            const std::vector<uint8_t> msg(16, 0x42);
            result.test_bin_eq("Legacy MGF1 roundtrip", dec.decrypt(enc.encrypt(msg, rng())), msg);
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_enc_options_rsa_explicit", PK_Encryption_Options_RSA_Explicit_Test);

   #endif

class PK_KEM_Options_Builder_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_KEM_Options builder");

         result.test_throws("KDF and raw shared key are exclusive (kdf first)",
                            [] { Botan::PK_KEM_Options().with_kdf("HKDF(SHA-256)").with_raw_shared_key(); });
         result.test_throws("KDF and raw shared key are exclusive (raw first)",
                            [] { Botan::PK_KEM_Options().with_raw_shared_key().with_kdf("HKDF(SHA-256)"); });

         result.test_throws<Botan::Invalid_Argument>("Empty KDF name rejected",
                                                     [] { Botan::PK_KEM_Options().with_kdf(""); });

         result.test_throws<Botan::Invalid_State>("Raw shared key twice rejected", [] {
            Botan::PK_KEM_Options().with_raw_shared_key().with_raw_shared_key();
         });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_kem_options_builder", PK_KEM_Options_Builder_Test);

class PK_Key_Agreement_Options_Test final : public Text_Based_Test {
   public:
      PK_Key_Agreement_Options_Test() : Text_Based_Test("pubkey/pk_ka_options.vec", "KeyParams") {}

      bool clear_between_callbacks() const override { return false; }

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("PK_Key_Agreement_Options " + header);

         std::unique_ptr<Botan::Private_Key> key_a;
         std::unique_ptr<Botan::Private_Key> key_b;
         try {
            key_a = Botan::create_private_key(header, rng(), vars.get_req_str("KeyParams"));
            key_b = Botan::create_private_key(header, rng(), vars.get_req_str("KeyParams"));
         } catch(const Botan::Lookup_Error&) {
            result.test_note("Skipping - algorithm not available");
            return result;
         }

         if(!key_a || !key_b) {
            result.test_note("Skipping - algorithm not available");
            return result;
         }

         const auto* ka_key_a = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(key_a.get());
         const auto* ka_key_b = dynamic_cast<const Botan::PK_Key_Agreement_Key*>(key_b.get());
         if(ka_key_a == nullptr || ka_key_b == nullptr) {
            result.test_failure("Not a key agreement key");
            return result;
         }

         // Both sides must derive the same key, which is returned
         auto agree = [&](const Botan::PK_Key_Agreement_Options& options,
                          size_t desired_len = 32) -> std::optional<Botan::secure_vector<uint8_t>> {
            const Botan::PK_Key_Agreement ka_a(*key_a, rng(), options);
            const Botan::PK_Key_Agreement ka_b(*key_b, rng(), options);
            auto shared_a = ka_a.derive_key(desired_len, ka_key_b->public_value()).bits_of();
            auto shared_b = ka_b.derive_key(desired_len, ka_key_a->public_value()).bits_of();
            if(shared_a != shared_b) {
               return std::nullopt;
            }
            return shared_a;
         };

         // The agreed value is not a uniform key, so it must be asked for explicitly
         result.test_throws<Botan::Invalid_Argument>("No options rejected as no KDF was specified", [&] {
            const Botan::PK_Key_Agreement ka(*key_a, rng(), Botan::PK_Key_Agreement_Options());
         });

         std::optional<Botan::secure_vector<uint8_t>> raw_key;
         result.test_no_throw("Explicit raw shared key accepted", [&] {
            raw_key = agree(Botan::PK_Key_Agreement_Options().with_raw_shared_key());
            result.test_is_true("Raw shared key roundtrip", raw_key.has_value());
            if(raw_key) {
               const Botan::PK_Key_Agreement ka(*key_a, rng(), Botan::PK_Key_Agreement_Options().with_raw_shared_key());
               result.test_sz_eq("Raw shared key has the agreed value size", raw_key->size(), ka.agreed_value_size());
            }
         });

         result.test_no_throw("KDF accepted", [&] {
            const auto kdf_key = agree(Botan::PK_Key_Agreement_Options().with_kdf("HKDF(SHA-256)"), 48);
            result.test_is_true("KDF roundtrip", kdf_key.has_value());
            if(kdf_key) {
               result.test_sz_eq("KDF output has requested length", kdf_key->size(), 48);
            }

            // Different KDFs must give different keys, ie the option is applied
            const auto other_kdf_key = agree(Botan::PK_Key_Agreement_Options().with_kdf("HKDF(SHA-512)"), 48);
            result.test_is_true("Other KDF roundtrip", other_kdf_key.has_value());
            if(kdf_key && other_kdf_key) {
               result.test_is_true("Different KDFs give different keys", *kdf_key != *other_kdf_key);
            }
         });

         result.test_throws("Unknown KDF rejected", [&] {
            const Botan::PK_Key_Agreement ka(*key_a, rng(), Botan::PK_Key_Agreement_Options().with_kdf("NoSuchKDF"));
         });

         result.test_throws("Unknown provider rejected", [&] {
            const Botan::PK_Key_Agreement ka(
               *key_a, rng(), Botan::PK_Key_Agreement_Options().with_raw_shared_key().with_provider("NoSuchProvider"));
         });

         // The string interface never allowed omitting the KDF
         result.test_throws<Botan::Invalid_Argument>("Legacy empty KDF string rejected",
                                                     [&] { const Botan::PK_Key_Agreement ka(*key_a, rng(), ""); });

         result.test_no_throw("Legacy Raw string matches raw option", [&] {
            const Botan::PK_Key_Agreement ka(*key_a, rng(), "Raw");
            const auto legacy_raw = ka.derive_key(0, ka_key_b->public_value()).bits_of();
            if(raw_key) {
               result.test_bin_eq("Legacy Raw agrees with with_raw_shared_key", legacy_raw, *raw_key);
            }
         });

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_ka_options", PK_Key_Agreement_Options_Test);

class PK_Key_Agreement_Options_Builder_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("PK_Key_Agreement_Options builder");

         result.test_throws<Botan::Invalid_State>("KDF and raw shared key are exclusive (kdf first)", [] {
            Botan::PK_Key_Agreement_Options().with_kdf("HKDF(SHA-256)").with_raw_shared_key();
         });
         result.test_throws<Botan::Invalid_State>("KDF and raw shared key are exclusive (raw first)", [] {
            Botan::PK_Key_Agreement_Options().with_raw_shared_key().with_kdf("HKDF(SHA-256)");
         });
         result.test_throws<Botan::Invalid_State>("KDF twice rejected", [] {
            Botan::PK_Key_Agreement_Options().with_kdf("HKDF(SHA-256)").with_kdf("HKDF(SHA-256)");
         });
         result.test_throws<Botan::Invalid_State>("Raw shared key twice rejected", [] {
            Botan::PK_Key_Agreement_Options().with_raw_shared_key().with_raw_shared_key();
         });
         result.test_throws<Botan::Invalid_Argument>("Empty KDF name rejected",
                                                     [] { Botan::PK_Key_Agreement_Options().with_kdf(""); });

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_ka_options_builder", PK_Key_Agreement_Options_Builder_Test);

/*
* Keys held in hardware have exactly one implementation; "base" names the
* software implementation and so is not available for them
*/
class PK_Options_Hardware_Provider_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Hardware provider selection");

         auto check = [&](const auto& options, bool expect_ok, const std::string& what) {
            if(expect_ok) {
               result.test_no_throw(what + " accepted",
                                    [&] { Botan::require_hardware_provider(options, "RSA", "pkcs11"); });
            } else {
               result.test_throws<Botan::Provider_Not_Found>(
                  what + " rejected", [&] { Botan::require_hardware_provider(options, "RSA", "pkcs11"); });
            }
         };

         check(Botan::PK_Signature_Options(), true, "Unset provider");
         check(Botan::PK_Signature_Options().with_provider("pkcs11"), true, "Own provider");
         check(Botan::PK_Signature_Options().with_provider("base"), false, "Software provider");
         check(Botan::PK_Signature_Options().with_provider("tpm2"), false, "Other hardware provider");
         check(Botan::PK_Encryption_Options().with_provider("base"), false, "Software provider for encryption");
         check(Botan::PK_KEM_Options().with_provider("base"), false, "Software provider for KEM");
         check(Botan::PK_Key_Agreement_Options().with_provider("base"), false, "Software provider for key agreement");

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "pk_options_hardware_provider", PK_Options_Hardware_Provider_Test);

}  // namespace

}  // namespace Botan_Tests

#endif
