/*
* (C) 2026 Moritz Schmitt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_FFI)
   #include <botan/ffi.h>
#endif

#if defined(BOTAN_HAS_FFI_TLS)
   #include <botan/certstor.h>
   #include <botan/ffi_tls.h>
   #include <botan/pk_keys.h>
   #include <botan/tls_session_manager_memory.h>
   #include <botan/tls_session_manager_noop.h>
   #include <botan/x509cert.h>
   #include <botan/internal/ffi_tls_impl.h>
   #include <memory>
   #include <string>
   #include <vector>
#endif

#if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
   #include <botan/certstor_system.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_FFI)

// NOLINTBEGIN(*-macro-usage)

   #define TEST_FFI_STR_HELPER(x) #x

   #define TEST_FFI_STR(x) TEST_FFI_STR_HELPER(x)

   #define TEST_FFI_SOURCE_LOCATION(func, file, line) (func " invoked at " file ":" TEST_FFI_STR(line))

   #define TEST_FFI_OK(func, args) result.test_rc_ok(TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), func args)

   #define TEST_FFI_RC(rc, func, args) \
      result.test_rc(TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), func args, rc)

   #define REQUIRE_FFI_OK(func, args)                           \
      if(!TEST_FFI_OK(func, args)) {                            \
         result.test_note("Exiting test early due to failure"); \
         return result;                                         \
      }

// NOLINTEND(*-macro-usage)

class FFI_TLS_Version_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("FFI TLS API version");

         const uint32_t version = botan_ffi_tls_api_version();

   #if defined(BOTAN_HAS_FFI_TLS)
         result.test_u32_eq("TLS API version matches BOTAN_HAS_FFI_TLS", version, BOTAN_HAS_FFI_TLS);
         result.test_u32_eq("TLS API version matches BOTAN_FFI_TLS_API_VERSION", version, BOTAN_FFI_TLS_API_VERSION);
         result.test_i32_eq("Current TLS API version is supported", botan_ffi_tls_supports_api(version), 0);
         result.test_i32_eq("Other TLS API version is not supported", botan_ffi_tls_supports_api(version + 1), -1);
   #else
         result.test_u32_eq("TLS API version is 0 without the ffi_tls module", version, 0);
   #endif

         result.test_i32_eq("TLS API version 0 is never supported", botan_ffi_tls_supports_api(0), -1);

         return {result};
      }
};

BOTAN_REGISTER_TEST("ffi", "ffi_tls_version", FFI_TLS_Version_Test);

#endif

#if defined(BOTAN_HAS_FFI_TLS)

int view_string_fn(void* ctx, const char* str, size_t len) {
   if(ctx == nullptr || str == nullptr || len == 0) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   // discard the null terminator
   *static_cast<std::string*>(ctx) = std::string(str, len - 1);
   return BOTAN_FFI_SUCCESS;
}

class FFI_TLS_Policy_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         return {test_stock_policies(), test_text_policy(), test_error_handling()};
      }

   private:
      static Test::Result test_stock_policies() {
         Test::Result result("FFI TLS stock policies");

         botan_tls_policy_t policy = nullptr;
         std::string default_text;

         REQUIRE_FFI_OK(botan_tls_policy_init, (&policy, "default"));
         result.test_not_null("Default policy handle", policy);
         TEST_FFI_OK(botan_tls_policy_view_text, (policy, &default_text, view_string_fn));
         result.test_str_not_empty("Default policy text", default_text);
         result.test_str_contains(
            "Default policy text uses Text_Policy keys", default_text, "minimum_signature_strength = ");
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         std::string null_name_text;
         REQUIRE_FFI_OK(botan_tls_policy_init, (&policy, nullptr));
         TEST_FFI_OK(botan_tls_policy_view_text, (policy, &null_name_text, view_string_fn));
         result.test_str_eq("NULL name selects the default policy", null_name_text, default_text);
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         std::string strict_text;
         REQUIRE_FFI_OK(botan_tls_policy_init, (&policy, "strict"));
         TEST_FFI_OK(botan_tls_policy_view_text, (policy, &strict_text, view_string_fn));
         result.test_str_ne("Strict policy differs from the default policy", strict_text, default_text);
         result.test_str_contains(
            "Strict policy restricts signature hashes", strict_text, "signature_hashes = SHA-512 SHA-384\n");
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         std::string bsi_text;
         REQUIRE_FFI_OK(botan_tls_policy_init, (&policy, "bsi_tr_02102_2"));
         TEST_FFI_OK(botan_tls_policy_view_text, (policy, &bsi_text, view_string_fn));
         result.test_str_ne("BSI policy differs from the default policy", bsi_text, default_text);
         result.test_str_contains(
            "BSI policy restricts signature hashes", bsi_text, "signature_hashes = SHA-512 SHA-384 SHA-256\n");
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         return result;
      }

      static Test::Result test_text_policy() {
         Test::Result result("FFI TLS text policy");

         botan_tls_policy_t policy = nullptr;
         std::string default_text;
         std::string text;

         REQUIRE_FFI_OK(botan_tls_policy_init, (&policy, "default"));
         TEST_FFI_OK(botan_tls_policy_view_text, (policy, &default_text, view_string_fn));
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         REQUIRE_FFI_OK(botan_tls_policy_init_from_text, (&policy, "# only a comment\n"));
         TEST_FFI_OK(botan_tls_policy_view_text, (policy, &text, view_string_fn));
         result.test_str_eq("Empty text policy equals the default policy", text, default_text);
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         REQUIRE_FFI_OK(botan_tls_policy_init_from_text,
                        (&policy, "hash_hello_random = false\nminimum_signature_strength = 128 # bits\n"));
         TEST_FFI_OK(botan_tls_policy_view_text, (policy, &text, view_string_fn));
         result.test_str_contains("Default policy hashes the hello random", default_text, "hash_hello_random = true\n");
         result.test_str_contains("Text policy overrides hash_hello_random", text, "hash_hello_random = false\n");
         result.test_str_contains(
            "Text policy overrides minimum_signature_strength", text, "minimum_signature_strength = 128\n");
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         return result;
      }

      static Test::Result test_error_handling() {
         Test::Result result("FFI TLS policy error handling");

         botan_tls_policy_t policy = nullptr;
         std::string text;

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_policy_init, (nullptr, "default"));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_policy_init_from_text, (nullptr, ""));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_policy_init_from_text, (&policy, nullptr));
         result.test_is_true("Handle stays NULL after NULL pointer error", policy == nullptr);

         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_tls_policy_init, (&policy, "nsa_suite_b_192"));
         result.test_is_true("Handle is NULL after unknown policy name", policy == nullptr);

         TEST_FFI_RC(BOTAN_FFI_ERROR_INVALID_INPUT, botan_tls_policy_init_from_text, (&policy, "not a policy\n"));
         result.test_is_true("Handle is NULL after malformed policy text", policy == nullptr);

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_policy_view_text, (nullptr, &text, view_string_fn));

         REQUIRE_FFI_OK(botan_tls_policy_init, (&policy, "default"));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_policy_view_text, (policy, &text, nullptr));
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         TEST_FFI_OK(botan_tls_policy_destroy, (nullptr));

         return result;
      }
};

BOTAN_REGISTER_TEST("ffi", "ffi_tls_policy", FFI_TLS_Policy_Test);

class FFI_TLS_Credentials_Test final : public Test {
   public:
      std::vector<Test::Result> run() override { return {test_credentials_api(), test_chain_selection()}; }

   private:
      static Test::Result test_credentials_api() {
         Test::Result result("FFI TLS credentials");

         botan_tls_credentials_t creds = nullptr;

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_init, (nullptr));
         REQUIRE_FFI_OK(botan_tls_credentials_init, (&creds));
         result.test_not_null("Credentials handle", creds);

         botan_x509_cert_t root = nullptr;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&root, Test::data_file("x509/nist/root.crt").c_str()));
         TEST_FFI_OK(botan_tls_credentials_add_trusted_cert, (creds, root));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_trusted_cert, (creds, nullptr));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_trusted_cert, (nullptr, root));
         TEST_FFI_OK(botan_x509_cert_destroy, (root));

         botan_x509_crl_t crl = nullptr;
         REQUIRE_FFI_OK(botan_x509_crl_load_file, (&crl, Test::data_file("x509/nist/root.crl").c_str()));
         TEST_FFI_OK(botan_tls_credentials_add_crl, (creds, crl));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_crl, (creds, nullptr));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_crl, (nullptr, crl));
         TEST_FFI_OK(botan_x509_crl_destroy, (crl));

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_trusted_dir, (creds, nullptr));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_trusted_dir, (nullptr, "."));
   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
         TEST_FFI_OK(botan_tls_credentials_add_trusted_dir, (creds, Test::data_file("x509/crl").c_str()));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER,
                     botan_tls_credentials_add_trusted_dir,
                     (creds, Test::data_file("x509/does-not-exist").c_str()));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_tls_credentials_add_trusted_dir, (creds, ""));
   #else
         TEST_FFI_RC(BOTAN_FFI_ERROR_NOT_IMPLEMENTED, botan_tls_credentials_add_trusted_dir, (creds, "."));
   #endif

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_use_system_store, (nullptr));
   #if defined(BOTAN_HAS_CERTSTOR_SYSTEM)
         bool system_store_available = false;
         try {
            const Botan::System_Certificate_Store store;
            system_store_available = true;
         } catch(std::exception&) {}

         if(system_store_available) {
            TEST_FFI_OK(botan_tls_credentials_use_system_store, (creds));
         } else {
            result.test_note("No system certificate store available on this system");
            result.test_is_true("use_system_store fails without a system store",
                                botan_tls_credentials_use_system_store(creds) < 0);
         }
   #else
         TEST_FFI_RC(BOTAN_FFI_ERROR_NOT_IMPLEMENTED, botan_tls_credentials_use_system_store, (creds));
   #endif

         botan_x509_cert_t cert1 = nullptr;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&cert1, Test::data_file("x509/certstor/cert1.crt").c_str()));

         const auto key01_pem = Test::read_binary_data_file("x509/certstor/key01.pem");
         const auto key03_pem = Test::read_binary_data_file("x509/certstor/key03.pem");
         botan_privkey_t key01 = nullptr;
         botan_privkey_t key03 = nullptr;
         REQUIRE_FFI_OK(botan_privkey_load, (&key01, nullptr, key01_pem.data(), key01_pem.size(), nullptr));
         REQUIRE_FFI_OK(botan_privkey_load, (&key03, nullptr, key03_pem.data(), key03_pem.size(), nullptr));

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_cert_chain, (nullptr, &cert1, 1, key01));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_cert_chain, (creds, nullptr, 1, key01));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_cert_chain, (creds, &cert1, 1, nullptr));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_tls_credentials_add_cert_chain, (creds, &cert1, 0, key01));

         const botan_x509_cert_t chain_with_null[2] = {cert1, nullptr};
         TEST_FFI_RC(
            BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_credentials_add_cert_chain, (creds, chain_with_null, 2, key01));

         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_tls_credentials_add_cert_chain, (creds, &cert1, 1, key03));
         TEST_FFI_OK(botan_tls_credentials_add_cert_chain, (creds, &cert1, 1, key01));

         TEST_FFI_OK(botan_privkey_destroy, (key01));
         TEST_FFI_OK(botan_privkey_destroy, (key03));
         TEST_FFI_OK(botan_x509_cert_destroy, (cert1));

         // The inputs were copied, so the credentials are complete although
         // every handle passed to the setters has been destroyed.
         auto& mgr = *Botan_FFI::safe_get(creds);
         const Botan::X509_Certificate leaf(Test::data_file("x509/certstor/cert1.crt"));
         const auto chain = mgr.find_cert_chain({"RSA"}, {}, {}, "tls-server", "");
         result.test_sz_eq("Chain is found after the handles were destroyed", chain.size(), 1);
         const auto key = mgr.private_key_for(leaf, "tls-server", "");
         result.test_not_null("Key is found after the handles were destroyed", key);

         TEST_FFI_OK(botan_tls_credentials_destroy, (creds));
         TEST_FFI_OK(botan_tls_credentials_destroy, (nullptr));

         return result;
      }

      static Test::Result test_chain_selection() {
         Test::Result result("FFI TLS credentials chain selection");

         botan_tls_credentials_t creds = nullptr;
         REQUIRE_FFI_OK(botan_tls_credentials_init, (&creds));

         // Before anything is added there is exactly one (empty) trust store
         auto& mgr = *Botan_FFI::safe_get(creds);
         auto stores = mgr.trusted_certificate_authorities("tls-client", "");
         result.test_sz_eq("One store on a fresh object", stores.size(), 1);
         if(stores.size() == 1) {
            result.test_is_true("The store is empty", stores[0]->all_subjects().empty());
         }

         botan_x509_cert_t root = nullptr;
         botan_x509_crl_t crl = nullptr;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&root, Test::data_file("x509/nist/root.crt").c_str()));
         REQUIRE_FFI_OK(botan_x509_crl_load_file, (&crl, Test::data_file("x509/nist/root.crl").c_str()));
         TEST_FFI_OK(botan_tls_credentials_add_trusted_cert, (creds, root));
         TEST_FFI_OK(botan_tls_credentials_add_crl, (creds, crl));
         TEST_FFI_OK(botan_x509_cert_destroy, (root));
         TEST_FFI_OK(botan_x509_crl_destroy, (crl));

         stores = mgr.trusted_certificate_authorities("tls-server", "");
         result.test_sz_eq("Still one store", stores.size(), 1);
         if(stores.size() == 1) {
            result.test_sz_eq("Trust anchor was added", stores[0]->all_subjects().size(), 1);
            const Botan::X509_Certificate end_entity(Test::data_file("x509/nist/test01/end.crt"));
            result.test_is_true("CRL of the issuer is found", stores[0]->find_crl_for(end_entity).has_value());
            result.test_is_true(
               "Trust anchor is found",
               stores[0]->find_cert(end_entity.issuer_dn(), end_entity.authority_key_id()).has_value());
         }

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
         TEST_FFI_OK(botan_tls_credentials_add_trusted_dir, (creds, Test::data_file("x509/crl").c_str()));
         stores = mgr.trusted_certificate_authorities("tls-client", "");
         result.test_sz_eq("Directory store was added", stores.size(), 2);
         if(stores.size() == 2) {
            result.test_sz_eq("Directory store holds the certificates", stores[1]->all_subjects().size(), 3);
         }
   #endif

         // Two RSA chains with the same key: CN=cert1 and CN=cert2, both
         // self-signed, so each is issued by a different "CA"
         botan_x509_cert_t cert1 = nullptr;
         botan_x509_cert_t cert2 = nullptr;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&cert1, Test::data_file("x509/certstor/cert1.crt").c_str()));
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&cert2, Test::data_file("x509/certstor/cert2.crt").c_str()));
         const auto key01_pem = Test::read_binary_data_file("x509/certstor/key01.pem");
         botan_privkey_t key01 = nullptr;
         REQUIRE_FFI_OK(botan_privkey_load, (&key01, nullptr, key01_pem.data(), key01_pem.size(), nullptr));
         TEST_FFI_OK(botan_tls_credentials_add_cert_chain, (creds, &cert1, 1, key01));
         TEST_FFI_OK(botan_tls_credentials_add_cert_chain, (creds, &cert2, 1, key01));
         TEST_FFI_OK(botan_privkey_destroy, (key01));
         TEST_FFI_OK(botan_x509_cert_destroy, (cert1));
         TEST_FFI_OK(botan_x509_cert_destroy, (cert2));

         const Botan::X509_Certificate leaf1(Test::data_file("x509/certstor/cert1.crt"));
         const Botan::X509_Certificate leaf2(Test::data_file("x509/certstor/cert2.crt"));
         const Botan::X509_Certificate unrelated(Test::data_file("x509/nist/root.crt"));

         const auto check_chain = [&](const std::string& what,
                                      const std::vector<Botan::X509_Certificate>& chain,
                                      const Botan::X509_Certificate& expected_leaf) {
            if(result.test_sz_eq(what + " (chain length)", chain.size(), 1)) {
               result.test_is_true(what, chain.front() == expected_leaf);
            }
         };

         // Key type filter
         check_chain("First chain without preferences", mgr.find_cert_chain({}, {}, {}, "tls-server", ""), leaf1);
         check_chain("First RSA chain", mgr.find_cert_chain({"RSA"}, {}, {}, "tls-server", ""), leaf1);
         check_chain(
            "Key type list may contain others", mgr.find_cert_chain({"ECDSA", "RSA"}, {}, {}, "tls-client", ""), leaf1);
         result.test_is_true("No chain for an unavailable key type",
                             mgr.find_cert_chain({"ECDSA"}, {}, {}, "tls-server", "").empty());

         // Server name preference (servers only)
         check_chain("Server prefers the chain matching the server name",
                     mgr.find_cert_chain({"RSA"}, {}, {}, "tls-server", "cert2"),
                     leaf2);
         check_chain("Server falls back to the first chain for an unknown name",
                     mgr.find_cert_chain({"RSA"}, {}, {}, "tls-server", "unknown.example"),
                     leaf1);
         check_chain(
            "Client ignores the server name", mgr.find_cert_chain({"RSA"}, {}, {}, "tls-client", "cert2"), leaf1);

         // Acceptable CA preference
         check_chain("Chain issued by an acceptable CA is preferred",
                     mgr.find_cert_chain({"RSA"}, {}, {leaf2.issuer_dn()}, "tls-client", ""),
                     leaf2);
         check_chain("Server also honors the acceptable CAs",
                     mgr.find_cert_chain({}, {}, {leaf2.issuer_dn()}, "tls-server", ""),
                     leaf2);
         check_chain("Falls back to the first chain if no CA matches",
                     mgr.find_cert_chain({"RSA"}, {}, {unrelated.subject_dn()}, "tls-client", ""),
                     leaf1);
         check_chain("A chain for the server name outranks the CA preference",
                     mgr.find_cert_chain({"RSA"}, {}, {leaf1.issuer_dn()}, "tls-server", "cert2"),
                     leaf2);
         result.test_is_true("No chain of another key type is offered when one matches the server name",
                             mgr.find_cert_chain({"ECDSA"}, {}, {}, "tls-server", "cert2").empty());

         // Private keys
         const auto key1 = mgr.private_key_for(leaf1, "tls-server", "");
         const auto key2 = mgr.private_key_for(leaf2, "tls-client", "");
         if(result.test_not_null("Key for the first leaf", key1) &&
            result.test_not_null("Key for the second leaf", key2)) {
            result.test_str_eq("Key algorithm", key1->algo_name(), "RSA");
            result.test_str_eq("Key belongs to the first leaf",
                               key1->public_key()->fingerprint_public(),
                               leaf1.subject_public_key()->fingerprint_public());
            result.test_str_eq("Key belongs to the second leaf",
                               key2->public_key()->fingerprint_public(),
                               leaf2.subject_public_key()->fingerprint_public());
         }
         result.test_is_true("No key for an unrelated certificate",
                             mgr.private_key_for(unrelated, "tls-server", "") == nullptr);

         TEST_FFI_OK(botan_tls_credentials_destroy, (creds));

         return result;
      }
};

BOTAN_REGISTER_TEST("ffi", "ffi_tls_credentials", FFI_TLS_Credentials_Test);

class FFI_TLS_Session_Manager_Test final : public Test {
   public:
      std::vector<Test::Result> run() override { return {test_session_managers()}; }

   private:
      static Test::Result test_session_managers() {
         Test::Result result("FFI TLS session managers");

         botan_tls_session_manager_t mgr = nullptr;

         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_session_manager_init_memory, (nullptr, nullptr, 0));
         TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_tls_session_manager_init_noop, (nullptr));

         REQUIRE_FFI_OK(botan_tls_session_manager_init_memory, (&mgr, nullptr, 0));
         result.test_not_null("In-memory manager with internal RNG", mgr);
         result.test_is_true(
            "Handle wraps Session_Manager_In_Memory",
            dynamic_cast<Botan::TLS::Session_Manager_In_Memory*>(Botan_FFI::safe_get(mgr).get()) != nullptr);
         TEST_FFI_OK(botan_tls_session_manager_destroy, (mgr));

         botan_rng_t rng = nullptr;
         REQUIRE_FFI_OK(botan_rng_init, (&rng, "user"));
         REQUIRE_FFI_OK(botan_tls_session_manager_init_memory, (&mgr, rng, 10));
         result.test_not_null("In-memory manager with borrowed RNG", mgr);
         TEST_FFI_OK(botan_tls_session_manager_destroy, (mgr));
         TEST_FFI_OK(botan_rng_destroy, (rng));

         REQUIRE_FFI_OK(botan_tls_session_manager_init_noop, (&mgr));
         result.test_not_null("Noop manager", mgr);
         result.test_is_true(
            "Handle wraps Session_Manager_Noop",
            dynamic_cast<Botan::TLS::Session_Manager_Noop*>(Botan_FFI::safe_get(mgr).get()) != nullptr);
         TEST_FFI_OK(botan_tls_session_manager_destroy, (mgr));

         TEST_FFI_OK(botan_tls_session_manager_destroy, (nullptr));

         return result;
      }
};

BOTAN_REGISTER_TEST("ffi", "ffi_tls_session_manager", FFI_TLS_Session_Manager_Test);

#endif

}  // namespace

}  // namespace Botan_Tests
