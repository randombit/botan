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
   #include <botan/ffi_tls.h>
   #include <string>
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

#endif

}  // namespace

}  // namespace Botan_Tests
