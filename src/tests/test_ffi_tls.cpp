/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_FFI_TLS)

   #include <botan/ffi.h>
   #include <botan/ffi_tls.h>

namespace Botan_Tests {

   #define TEST_FFI_OK(func, args) result.test_rc_ok(#func, func args)
   #define TEST_FFI_FAIL(msg, func, args) result.test_rc_fail(#func, msg, func args)
   #define TEST_FFI_RC(rc, func, args) result.test_rc(#func, rc, func args)

   #define REQUIRE_FFI_OK(func, args)                           \
      if(!TEST_FFI_OK(func, args)) {                            \
         result.test_note("Exiting test early due to failure"); \
         return result;                                         \
      }

class FFI_TLS_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_tls_policies());

         return results;
      }

   private:
      Test::Result test_tls_policies() {
         Test::Result result("FFI TLS policies");

         botan_tls_policy_t policy;
         TEST_FFI_OK(botan_tls_policy_default_init, (&policy));
         result.test_not_null("Default policy returned object", policy);
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         TEST_FFI_OK(botan_tls_policy_nsa_suiteb_init, (&policy));
         result.test_not_null("NSA policy returned object", policy);
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         TEST_FFI_OK(botan_tls_policy_bsi_tr_02102_2_init, (&policy));
         result.test_not_null("BSI policy returned object", policy);
         TEST_FFI_OK(botan_tls_policy_destroy, (policy));

         return result;
      }
};

BOTAN_REGISTER_TEST("ffi", "ffi_tls", FFI_TLS_Tests);

}  // namespace Botan_Tests

#endif
