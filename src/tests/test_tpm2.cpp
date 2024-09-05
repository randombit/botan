/*
* (C) 2024 Jack Lloyd
* (C) 2024 René Meusel, Amos Treiber Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#if defined(BOTAN_HAS_TPM2)
   #include <botan/pubkey.h>
   #include <botan/tpm2_session.h>

   #include <tss2/tss2_esys.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TPM2)
namespace {

std::shared_ptr<Botan::TPM2::Context> get_tpm2_context(std::string_view rng_tag) {
   const auto tcti_name = Test::options().tpm2_tcti_name();
   if(tcti_name.value() == "disabled") {
      // skip the test if the special 'disabled' TCTI is configured
      return {};
   }

   auto ctx = Botan::TPM2::Context::create(tcti_name, Test::options().tpm2_tcti_conf());
   if(ctx->vendor() != "SW   TPM" || ctx->manufacturer() != "IBM") {
      return {};
   }

   BOTAN_UNUSED(rng_tag);

   return ctx;
}

Test::Result bail_out() {
   Test::Result result("TPM2 test bail out");

   if(Test::options().tpm2_tcti_name() == "disabled") {
      result.test_note("TPM2 tests are disabled.");
      return result;
   } else {
      result.test_failure("Not sure we're on a simulated TPM2, cautiously refusing any action.");
      return result;
   }
}

std::vector<Test::Result> test_tpm2_properties() {
   auto ctx = get_tpm2_context(__func__);
   if(!ctx) {
      return {bail_out()};
   }

   return {
      CHECK("Vendor and Manufacturer",
            [&](Test::Result& result) {
               result.test_eq("Vendor", ctx->vendor(), "SW   TPM");
               result.test_eq("Manufacturer", ctx->manufacturer(), "IBM");
            }),

      CHECK("Max random bytes per request",
            [&](Test::Result& result) {
               const auto prop = ctx->max_random_bytes_per_request();
               result.test_gte("at least as long as SHA-256", prop, 32);
               result.test_lte("at most as long as SHA-512", prop, 64);
            }),

      CHECK("Supports basic algorithms",
            [&](Test::Result& result) {
               result.confirm("RSA is supported", ctx->supports_algorithm("RSA"));
               result.confirm("AES-128 is supported", ctx->supports_algorithm("AES-128"));
               result.confirm("AES-256 is supported", ctx->supports_algorithm("AES-256"));
               result.confirm("SHA-1 is supported", ctx->supports_algorithm("SHA-1"));
               result.confirm("SHA-256 is supported", ctx->supports_algorithm("SHA-256"));
               result.confirm("OFB(AES-128) is supported", ctx->supports_algorithm("OFB(AES-128)"));
               result.confirm("OFB is supported", ctx->supports_algorithm("OFB"));
            }),

      CHECK("Unsupported algorithms aren't supported",
            [&](Test::Result& result) {
               result.confirm("Enigma is not supported", !ctx->supports_algorithm("Enigma"));
               result.confirm("MD5 is not supported", !ctx->supports_algorithm("MD5"));
               result.confirm("DES is not supported", !ctx->supports_algorithm("DES"));
               result.confirm("OAEP(Keccak) is not supported", !ctx->supports_algorithm("OAEP(Keccak)"));
            }),
   };
}

std::vector<Test::Result> test_tpm2_context() {
   auto ctx = get_tpm2_context(__func__);
   if(!ctx) {
      return {bail_out()};
   }

   const auto persistent_key_id = Test::options().tpm2_persistent_rsa_handle();

   return {
      CHECK("Persistent handles",
            [&](Test::Result& result) {
               const auto handles = ctx->persistent_handles();
               result.confirm("At least one persistent handle", !handles.empty());
               result.confirm("SRK is in the list", Botan::value_exists(handles, 0x81000001));
               result.confirm("Test private key is in the list", Botan::value_exists(handles, persistent_key_id));
               result.confirm("Test persistence location is not in the list",
                              !Botan::value_exists(handles, persistent_key_id + 1));
            }),
   };
}

std::vector<Test::Result> test_tpm2_sessions() {
   auto ctx = get_tpm2_context(__func__);
   if(!ctx) {
      return {bail_out()};
   }

   auto ok = [](Test::Result& result, std::string_view name, const std::shared_ptr<Botan::TPM2::Session>& session) {
      result.require(Botan::fmt("Session '{}' is non-null", name), session != nullptr);
      result.confirm(Botan::fmt("Session '{}' has a valid handle", name), session->handle() != ESYS_TR_NONE);
      result.confirm(Botan::fmt("Session '{}' has a non-empty nonce", name), !session->tpm_nonce().empty());
   };

   return {
      CHECK("Unauthenticated sessions",
            [&](Test::Result& result) {
               using Session = Botan::TPM2::Session;

               ok(result, "default", Session::unauthenticated_session(ctx));
               ok(result, "CFB(AES-128)", Session::unauthenticated_session(ctx, "CFB(AES-128)"));
               ok(result, "CFB(AES-128),SHA-384", Session::unauthenticated_session(ctx, "CFB(AES-128)", "SHA-384"));
               ok(result, "CFB(AES-128),SHA-1", Session::unauthenticated_session(ctx, "CFB(AES-128)", "SHA-1"));
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_props", test_tpm2_properties);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_ctx", test_tpm2_context);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_sessions", test_tpm2_sessions);

#endif

}  // namespace Botan_Tests
