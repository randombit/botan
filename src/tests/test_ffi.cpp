/*
* (C) 2015 Jack Lloyd
* (C) 2016 René Korthaus
* (C) 2018 Ribose Inc, Krzysztof Kwiatkowski
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#define BOTAN_NO_DEPRECATED_WARNINGS

#include "tests.h"
#include <botan/version.h>

#if defined(BOTAN_HAS_FFI)
   #include <botan/ec_group.h>
   #include <botan/ffi.h>
   #include <botan/hex.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/stl_util.h>
   #include <botan/internal/target_info.h>
   #include <set>
#endif

#if defined(BOTAN_HAS_TPM2)
   #include <tss2/tss2_esys.h>
   #include <tss2/tss2_tctildr.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_FFI)

   // NOLINTNEXTLINE(*-macro-usage)
   #define _TEST_FFI_STR_HELPER(x) #x
   // NOLINTNEXTLINE(*-macro-usage)
   #define _TEST_FFI_STR(x) _TEST_FFI_STR_HELPER(x)
   // NOLINTNEXTLINE(*-macro-usage)
   #define _TEST_FFI_SOURCE_LOCATION(func, file, line) (func " invoked at " file ":" _TEST_FFI_STR(line))

   // NOLINTNEXTLINE(*-macro-usage)
   #define TEST_FFI_OK(func, args) result.test_rc_ok(_TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), func args)
   // NOLINTNEXTLINE(*-macro-usage)
   #define TEST_FFI_INIT(func, args) \
      result.test_rc_init(_TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), func args)
   // NOLINTNEXTLINE(*-macro-usage)
   #define TEST_FFI_FAIL(msg, func, args) \
      result.test_rc_fail(_TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), msg, func args)
   // NOLINTNEXTLINE(*-macro-usage)
   #define TEST_FFI_RC(rc, func, args) \
      result.test_rc(_TEST_FFI_SOURCE_LOCATION(#func, __FILE__, __LINE__), rc, func args)

   // NOLINTNEXTLINE(*-macro-usage)
   #define REQUIRE_FFI_OK(func, args)                           \
      if(!TEST_FFI_OK(func, args)) {                            \
         result.test_note("Exiting test early due to failure"); \
         return;                                                \
      }

class FFI_Test : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result(this->name());

         botan_rng_t rng;
         if(botan_rng_init(&rng, "system") != 0) {
            result.test_failure("Failed to init RNG");
            return {result};
         }

         result.start_timer();
         ffi_test(result, rng);
         result.end_timer();

         botan_rng_destroy(rng);

         return {result};
      }

   private:
      virtual std::string name() const = 0;
      virtual void ffi_test(Test::Result& result, botan_rng_t rng) = 0;
};

void ffi_test_pubkey_export(Test::Result& result, botan_pubkey_t pub, botan_privkey_t priv, botan_rng_t rng) {
   // export public key
   size_t pubkey_len = 0;
   TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
               botan_pubkey_export,
               (pub, nullptr, &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

   std::vector<uint8_t> pubkey(pubkey_len);
   TEST_FFI_OK(botan_pubkey_export, (pub, pubkey.data(), &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

   pubkey_len = 0;
   TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
               botan_pubkey_export,
               (pub, nullptr, &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

   pubkey.resize(pubkey_len);
   TEST_FFI_OK(botan_pubkey_export, (pub, pubkey.data(), &pubkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

   // reimport exported public key
   botan_pubkey_t pub_copy;
   TEST_FFI_OK(botan_pubkey_load, (&pub_copy, pubkey.data(), pubkey_len));
   TEST_FFI_OK(botan_pubkey_check_key, (pub_copy, rng, 0));
   TEST_FFI_OK(botan_pubkey_destroy, (pub_copy));

   // export private key
   std::vector<uint8_t> privkey;
   size_t privkey_len = 0;

   // call with nullptr to query the length
   TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
               botan_privkey_export,
               (priv, nullptr, &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

   privkey.resize(privkey_len);
   privkey_len = privkey.size();  // set buffer size

   TEST_FFI_OK(botan_privkey_export, (priv, privkey.data(), &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

   privkey.resize(privkey_len);

   result.test_gte("Reasonable size", privkey.size(), 32);

   // reimport exported private key
   botan_privkey_t copy;
   TEST_FFI_OK(botan_privkey_load, (&copy, rng, privkey.data(), privkey.size(), nullptr));
   botan_privkey_destroy(copy);

   // Now again for PEM
   privkey_len = 0;

   TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
               botan_privkey_export,
               (priv, nullptr, &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

   privkey.resize(privkey_len);
   TEST_FFI_OK(botan_privkey_export, (priv, privkey.data(), &privkey_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

   TEST_FFI_OK(botan_privkey_load, (&copy, rng, privkey.data(), privkey.size(), nullptr));
   botan_privkey_destroy(copy);

   #if defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_PKCS5_PBES2)
   const size_t pbkdf_iter = 1000;

   // export private key encrypted
   privkey_len = 0;
   TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
               botan_privkey_export_encrypted_pbkdf_iter,
               (priv, nullptr, &privkey_len, rng, "password", pbkdf_iter, "", "", BOTAN_PRIVKEY_EXPORT_FLAG_DER));

   privkey.resize(privkey_len);
   privkey_len = privkey.size();

   TEST_FFI_OK(
      botan_privkey_export_encrypted_pbkdf_iter,
      (priv, privkey.data(), &privkey_len, rng, "password", pbkdf_iter, "", "", BOTAN_PRIVKEY_EXPORT_FLAG_DER));

   // reimport encrypted private key
   botan_privkey_load(&copy, rng, privkey.data(), privkey.size(), "password");
   botan_privkey_destroy(copy);

   privkey_len = 0;
   TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
               botan_privkey_export_encrypted_pbkdf_iter,
               (priv, nullptr, &privkey_len, rng, "password", pbkdf_iter, "", "", BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

   privkey.resize(privkey_len);
   TEST_FFI_OK(
      botan_privkey_export_encrypted_pbkdf_iter,
      (priv, privkey.data(), &privkey_len, rng, "password", pbkdf_iter, "", "", BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

   privkey.resize(privkey_len * 2);
   privkey_len = privkey.size();
   const uint32_t pbkdf_msec = 100;
   size_t pbkdf_iters_out = 0;

      #if defined(BOTAN_HAS_SCRYPT)
   const std::string pbe_hash = "Scrypt";
      #else
   const std::string pbe_hash = "SHA-512";
      #endif

      #if defined(BOTAN_HAS_AEAD_GCM)
   const std::string pbe_cipher = "AES-256/GCM";
      #else
   const std::string pbe_cipher = "AES-256/CBC";
      #endif

   TEST_FFI_OK(botan_privkey_export_encrypted_pbkdf_msec,
               (priv,
                privkey.data(),
                &privkey_len,
                rng,
                "password",
                pbkdf_msec,
                &pbkdf_iters_out,
                pbe_cipher.c_str(),
                pbe_hash.c_str(),
                0));

   if(pbe_hash == "Scrypt") {
      result.test_eq("Scrypt iters set to zero in this API", pbkdf_iters_out, 0);
   } else {
      // PBKDF2 currently always rounds to multiple of 2000
      result.test_eq("Expected PBKDF2 iters", pbkdf_iters_out % 2000, 0);
   }

   privkey.resize(privkey_len);

   TEST_FFI_OK(botan_privkey_load, (&copy, rng, privkey.data(), privkey.size(), "password"));
   botan_privkey_destroy(copy);
   #endif

   // calculate fingerprint
   size_t strength = 0;
   TEST_FFI_OK(botan_pubkey_estimated_strength, (pub, &strength));
   result.test_gte("estimated strength", strength, 1);

   size_t fingerprint_len = 0;
   TEST_FFI_RC(
      BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_pubkey_fingerprint, (pub, "SHA-256", nullptr, &fingerprint_len));

   std::vector<uint8_t> fingerprint(fingerprint_len);
   TEST_FFI_OK(botan_pubkey_fingerprint, (pub, "SHA-256", fingerprint.data(), &fingerprint_len));
}

class FFI_Utils_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Utils"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         result.test_is_eq("FFI API version macro", uint32_t(BOTAN_FFI_API_VERSION), uint32_t(BOTAN_HAS_FFI));
         result.test_is_eq("FFI API version function", botan_ffi_api_version(), uint32_t(BOTAN_HAS_FFI));
         result.test_is_eq("Major version", botan_version_major(), Botan::version_major());
         result.test_is_eq("Minor version", botan_version_minor(), Botan::version_minor());
         result.test_is_eq("Patch version", botan_version_patch(), Botan::version_patch());
         result.test_is_eq("Botan version", botan_version_string(), Botan::version_cstr());
         result.test_is_eq("Botan version datestamp", botan_version_datestamp(), Botan::version_datestamp());
         result.test_is_eq("FFI supports its own version", botan_ffi_supports_api(botan_ffi_api_version()), 0);

         result.test_is_eq("FFI compile time time var matches botan_ffi_api_version",
                           botan_ffi_api_version(),
                           uint32_t(BOTAN_FFI_API_VERSION));

         result.test_is_eq("FFI supports 2.0 version", botan_ffi_supports_api(20150515), 0);
         result.test_is_eq("FFI supports 2.1 version", botan_ffi_supports_api(20170327), 0);
         result.test_is_eq("FFI supports 2.3 version", botan_ffi_supports_api(20170815), 0);
         result.test_is_eq("FFI supports 2.8 version", botan_ffi_supports_api(20180713), 0);

         result.test_is_eq("FFI doesn't support bogus version", botan_ffi_supports_api(20160229), -1);

         const std::vector<uint8_t> mem1 = {0xFF, 0xAA, 0xFF};
         const std::vector<uint8_t> mem2 = {0xFF, 0xA9, 0xFF};

         TEST_FFI_RC(0, botan_constant_time_compare, (mem1.data(), mem1.data(), mem1.size()));
         TEST_FFI_RC(-1, botan_constant_time_compare, (mem1.data(), mem2.data(), mem1.size()));

         std::vector<uint8_t> to_zero = {0xFF, 0xA0};
         TEST_FFI_OK(botan_scrub_mem, (to_zero.data(), to_zero.size()));
         result.confirm("scrub_memory zeros", to_zero[0] == 0 && to_zero[1] == 0);

         const std::vector<uint8_t> bin = {0xAA, 0xDE, 0x01};

         std::string outstr;
         std::vector<uint8_t> outbuf;

         outstr.resize(2 * bin.size());
         TEST_FFI_OK(botan_hex_encode, (bin.data(), bin.size(), &outstr[0], 0));
         result.test_eq("uppercase hex", outstr, "AADE01");

         TEST_FFI_OK(botan_hex_encode, (bin.data(), bin.size(), &outstr[0], BOTAN_FFI_HEX_LOWER_CASE));
         result.test_eq("lowercase hex", outstr, "aade01");
      }
};

class FFI_RNG_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI RNG"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         // RNG test and initialization
         botan_rng_t rng;
         botan_rng_t system_rng;
         botan_rng_t hwrng_rng = nullptr;
         botan_rng_t null_rng;
         botan_rng_t custom_rng;
         botan_rng_t tpm2_rng = nullptr;

         botan_tpm2_ctx_t tpm2_ctx = nullptr;
         botan_tpm2_session_t tpm2_session = nullptr;

         TEST_FFI_FAIL("invalid rng type", botan_rng_init, (&rng, "invalid_type"));

         REQUIRE_FFI_OK(botan_rng_init, (&system_rng, "system"));
         REQUIRE_FFI_OK(botan_rng_init, (&null_rng, "null"));

         int rc = botan_rng_init(&hwrng_rng, "hwrng");
         result.confirm("Either success or not implemented", rc == 0 || rc == BOTAN_FFI_ERROR_NOT_IMPLEMENTED);

         std::vector<uint8_t> outbuf(512);

         rc = botan_rng_init(&rng, "user-threadsafe");
         result.confirm("Either success or not implemented", rc == 0 || rc == BOTAN_FFI_ERROR_NOT_IMPLEMENTED);

         if(rc != 0) {
            REQUIRE_FFI_OK(botan_rng_init, (&rng, "user"));
            REQUIRE_FFI_OK(botan_rng_destroy, (rng));
         }

         if(rc == 0) {
            TEST_FFI_OK(botan_rng_get, (rng, outbuf.data(), outbuf.size()));
            TEST_FFI_OK(botan_rng_reseed, (rng, 256));

            TEST_FFI_RC(BOTAN_FFI_ERROR_INVALID_OBJECT_STATE, botan_rng_reseed_from_rng, (rng, null_rng, 256));
            if(hwrng_rng) {
               TEST_FFI_OK(botan_rng_reseed_from_rng, (rng, hwrng_rng, 256));
            }
            TEST_FFI_RC(BOTAN_FFI_ERROR_INVALID_OBJECT_STATE, botan_rng_get, (null_rng, outbuf.data(), outbuf.size()));

            TEST_FFI_OK(botan_rng_destroy, (rng));
         }

         if(TEST_FFI_OK(botan_rng_init, (&rng, "user"))) {
            TEST_FFI_OK(botan_rng_get, (rng, outbuf.data(), outbuf.size()));
            TEST_FFI_OK(botan_rng_reseed, (rng, 256));

            TEST_FFI_OK(botan_rng_reseed_from_rng, (rng, system_rng, 256));

            uint8_t not_really_entropy[32] = {0};
            TEST_FFI_OK(botan_rng_add_entropy, (rng, not_really_entropy, 32));
         }

         uint8_t system_rng_buf[4096];
         TEST_FFI_OK(botan_system_rng_get, (system_rng_buf, sizeof(system_rng_buf)));

         size_t cb_counter = 0;

         auto custom_get_cb = +[](void* context, uint8_t* out, size_t out_len) -> int {
            for(size_t i = 0; i != out_len; ++i) {
               out[i] = 0x12;
            }
            (*(static_cast<size_t*>(context)))++;
            return 0;
         };

         auto custom_add_entropy_cb = +[](void* context, const uint8_t input[], size_t length) -> int {
            BOTAN_UNUSED(input, length);
            (*(static_cast<size_t*>(context)))++;
            return 0;
         };

         auto custom_destroy_cb = +[](void* context) -> void { (*(static_cast<size_t*>(context)))++; };

         if(TEST_FFI_OK(
               botan_rng_init_custom,
               (&custom_rng, "custom rng", &cb_counter, custom_get_cb, custom_add_entropy_cb, custom_destroy_cb))) {
            Botan::clear_mem(outbuf.data(), outbuf.size());
            TEST_FFI_OK(botan_rng_get, (custom_rng, outbuf.data(), outbuf.size()));
            result.test_eq("custom_get_cb called", cb_counter, 1);
            std::vector<uint8_t> pattern(outbuf.size(), 0x12);
            result.test_eq("custom_get_cb returned bytes", pattern, outbuf);

            TEST_FFI_OK(botan_rng_reseed, (custom_rng, 256));
            result.test_eq("custom_add_entropy_cb called", cb_counter, 2);

            TEST_FFI_OK(botan_rng_reseed_from_rng, (custom_rng, system_rng, 256));
            result.test_eq("custom_add_entropy_cb called", cb_counter, 3);

            uint8_t not_really_entropy[32] = {0};
            TEST_FFI_OK(botan_rng_add_entropy, (custom_rng, not_really_entropy, 32));
            result.test_eq("custom_add_entropy_cb called", cb_counter, 4);

            TEST_FFI_OK(botan_rng_destroy, (custom_rng));
            result.test_eq("custom_destroy_cb called", cb_counter, 5);
         }

   #ifdef BOTAN_HAS_JITTER_RNG
         botan_rng_t jitter_rng;
         if(TEST_FFI_OK(botan_rng_init, (&jitter_rng, "jitter"))) {
            std::vector<uint8_t> buf(256);
            TEST_FFI_OK(botan_rng_get, (jitter_rng, outbuf.data(), buf.size()));
            TEST_FFI_OK(botan_rng_destroy, (jitter_rng));
         }
   #endif

         const auto tcti_name = Test::options().tpm2_tcti_name().value_or("");
         const auto tcti_conf = Test::options().tpm2_tcti_conf().value_or("");
         if(tcti_name.empty() || tcti_name == "disabled") {
            result.test_note("TPM2 tests are disabled.");
         } else {
            auto tpm2_test_rng = [&](botan_tpm2_ctx_t tpm2_context) {
               // Create and use an RNG without a TPM2 session
               // (communication between application and TPM won't be encrypted)
               if(TEST_FFI_INIT(botan_tpm2_rng_init, (&tpm2_rng, tpm2_context, nullptr, nullptr, nullptr))) {
                  Botan::clear_mem(outbuf.data(), outbuf.size());

                  TEST_FFI_OK(botan_rng_get, (tpm2_rng, outbuf.data(), outbuf.size()));
                  TEST_FFI_OK(botan_rng_reseed, (tpm2_rng, 256));

                  TEST_FFI_OK(botan_rng_reseed_from_rng, (tpm2_rng, system_rng, 256));

                  uint8_t not_really_entropy[32] = {0};
                  TEST_FFI_OK(botan_rng_add_entropy, (tpm2_rng, not_really_entropy, 32));
                  TEST_FFI_OK(botan_rng_destroy, (tpm2_rng));
               }

               // Create an anonymous TPM2 session
               if(TEST_FFI_INIT(botan_tpm2_unauthenticated_session_init, (&tpm2_session, tpm2_context))) {
                  // Create and use an RNG with an anonymous TPM2 session
                  // (communication between application and TPM will be encrypted)
                  if(TEST_FFI_INIT(botan_tpm2_rng_init, (&tpm2_rng, tpm2_context, tpm2_session, nullptr, nullptr))) {
                     Botan::clear_mem(outbuf.data(), outbuf.size());

                     TEST_FFI_OK(botan_rng_get, (tpm2_rng, outbuf.data(), outbuf.size()));
                     TEST_FFI_OK(botan_rng_reseed, (tpm2_rng, 256));

                     TEST_FFI_OK(botan_rng_reseed_from_rng, (tpm2_rng, system_rng, 256));

                     uint8_t not_really_entropy[32] = {0};
                     TEST_FFI_OK(botan_rng_add_entropy, (tpm2_rng, not_really_entropy, 32));
                     TEST_FFI_OK(botan_rng_destroy, (tpm2_rng));
                  }

                  TEST_FFI_OK(botan_tpm2_session_destroy, (tpm2_session));
               }
            };

            if(TEST_FFI_INIT(botan_tpm2_ctx_init_ex, (&tpm2_ctx, tcti_name.c_str(), tcti_conf.c_str()))) {
               if(botan_tpm2_supports_crypto_backend() == 1) {
                  TEST_FFI_OK(botan_tpm2_ctx_enable_crypto_backend, (tpm2_ctx, system_rng));
                  result.test_note("TPM2 crypto backend enabled");
               } else {
                  result.test_note("TPM2 crypto backend not supported");
               }

               tpm2_test_rng(tpm2_ctx);
               TEST_FFI_OK(botan_tpm2_ctx_destroy, (tpm2_ctx));
            }

   #if defined(BOTAN_HAS_TPM2)
            TSS2_TCTI_CONTEXT* tcti_ctx;
            ESYS_CONTEXT* esys_ctx;

            if(TEST_FFI_INIT(Tss2_TctiLdr_Initialize_Ex, (tcti_name.c_str(), tcti_conf.c_str(), &tcti_ctx))) {
               if(TEST_FFI_INIT(Esys_Initialize, (&esys_ctx, tcti_ctx, nullptr /* ABI version */))) {
                  botan_tpm2_crypto_backend_state_t cbs = nullptr;

                  // enable the botan-based TSS2 crypto backend on a bare ESYS_CONTEXT
                  if(botan_tpm2_supports_crypto_backend() == 1) {
                     TEST_FFI_OK(botan_tpm2_enable_crypto_backend, (&cbs, esys_ctx, system_rng));
                     result.test_note("TPM2 crypto backend enabled");
                  } else {
                     result.test_note("TPM2 crypto backend not supported");
                  }

                  // initialize the Botan TPM2 FFI wrapper from the bare ESYS_CONTEXT
                  if(TEST_FFI_INIT(botan_tpm2_ctx_from_esys, (&tpm2_ctx, esys_ctx))) {
                     tpm2_test_rng(tpm2_ctx);
                     TEST_FFI_OK(botan_tpm2_ctx_destroy, (tpm2_ctx));
                  }

                  if(cbs != nullptr) {
                     TEST_FFI_OK(botan_tpm2_crypto_backend_state_destroy, (cbs));
                  }

                  Esys_Finalize(&esys_ctx);
               }
               Tss2_TctiLdr_Finalize(&tcti_ctx);
            }
   #endif
         }

         TEST_FFI_OK(botan_rng_destroy, (rng));
         TEST_FFI_OK(botan_rng_destroy, (null_rng));
         TEST_FFI_OK(botan_rng_destroy, (system_rng));
         TEST_FFI_OK(botan_rng_destroy, (hwrng_rng));
      }
};

class FFI_RSA_Cert_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI RSA cert"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_x509_cert_t cert;
         if(TEST_FFI_INIT(botan_x509_cert_load_file, (&cert, Test::data_file("x509/ocsp/randombit.pem").c_str()))) {
            TEST_FFI_RC(0, botan_x509_cert_hostname_match, (cert, "randombit.net"));
            TEST_FFI_RC(0, botan_x509_cert_hostname_match, (cert, "www.randombit.net"));
            TEST_FFI_RC(-1, botan_x509_cert_hostname_match, (cert, "*.randombit.net"));
            TEST_FFI_RC(-1, botan_x509_cert_hostname_match, (cert, "flub.randombit.net"));
            TEST_FFI_RC(-1, botan_x509_cert_hostname_match, (cert, "randombit.net.com"));

            botan_x509_cert_t copy;
            TEST_FFI_OK(botan_x509_cert_dup, (&copy, cert));
            TEST_FFI_RC(0, botan_x509_cert_hostname_match, (copy, "randombit.net"));

            TEST_FFI_OK(botan_x509_cert_destroy, (copy));
            TEST_FFI_OK(botan_x509_cert_destroy, (cert));
         }
      }
};

class FFI_ZFEC_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI ZFEC"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         /* exercise a simple success case
          */

         // Select some arbitrary, valid encoding parameters.  There is
         // nothing special about them but some relationships between these
         // values and other inputs must hold.
         const size_t K = 3;
         const size_t N = 11;

         // The decoder needs to know the indexes of the blocks being passed
         // in to it.  This array must equal [0..N) for the logic in the
         // decoding loop below to hold.
         const std::vector<size_t> indexes = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

         // This will be the size of each encoded (or decoded) block.  This is
         // an arbitrary value but it must match up with the length of the
         // test data given in `input`.
         const size_t blockSize = 15;

         // K of the blocks are required so the total information represented
         // can be this multiple.  totalSize must be a multiple of K and it
         // always will be using this construction.
         const size_t totalSize = blockSize * K;

         // Here's the complete original input (plus a trailing NUL that we
         // won't pass through ZFEC).  These are arbitrary bytes.
         const uint8_t input[totalSize + 1] = "Does this work?AAAAAAAAAAAAAAAzzzzzzzzzzzzzzz";

         // Allocate memory for the encoding and decoding output parameters.
         std::vector<uint8_t> encoded_buf(N * blockSize);
         std::vector<uint8_t> decoded_buf(K * blockSize);

         std::vector<uint8_t*> encoded(N);
         for(size_t i = 0; i < N; ++i) {
            encoded[i] = &encoded_buf[i * blockSize];
         }
         std::vector<uint8_t*> decoded(K);
         for(size_t i = 0; i < K; ++i) {
            decoded[i] = &decoded_buf[i * blockSize];
         }

         // First encode the complete input string into N blocks where K are
         // required for reconstruction.  The N encoded blocks will end up in
         // `encoded`.
         if(!TEST_FFI_INIT(botan_zfec_encode, (K, N, input, totalSize, encoded.data()))) {
            return;
         }

         // Any K blocks can be decoded to reproduce the original input (split
         // across an array of K strings of blockSize bytes each).  This loop
         // only exercises decoding with consecutive blocks because it's
         // harder to pick non-consecutive blocks out for a test.
         for(size_t offset = 0; offset < N - K; ++offset) {
            result.test_note("About to decode with offset " + std::to_string(offset));
            // Pass in the K shares starting from `offset` (and their indexes)
            // so that we can try decoding a certain group of blocks here.  Any
            // K shares *should* work.
            REQUIRE_FFI_OK(botan_zfec_decode,
                           (K, N, indexes.data() + offset, encoded.data() + offset, blockSize, decoded.data()));

            // Check that the original input bytes have been written to the
            // output parameter.
            for(size_t k = 0, pos = 0; k < K; ++k, pos += blockSize) {
               TEST_FFI_RC(0, botan_constant_time_compare, (input + pos, decoded[k], blockSize));
            }
         }

         /* Exercise a couple basic failure cases, such as you encounter if
          * the caller supplies invalid parameters.  We don't try to
          * exhaustively prove invalid parameters are handled through this
          * interface since the implementation only passes them through to
          * ZFEC::{encode,decode} where the real checking is.  We just want to
          * see that errors can propagate.
          */
         TEST_FFI_FAIL("encode with out-of-bounds encoding parameters should have failed",
                       botan_zfec_encode,
                       (0, 0, nullptr, 0, nullptr));
         TEST_FFI_FAIL("decode with out-of-bounds encoding parameters should have failed",
                       botan_zfec_decode,
                       (0, 0, nullptr, nullptr, 0, nullptr));
      }
};

class FFI_CRL_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI CRL"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const char* crl_string =
            "-----BEGIN X509 CRL-----\n"
            "MIICoTCCAQkCAQEwDQYJKoZIhvcNAQELBQAwgZQxLTArBgNVBAMTJFVzYWJsZSBj\n"
            "ZXJ0IHZhbGlkYXRpb246IFRlbXBvcmFyeSBDQTE5MDcGA1UECxMwQ2VudHJlIGZv\n"
            "ciBSZXNlYXJjaCBvbiBDcnlwdG9ncmFwaHkgYW5kIFNlY3VyaXR5MRswGQYDVQQK\n"
            "ExJNYXNhcnlrIFVuaXZlcnNpdHkxCzAJBgNVBAYTAkNaGA8yMDUwMDIyNTE1MjE0\n"
            "MloYDzIwNTAwMjI1MTUyNDQxWjAAoDowODAfBgNVHSMEGDAWgBRKzxAvI4+rVVo/\n"
            "JzLigRznREyB+TAVBgNVHRQEDgIMXcr16yNys/gjeuCFMA0GCSqGSIb3DQEBCwUA\n"
            "A4IBgQCfxv/5REM/KUnzeVycph3dJr1Yrtxhc6pZmQ9pMzSW/nawLN3rUHm5oG44\n"
            "ZuQgjvzE4PnbU0/DNRu/4w3H58kgrctJHHXbbvkU3lf2ZZLh2wBl+EUh92+/COow\n"
            "ZyGB+jqj/XwB99hYUhrY6NLEWRz08kpgG6dnNMEU0uFqdQKWk0CQPnmgPRgDb8BW\n"
            "IuMBcjY7aF9XoCZFOqPYdEvUKzAo4QGCf7uJ7fNGS3LqvjaLjAHJseSr5/yR7Q9r\n"
            "nEdI38yKPbRj0tNHe7j+BbYg31C+X+AZZKJtlTg8GxYR3qfQio1kDgpZ3rQLzHY3\n"
            "ea2MLX/Kdx9cPSwh4KwlcDxQmQKoELb4EnZW1CScSBHi9HQyCBNyCkgkOBMGcJqz\n"
            "Ihq1dGeSf8eca9+Avk5kAQ3yjXK1TI2CDEi0msrXLr9XbgowXiOLLzR+rYkhQz+V\n"
            "RnIoBwjnrGoJoz636KS170SZCB9ARNs17WE4IvbJdZrTXNOGaVZCQUUpiLRj4ZSO\n"
            "Na/nobI=\n"
            "-----END X509 CRL-----";

         botan_x509_crl_t bytecrl;
         if(!TEST_FFI_INIT(botan_x509_crl_load, (&bytecrl, reinterpret_cast<const uint8_t*>(crl_string), 966))) {
            return;
         }

         botan_x509_crl_t crl;
         REQUIRE_FFI_OK(botan_x509_crl_load_file, (&crl, Test::data_file("x509/nist/root.crl").c_str()));

         botan_x509_cert_t cert1;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&cert1, Test::data_file("x509/nist/test01/end.crt").c_str()));
         TEST_FFI_RC(-1, botan_x509_is_revoked, (crl, cert1));
         TEST_FFI_OK(botan_x509_cert_destroy, (cert1));

         botan_x509_cert_t cert2;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&cert2, Test::data_file("x509/nist/test20/int.crt").c_str()));
         TEST_FFI_RC(0, botan_x509_is_revoked, (crl, cert2));
         TEST_FFI_RC(-1, botan_x509_is_revoked, (bytecrl, cert2));
         TEST_FFI_OK(botan_x509_cert_destroy, (cert2));

         TEST_FFI_OK(botan_x509_crl_destroy, (crl));
         TEST_FFI_OK(botan_x509_crl_destroy, (bytecrl));
      }
};

class FFI_Cert_Validation_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Cert Validation"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_x509_cert_t root;
         int rc;

         if(!TEST_FFI_INIT(botan_x509_cert_load_file, (&root, Test::data_file("x509/nist/root.crt").c_str()))) {
            return;
         }

         botan_x509_cert_t end2;
         botan_x509_cert_t sub2;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&end2, Test::data_file("x509/nist/test02/end.crt").c_str()));
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&sub2, Test::data_file("x509/nist/test02/int.crt").c_str()));

         TEST_FFI_RC(1, botan_x509_cert_verify, (&rc, end2, &sub2, 1, &root, 1, nullptr, 0, nullptr, 0));
         result.confirm("Validation test02 failed", rc == 5002);
         result.test_eq("Validation test02 status string", botan_x509_cert_validation_status(rc), "Signature error");

         TEST_FFI_RC(1, botan_x509_cert_verify, (&rc, end2, nullptr, 0, &root, 1, nullptr, 0, nullptr, 0));
         result.confirm("Validation test02 failed (missing int)", rc == 3000);
         result.test_eq(
            "Validation test02 status string", botan_x509_cert_validation_status(rc), "Certificate issuer not found");

         botan_x509_cert_t end7;
         botan_x509_cert_t sub7;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&end7, Test::data_file("x509/nist/test07/end.crt").c_str()));
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&sub7, Test::data_file("x509/nist/test07/int.crt").c_str()));

         botan_x509_cert_t subs[2] = {sub2, sub7};
         TEST_FFI_RC(1, botan_x509_cert_verify, (&rc, end7, subs, 2, &root, 1, nullptr, 0, nullptr, 0));
         result.confirm("Validation test07 failed with expected error", rc == 1001);
         result.test_eq("Validation test07 status string",
                        botan_x509_cert_validation_status(rc),
                        "Hash function used is considered too weak for security");

         TEST_FFI_RC(0, botan_x509_cert_verify, (&rc, end7, subs, 2, &root, 1, nullptr, 80, nullptr, 0));
         result.confirm("Validation test07 passed", rc == 0);
         result.test_eq("Validation test07 status string", botan_x509_cert_validation_status(rc), "Verified");

         TEST_FFI_RC(1,
                     botan_x509_cert_verify_with_crl,
                     (&rc, end7, subs, 2, nullptr, 0, nullptr, 0, "x509/farce", 0, nullptr, 0));
         result.confirm("Validation test07 failed with expected error", rc == 3000);
         result.test_eq(
            "Validation test07 status string", botan_x509_cert_validation_status(rc), "Certificate issuer not found");

         botan_x509_crl_t rootcrl;

         REQUIRE_FFI_OK(botan_x509_crl_load_file, (&rootcrl, Test::data_file("x509/nist/root.crl").c_str()));
         TEST_FFI_RC(
            0, botan_x509_cert_verify_with_crl, (&rc, end7, subs, 2, &root, 1, &rootcrl, 1, nullptr, 80, nullptr, 0));
         result.confirm("Validation test07 with CRL passed", rc == 0);
         result.test_eq("Validation test07 with CRL status string", botan_x509_cert_validation_status(rc), "Verified");

         botan_x509_cert_t end20;
         botan_x509_cert_t sub20;
         botan_x509_crl_t sub20crl;
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&end20, Test::data_file("x509/nist/test20/end.crt").c_str()));
         REQUIRE_FFI_OK(botan_x509_cert_load_file, (&sub20, Test::data_file("x509/nist/test20/int.crt").c_str()));
         REQUIRE_FFI_OK(botan_x509_crl_load_file, (&sub20crl, Test::data_file("x509/nist/test20/int.crl").c_str()));
         botan_x509_crl_t crls[2] = {sub20crl, rootcrl};
         TEST_FFI_RC(
            1, botan_x509_cert_verify_with_crl, (&rc, end20, &sub20, 1, &root, 1, crls, 2, nullptr, 80, nullptr, 0));
         result.confirm("Validation test20 failed with expected error", rc == 5000);
         result.test_eq(
            "Validation test20 status string", botan_x509_cert_validation_status(rc), "Certificate is revoked");

         TEST_FFI_OK(botan_x509_cert_destroy, (end2));
         TEST_FFI_OK(botan_x509_cert_destroy, (sub2));
         TEST_FFI_OK(botan_x509_cert_destroy, (end7));
         TEST_FFI_OK(botan_x509_cert_destroy, (sub7));
         TEST_FFI_OK(botan_x509_cert_destroy, (end20));
         TEST_FFI_OK(botan_x509_cert_destroy, (sub20));
         TEST_FFI_OK(botan_x509_crl_destroy, (sub20crl));
         TEST_FFI_OK(botan_x509_cert_destroy, (root));
         TEST_FFI_OK(botan_x509_crl_destroy, (rootcrl));
      }
};

class FFI_ECDSA_Certificate_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI ECDSA cert"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_x509_cert_t cert;
         if(TEST_FFI_INIT(botan_x509_cert_load_file, (&cert, Test::data_file("x509/ecc/isrg-root-x2.pem").c_str()))) {
            size_t date_len = 0;
            TEST_FFI_RC(
               BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_time_starts, (cert, nullptr, &date_len));

            date_len = 8;
            TEST_FFI_RC(
               BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_time_starts, (cert, nullptr, &date_len));

            std::string date(date_len - 1, '0');
            TEST_FFI_OK(botan_x509_cert_get_time_starts, (cert, &date[0], &date_len));
            result.test_eq("cert valid from", date, "200904000000Z");

            date_len = 0;
            TEST_FFI_RC(
               BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_get_time_expires, (cert, nullptr, &date_len));

            date.resize(date_len - 1);
            TEST_FFI_OK(botan_x509_cert_get_time_expires, (cert, &date[0], &date_len));
            result.test_eq("cert valid until", date, "400917160000Z");

            uint64_t not_before = 0;
            TEST_FFI_OK(botan_x509_cert_not_before, (cert, &not_before));
            result.confirm("cert not before", not_before == 1599177600);

            uint64_t not_after = 0;
            TEST_FFI_OK(botan_x509_cert_not_after, (cert, &not_after));
            result.confirm("cert not after", not_after == 2231510400);

            size_t serial_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_x509_cert_get_serial_number,
                        (cert, nullptr, &serial_len));

            std::vector<uint8_t> serial(serial_len);
            TEST_FFI_OK(botan_x509_cert_get_serial_number, (cert, serial.data(), &serial_len));
            result.test_eq("cert serial length", serial.size(), 16);
            result.test_eq("cert serial", Botan::hex_encode(serial), "41D29DD172EAEEA780C12C6CE92F8752");

            size_t fingerprint_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_x509_cert_get_fingerprint,
                        (cert, "SHA-256", nullptr, &fingerprint_len));

            std::vector<uint8_t> fingerprint(fingerprint_len);
            TEST_FFI_OK(botan_x509_cert_get_fingerprint, (cert, "SHA-256", fingerprint.data(), &fingerprint_len));
            result.test_eq(
               "cert fingerprint",
               reinterpret_cast<const char*>(fingerprint.data()),
               "69:72:9B:8E:15:A8:6E:FC:17:7A:57:AF:B7:17:1D:FC:64:AD:D2:8C:2F:CA:8C:F1:50:7E:34:45:3C:CB:14:70");

            size_t key_id_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_x509_cert_get_authority_key_id,
                        (cert, nullptr, &key_id_len));

            result.test_eq("No AKID", key_id_len, 0);

            key_id_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_x509_cert_get_subject_key_id,
                        (cert, nullptr, &key_id_len));

            std::vector<uint8_t> key_id(key_id_len);
            TEST_FFI_OK(botan_x509_cert_get_subject_key_id, (cert, key_id.data(), &key_id_len));
            result.test_eq("cert subject key id",
                           Botan::hex_encode(key_id.data(), key_id.size(), true),
                           "7C4296AEDE4B483BFA92F89E8CCF6D8BA9723795");

            size_t pubkey_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_x509_cert_get_public_key_bits,
                        (cert, nullptr, &pubkey_len));

            std::vector<uint8_t> pubkey(pubkey_len);
            TEST_FFI_OK(botan_x509_cert_get_public_key_bits, (cert, pubkey.data(), &pubkey_len));

   #if defined(BOTAN_HAS_ECDSA)
            botan_pubkey_t pub;
            if(TEST_FFI_OK(botan_x509_cert_get_public_key, (cert, &pub))) {
               TEST_FFI_RC(0, botan_pubkey_ecc_key_used_explicit_encoding, (pub));
               TEST_FFI_OK(botan_pubkey_destroy, (pub));
            }
   #endif

            size_t dn_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_x509_cert_get_issuer_dn,
                        (cert, "Name", 0, nullptr, &dn_len));

            std::vector<uint8_t> dn(dn_len);
            TEST_FFI_OK(botan_x509_cert_get_issuer_dn, (cert, "Name", 0, dn.data(), &dn_len));
            result.test_eq("issuer dn", reinterpret_cast<const char*>(dn.data()), "ISRG Root X2");

            dn_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_x509_cert_get_subject_dn,
                        (cert, "Name", 0, nullptr, &dn_len));

            dn.resize(dn_len);
            TEST_FFI_OK(botan_x509_cert_get_subject_dn, (cert, "Name", 0, dn.data(), &dn_len));
            result.test_eq("subject dn", reinterpret_cast<const char*>(dn.data()), "ISRG Root X2");

            size_t printable_len = 0;
            TEST_FFI_RC(
               BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_x509_cert_to_string, (cert, nullptr, &printable_len));

            std::string printable(printable_len - 1, '0');
            TEST_FFI_OK(botan_x509_cert_to_string, (cert, &printable[0], &printable_len));

            TEST_FFI_RC(0, botan_x509_cert_allowed_usage, (cert, KEY_CERT_SIGN));
            TEST_FFI_RC(0, botan_x509_cert_allowed_usage, (cert, CRL_SIGN));
            TEST_FFI_RC(1, botan_x509_cert_allowed_usage, (cert, DIGITAL_SIGNATURE));

            TEST_FFI_OK(botan_x509_cert_destroy, (cert));
         }
      }
};

class FFI_PKCS_Hashid_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI PKCS hash id"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         std::vector<uint8_t> hash_id(64);
         size_t hash_id_len = hash_id.size();

         if(TEST_FFI_INIT(botan_pkcs_hash_id, ("SHA-256", hash_id.data(), &hash_id_len))) {
            result.test_eq("Expected SHA-256 PKCS hash id len", hash_id_len, 19);

            hash_id.resize(hash_id_len);
            result.test_eq("Expected SHA_256 PKCS hash id", hash_id, "3031300D060960864801650304020105000420");

            hash_id_len = 3;  // too short
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_pkcs_hash_id,
                        ("SHA-256", hash_id.data(), &hash_id_len));
         }
      }
};

class FFI_CBC_Cipher_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI CBC cipher"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_cipher_t cipher_encrypt, cipher_decrypt;

         if(TEST_FFI_INIT(botan_cipher_init, (&cipher_encrypt, "AES-128/CBC/PKCS7", BOTAN_CIPHER_INIT_FLAG_ENCRYPT))) {
            size_t min_keylen = 0;
            size_t max_keylen = 0;
            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            result.test_int_eq(min_keylen, 16, "Min key length");
            result.test_int_eq(max_keylen, 16, "Max key length");

            // from https://github.com/geertj/bluepass/blob/master/tests/vectors/aes-cbc-pkcs7.txt
            const std::vector<uint8_t> plaintext =
               Botan::hex_decode("0397f4f6820b1f9386f14403be5ac16e50213bd473b4874b9bcbf5f318ee686b1d");
            const std::vector<uint8_t> symkey = Botan::hex_decode("898be9cc5004ed0fa6e117c9a3099d31");
            const std::vector<uint8_t> nonce = Botan::hex_decode("9dea7621945988f96491083849b068df");
            const std::vector<uint8_t> exp_ciphertext = Botan::hex_decode(
               "e232cd6ef50047801ee681ec30f61d53cfd6b0bca02fd03c1b234baa10ea82ac9dab8b960926433a19ce6dea08677e34");

            size_t output_written = 0;
            size_t input_consumed = 0;

            // Test that after clear or final the object can be reused
            for(size_t r = 0; r != 2; ++r) {
               size_t ctext_len;
               TEST_FFI_OK(botan_cipher_output_length, (cipher_encrypt, plaintext.size(), &ctext_len));
               result.test_eq("Expected size of padded message", ctext_len, plaintext.size() + 15);
               std::vector<uint8_t> ciphertext(ctext_len);

               size_t update_granularity = 0;
               size_t ideal_granularity = 0;
               size_t taglen = 0;

               TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_encrypt, &update_granularity));
               TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_encrypt, &ideal_granularity));
               TEST_FFI_OK(botan_cipher_get_tag_length, (cipher_encrypt, &taglen));

               result.test_eq(
                  "ideal granularity is a multiple of update granularity", ideal_granularity % update_granularity, 0);
               result.test_eq("not an AEAD, hence no tag", taglen, 0);

               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            0,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));
               TEST_FFI_OK(botan_cipher_clear, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));

               ciphertext.resize(output_written);
               result.test_eq("AES/CBC ciphertext", ciphertext, exp_ciphertext);

               if(TEST_FFI_OK(botan_cipher_init, (&cipher_decrypt, "AES-128/CBC", BOTAN_CIPHER_INIT_FLAG_DECRYPT))) {
                  size_t ptext_len;
                  TEST_FFI_OK(botan_cipher_output_length, (cipher_decrypt, ciphertext.size(), &ptext_len));
                  std::vector<uint8_t> decrypted(ptext_len);

                  TEST_FFI_RC(0, botan_cipher_is_authenticated, (cipher_encrypt));

                  TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_decrypt, &update_granularity));
                  TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_decrypt, &ideal_granularity));
                  TEST_FFI_OK(botan_cipher_get_tag_length, (cipher_decrypt, &taglen));

                  result.test_eq("ideal granularity is a multiple of update granularity (decrypt)",
                                 ideal_granularity % update_granularity,
                                 0);
                  result.test_eq("not an AEAD, hence no tag (decrypt)", taglen, 0);

                  TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, symkey.data(), symkey.size()));
                  TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));
                  TEST_FFI_OK(botan_cipher_update,
                              (cipher_decrypt,
                               BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                               decrypted.data(),
                               decrypted.size(),
                               &output_written,
                               ciphertext.data(),
                               ciphertext.size(),
                               &input_consumed));

                  decrypted.resize(output_written);

                  result.test_eq("AES/CBC plaintext", decrypted, plaintext);

                  TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));
               }
            }

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));
         }
      }
};

class FFI_GCM_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI GCM"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_cipher_t cipher_encrypt, cipher_decrypt;

         if(TEST_FFI_INIT(botan_cipher_init, (&cipher_encrypt, "AES-128/GCM", BOTAN_CIPHER_INIT_FLAG_ENCRYPT))) {
            char namebuf[18];
            size_t name_len = 15;
            TEST_FFI_FAIL("output buffer too short", botan_cipher_name, (cipher_encrypt, namebuf, &name_len));
            result.test_eq("name len", name_len, 16);

            name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_cipher_name, (cipher_encrypt, namebuf, &name_len))) {
               result.test_eq("name len", name_len, 16);
               result.test_eq("name", std::string(namebuf), "AES-128/GCM(16)");
            }

            size_t min_keylen = 0;
            size_t max_keylen = 0;
            size_t nonce_len = 0;
            size_t tag_len = 0;
            size_t update_granularity = 0;
            size_t ideal_granularity = 0;

            TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_encrypt, &update_granularity));
            TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_encrypt, &ideal_granularity));

            result.test_eq(
               "ideal granularity is a multiple of update granularity", ideal_granularity % update_granularity, 0);

            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            result.test_int_eq(min_keylen, 16, "Min key length");
            result.test_int_eq(max_keylen, 16, "Max key length");

            TEST_FFI_OK(botan_cipher_get_default_nonce_length, (cipher_encrypt, &nonce_len));
            result.test_int_eq(nonce_len, 12, "Expected default GCM nonce length");

            TEST_FFI_OK(botan_cipher_get_tag_length, (cipher_encrypt, &tag_len));
            result.test_int_eq(tag_len, 16, "Expected GCM tag length");

            TEST_FFI_RC(1, botan_cipher_is_authenticated, (cipher_encrypt));

            TEST_FFI_RC(1, botan_cipher_valid_nonce_length, (cipher_encrypt, 12));
            // GCM accepts any nonce size except zero
            TEST_FFI_RC(0, botan_cipher_valid_nonce_length, (cipher_encrypt, 0));
            TEST_FFI_RC(1, botan_cipher_valid_nonce_length, (cipher_encrypt, 1));
            TEST_FFI_RC(1, botan_cipher_valid_nonce_length, (cipher_encrypt, 100009));

            // NIST test vector
            const std::vector<uint8_t> plaintext = Botan::hex_decode(
               "D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B39");

            const std::vector<uint8_t> symkey = Botan::hex_decode("FEFFE9928665731C6D6A8F9467308308");
            const std::vector<uint8_t> nonce = Botan::hex_decode("CAFEBABEFACEDBADDECAF888");
            const std::vector<uint8_t> exp_ciphertext = Botan::hex_decode(
               "42831EC2217774244B7221B784D0D49CE3AA212F2C02A4E035C17E2329ACA12E21D514B25466931C7D8F6A5AAC84AA051BA30B396A0AAC973D58E0915BC94FBC3221A5DB94FAE95AE7121A47");
            const std::vector<uint8_t> aad = Botan::hex_decode("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");

            std::vector<uint8_t> ciphertext(tag_len + plaintext.size());

            size_t output_written = 0;
            size_t input_consumed = 0;

            // Test that after clear or final the object can be reused
            for(size_t r = 0; r != 2; ++r) {
               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));

               // First use a nonce of the AAD, and ensure reset works
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, aad.data(), aad.size()));
               TEST_FFI_OK(botan_cipher_reset, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            0,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));
               TEST_FFI_OK(botan_cipher_clear, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_set_associated_data, (cipher_encrypt, aad.data(), aad.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));

               ciphertext.resize(output_written);
               result.test_eq("AES/GCM ciphertext", ciphertext, exp_ciphertext);

               if(TEST_FFI_OK(botan_cipher_init, (&cipher_decrypt, "AES-128/GCM", BOTAN_CIPHER_INIT_FLAG_DECRYPT))) {
                  std::vector<uint8_t> decrypted(plaintext.size());

                  TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_decrypt, &update_granularity));
                  TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_decrypt, &ideal_granularity));

                  result.test_eq("ideal granularity is a multiple of update granularity (decrypt)",
                                 ideal_granularity % update_granularity,
                                 0);

                  TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, symkey.data(), symkey.size()));
                  TEST_FFI_OK(botan_cipher_set_associated_data, (cipher_decrypt, aad.data(), aad.size()));
                  TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));
                  TEST_FFI_OK(botan_cipher_update,
                              (cipher_decrypt,
                               BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                               decrypted.data(),
                               decrypted.size(),
                               &output_written,
                               ciphertext.data(),
                               ciphertext.size(),
                               &input_consumed));

                  result.test_int_eq(input_consumed, ciphertext.size(), "All input consumed");
                  result.test_int_eq(output_written, decrypted.size(), "Expected output size produced");
                  result.test_eq("AES/GCM plaintext", decrypted, plaintext);

                  TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));
               }
            }

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));
         }
      }
};

class FFI_ChaCha20Poly1305_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI ChaCha20Poly1305"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_cipher_t cipher_encrypt, cipher_decrypt;

         if(TEST_FFI_INIT(botan_cipher_init, (&cipher_encrypt, "ChaCha20Poly1305", BOTAN_CIPHER_INIT_FLAG_ENCRYPT))) {
            std::array<char, 17> namebuf;
            size_t name_len = 15;
            TEST_FFI_FAIL("output buffer too short", botan_cipher_name, (cipher_encrypt, namebuf.data(), &name_len));
            result.test_eq("name len", name_len, 17);

            name_len = namebuf.size();
            if(TEST_FFI_OK(botan_cipher_name, (cipher_encrypt, namebuf.data(), &name_len))) {
               result.test_eq("name len", name_len, 17);
               result.test_eq("name", std::string(namebuf.data()), "ChaCha20Poly1305");
            }

            size_t min_keylen = 0;
            size_t max_keylen = 0;
            size_t nonce_len = 0;
            size_t tag_len = 0;
            size_t update_granularity = 0;
            size_t ideal_granularity = 0;

            TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_encrypt, &update_granularity));
            TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_encrypt, &ideal_granularity));

            result.test_eq(
               "ideal granularity is a multiple of update granularity", ideal_granularity % update_granularity, 0);

            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            result.test_int_eq(min_keylen, 32, "Min key length");
            result.test_int_eq(max_keylen, 32, "Max key length");

            TEST_FFI_OK(botan_cipher_get_default_nonce_length, (cipher_encrypt, &nonce_len));
            result.test_int_eq(nonce_len, 12, "Expected default ChaCha20Poly1305 nonce length");

            TEST_FFI_OK(botan_cipher_get_tag_length, (cipher_encrypt, &tag_len));
            result.test_int_eq(tag_len, 16, "Expected Chacha20Poly1305 tag length");

            TEST_FFI_RC(1, botan_cipher_is_authenticated, (cipher_encrypt));

            // From RFC 7539
            const std::vector<uint8_t> plaintext = Botan::hex_decode(
               "4C616469657320616E642047656E746C656D656E206F662074686520636C617373206F66202739393A204966204920636F756C64206F6666657220796F75206F6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73637265656E20776F756C642062652069742E");
            const std::vector<uint8_t> symkey =
               Botan::hex_decode("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F");
            const std::vector<uint8_t> nonce = Botan::hex_decode("070000004041424344454647");
            const std::vector<uint8_t> exp_ciphertext = Botan::hex_decode(
               "D31A8D34648E60DB7B86AFBC53EF7EC2A4ADED51296E08FEA9E2B5A736EE62D63DBEA45E8CA9671282FAFB69DA92728B1A71DE0A9E060B2905D6A5B67ECD3B3692DDBD7F2D778B8C9803AEE328091B58FAB324E4FAD675945585808B4831D7BC3FF4DEF08E4B7A9DE576D26586CEC64B61161AE10B594F09E26A7E902ECBD0600691");
            const std::vector<uint8_t> aad = Botan::hex_decode("50515253C0C1C2C3C4C5C6C7");

            std::vector<uint8_t> ciphertext(tag_len + plaintext.size());

            size_t output_written = 0;
            size_t input_consumed = 0;

            // Test that after clear or final the object can be reused
            for(size_t r = 0; r != 2; ++r) {
               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));

               // First use a nonce of the AAD, and ensure reset works
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, aad.data(), aad.size()));
               TEST_FFI_OK(botan_cipher_reset, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            0,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));
               TEST_FFI_OK(botan_cipher_clear, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_set_associated_data, (cipher_encrypt, aad.data(), aad.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));

               ciphertext.resize(output_written);
               result.test_eq("AES/GCM ciphertext", ciphertext, exp_ciphertext);

               if(TEST_FFI_OK(botan_cipher_init,
                              (&cipher_decrypt, "ChaCha20Poly1305", BOTAN_CIPHER_INIT_FLAG_DECRYPT))) {
                  std::vector<uint8_t> decrypted(plaintext.size());

                  TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_decrypt, &update_granularity));
                  TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_decrypt, &ideal_granularity));

                  result.test_eq("ideal granularity is a multiple of update granularity (decrypt)",
                                 ideal_granularity % update_granularity,
                                 0);

                  TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, symkey.data(), symkey.size()));
                  TEST_FFI_OK(botan_cipher_set_associated_data, (cipher_decrypt, aad.data(), aad.size()));
                  TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));
                  TEST_FFI_OK(botan_cipher_update,
                              (cipher_decrypt,
                               BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                               decrypted.data(),
                               decrypted.size(),
                               &output_written,
                               ciphertext.data(),
                               ciphertext.size(),
                               &input_consumed));

                  result.test_int_eq(input_consumed, ciphertext.size(), "All input consumed");
                  result.test_int_eq(output_written, decrypted.size(), "Expected output size produced");
                  result.test_eq("AES/GCM plaintext", decrypted, plaintext);

                  TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));
               }
            }

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));
         }
      }
};

class FFI_EAX_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI EAX"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_cipher_t cipher_encrypt, cipher_decrypt;

         if(TEST_FFI_INIT(botan_cipher_init, (&cipher_encrypt, "AES-128/EAX", BOTAN_CIPHER_INIT_FLAG_ENCRYPT))) {
            size_t min_keylen = 0;
            size_t max_keylen = 0;
            size_t mod_keylen = 0;
            size_t nonce_len = 0;
            size_t tag_len = 0;
            size_t update_granularity = 0;
            size_t ideal_granularity = 0;

            TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_encrypt, &update_granularity));
            TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_encrypt, &ideal_granularity));

            result.test_eq(
               "ideal granularity is a multiple of update granularity", ideal_granularity % update_granularity, 0);

            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            result.test_int_eq(min_keylen, 16, "Min key length");
            result.test_int_eq(max_keylen, 16, "Max key length");

            TEST_FFI_OK(botan_cipher_get_keyspec, (cipher_encrypt, &min_keylen, &max_keylen, &mod_keylen));
            result.test_int_eq(min_keylen, 16, "Min key length");
            result.test_int_eq(max_keylen, 16, "Max key length");
            result.test_int_eq(mod_keylen, 1, "Mod key length");

            TEST_FFI_OK(botan_cipher_get_default_nonce_length, (cipher_encrypt, &nonce_len));
            result.test_int_eq(nonce_len, 12, "Expected default EAX nonce length");

            TEST_FFI_OK(botan_cipher_get_tag_length, (cipher_encrypt, &tag_len));
            result.test_int_eq(tag_len, 16, "Expected EAX tag length");

            TEST_FFI_RC(1, botan_cipher_is_authenticated, (cipher_encrypt));

            TEST_FFI_RC(1, botan_cipher_valid_nonce_length, (cipher_encrypt, 12));
            // EAX accepts any nonce size...
            TEST_FFI_RC(1, botan_cipher_valid_nonce_length, (cipher_encrypt, 0));

            const std::vector<uint8_t> plaintext =
               Botan::hex_decode("0000000000000000000000000000000011111111111111111111111111111111");
            const std::vector<uint8_t> symkey = Botan::hex_decode("000102030405060708090a0b0c0d0e0f");
            const std::vector<uint8_t> nonce = Botan::hex_decode("3c8cc2970a008f75cc5beae2847258c2");
            const std::vector<uint8_t> exp_ciphertext = Botan::hex_decode(
               "3c441f32ce07822364d7a2990e50bb13d7b02a26969e4a937e5e9073b0d9c968db90bdb3da3d00afd0fc6a83551da95e");

            std::vector<uint8_t> ciphertext(tag_len + plaintext.size());

            size_t output_written = 0;
            size_t input_consumed = 0;

            // Test that after clear or final the object can be reused
            for(size_t r = 0; r != 2; ++r) {
               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            0,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));
               TEST_FFI_OK(botan_cipher_clear, (cipher_encrypt));

               TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, symkey.data(), symkey.size()));
               TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));
               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                            ciphertext.data(),
                            ciphertext.size(),
                            &output_written,
                            plaintext.data(),
                            plaintext.size(),
                            &input_consumed));

               ciphertext.resize(output_written);
               result.test_eq("AES/EAX ciphertext", ciphertext, exp_ciphertext);

               if(TEST_FFI_OK(botan_cipher_init, (&cipher_decrypt, "AES-128/EAX", BOTAN_CIPHER_INIT_FLAG_DECRYPT))) {
                  std::vector<uint8_t> decrypted(plaintext.size());

                  TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_decrypt, &update_granularity));
                  TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_decrypt, &ideal_granularity));

                  result.test_eq("ideal granularity is a multiple of update granularity (decrypt)",
                                 ideal_granularity % update_granularity,
                                 0);

                  TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, symkey.data(), symkey.size()));
                  TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));
                  TEST_FFI_OK(botan_cipher_update,
                              (cipher_decrypt,
                               BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                               decrypted.data(),
                               decrypted.size(),
                               &output_written,
                               ciphertext.data(),
                               ciphertext.size(),
                               &input_consumed));

                  result.test_int_eq(input_consumed, ciphertext.size(), "All input consumed");
                  result.test_int_eq(output_written, decrypted.size(), "Expected output size produced");
                  result.test_eq("AES/EAX plaintext", decrypted, plaintext);

                  TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));
               }
            }

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));
         }
      }
};

class FFI_AEAD_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI AEAD"; }

      void ffi_test(Test::Result& merged_result, botan_rng_t rng) override {
         botan_cipher_t cipher_encrypt, cipher_decrypt;

         std::array<std::string, 5> aeads = {
            "AES-128/GCM", "ChaCha20Poly1305", "AES-128/EAX", "AES-256/SIV", "AES-128/CCM"};

         for(const std::string& aead : aeads) {
            Test::Result result(Botan::fmt("AEAD {}", aead));

            if(!TEST_FFI_INIT(botan_cipher_init, (&cipher_encrypt, aead.c_str(), BOTAN_CIPHER_INIT_FLAG_ENCRYPT))) {
               continue;
            }

            if(!botan_cipher_is_authenticated(cipher_encrypt)) {
               result.test_failure("Cipher " + aead + " claims is not authenticated");
               botan_cipher_destroy(cipher_encrypt);
               continue;
            }

            size_t min_keylen = 0;
            size_t max_keylen = 0;
            size_t update_granularity = 0;
            size_t ideal_granularity = 0;
            size_t noncelen = 0;
            size_t taglen = 0;
            constexpr size_t pt_multiplier = 5;
            TEST_FFI_OK(botan_cipher_query_keylen, (cipher_encrypt, &min_keylen, &max_keylen));
            TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_encrypt, &update_granularity));
            TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_encrypt, &ideal_granularity));
            TEST_FFI_OK(botan_cipher_get_default_nonce_length, (cipher_encrypt, &noncelen));
            TEST_FFI_OK(botan_cipher_get_tag_length, (cipher_encrypt, &taglen));

            result.test_eq(
               "ideal granularity is a multiple of update granularity", ideal_granularity % update_granularity, 0);

            std::vector<uint8_t> key(max_keylen);
            TEST_FFI_OK(botan_rng_get, (rng, key.data(), key.size()));
            TEST_FFI_OK(botan_cipher_set_key, (cipher_encrypt, key.data(), key.size()));

            std::vector<uint8_t> nonce(noncelen);
            TEST_FFI_OK(botan_rng_get, (rng, nonce.data(), nonce.size()));
            TEST_FFI_OK(botan_cipher_start, (cipher_encrypt, nonce.data(), nonce.size()));

            std::vector<uint8_t> plaintext(ideal_granularity * pt_multiplier);
            std::vector<uint8_t> ciphertext(ideal_granularity * pt_multiplier + taglen);
            TEST_FFI_OK(botan_rng_get, (rng, plaintext.data(), plaintext.size()));

            std::vector<uint8_t> dummy_buffer(1024);
            TEST_FFI_OK(botan_rng_get, (rng, dummy_buffer.data(), dummy_buffer.size()));
            std::vector<uint8_t> dummy_buffer_reference = dummy_buffer;

            const bool requires_entire_message = botan_cipher_requires_entire_message(cipher_encrypt);
            result.test_eq(
               "requires entire message", requires_entire_message, (aead == "AES-256/SIV" || aead == "AES-128/CCM"));

            std::span<const uint8_t> pt_slicer(plaintext);
            std::span<uint8_t> ct_stuffer(ciphertext);

            // Process data that is explicitly a multiple of the ideal
            // granularity and therefore should be aligned with the cipher's
            // internal block size.
            for(size_t i = 0; i < pt_multiplier; ++i) {
               size_t output_written = 0;
               size_t input_consumed = 0;

               auto pt_chunk = pt_slicer.first(ideal_granularity);

               // The existing implementation won't consume any bytes from the
               // input if there is no space in the output buffer. Even when
               // the cipher is a mode that won't produce any output until the
               // entire message is processed. Hence, give it some dummy buffer.
               BOTAN_ASSERT_NOMSG(dummy_buffer.size() > ideal_granularity);
               auto ct_chunk = (requires_entire_message) ? std::span(dummy_buffer).first(ideal_granularity)
                                                         : ct_stuffer.first(ideal_granularity);

               TEST_FFI_OK(botan_cipher_update,
                           (cipher_encrypt,
                            0 /* don't finalize */,
                            ct_chunk.data(),
                            ct_chunk.size(),
                            &output_written,
                            pt_chunk.data(),
                            pt_chunk.size(),
                            &input_consumed));

               result.test_gt("some input consumed", input_consumed, 0);
               result.test_lte("at most, all input consumed", input_consumed, pt_chunk.size());
               pt_slicer = pt_slicer.subspan(input_consumed);

               if(requires_entire_message) {
                  result.test_eq("no output produced", output_written, 0);
               } else {
                  result.test_eq("all bytes produced", output_written, input_consumed);
                  ct_stuffer = ct_stuffer.subspan(output_written);
               }
            }

            // Trying to pull a part of the authentication tag should fail,
            // as we must consume the entire tag in a single invocation to
            // botan_cipher_update().
            size_t final_output_written = 42;
            size_t final_input_consumed = 1337;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_cipher_update,
                        (cipher_encrypt,
                         BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                         dummy_buffer.data(),
                         3, /* not enough to hold any reasonable auth'n tag */
                         &final_output_written,
                         pt_slicer.data(),  // remaining bytes (typically 0)
                         pt_slicer.size(),
                         &final_input_consumed));

            const size_t expected_final_size = requires_entire_message ? ciphertext.size() : taglen + pt_slicer.size();

            result.test_eq("remaining bytes consumed in bogus final", final_input_consumed, pt_slicer.size());
            result.test_eq("required buffer size is written in bogus final", final_output_written, expected_final_size);

            auto final_ct_chunk = ct_stuffer.first(expected_final_size);

            TEST_FFI_OK(botan_cipher_update,
                        (cipher_encrypt,
                         BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                         final_ct_chunk.data(),
                         final_ct_chunk.size(),
                         &final_output_written,
                         nullptr,  // no more input
                         0,
                         &final_input_consumed));

            result.test_eq("no bytes consumed in final", final_input_consumed, 0);
            result.test_eq("final bytes written", final_output_written, expected_final_size);
            result.test_eq("dummy buffer unchanged", dummy_buffer, dummy_buffer_reference);

            TEST_FFI_OK(botan_cipher_destroy, (cipher_encrypt));

            // ----------------------------------------------------------------

            TEST_FFI_INIT(botan_cipher_init, (&cipher_decrypt, aead.c_str(), BOTAN_CIPHER_INIT_FLAG_DECRYPT));

            TEST_FFI_OK(botan_cipher_get_update_granularity, (cipher_decrypt, &update_granularity));
            TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (cipher_decrypt, &ideal_granularity));

            result.test_eq("ideal granularity is a multiple of update granularity (decrypt)",
                           ideal_granularity % update_granularity,
                           0);

            TEST_FFI_OK(botan_cipher_set_key, (cipher_decrypt, key.data(), key.size()));
            TEST_FFI_OK(botan_cipher_start, (cipher_decrypt, nonce.data(), nonce.size()));

            std::vector<uint8_t> decrypted(plaintext.size());

            std::span<const uint8_t> ct_slicer(ciphertext);
            std::span<uint8_t> pt_stuffer(decrypted);

            // Process data that is explicitly a multiple of the ideal
            // granularity and therefore should be aligned with the cipher's
            // internal block size.
            for(size_t i = 0; i < pt_multiplier; ++i) {
               size_t output_written = 42;
               size_t input_consumed = 1337;

               auto ct_chunk = ct_slicer.first(ideal_granularity);

               // The existing implementation won't consume any bytes from the
               // input if there is no space in the output buffer. Even when
               // the cipher is a mode that won't produce any output until the
               // entire message is processed. Hence, give it some dummy buffer.
               auto pt_chunk = (requires_entire_message) ? std::span(dummy_buffer).first(ideal_granularity)
                                                         : pt_stuffer.first(ideal_granularity);

               TEST_FFI_OK(botan_cipher_update,
                           (cipher_decrypt,
                            0 /* don't finalize */,
                            pt_chunk.data(),
                            pt_chunk.size(),
                            &output_written,
                            ct_chunk.data(),
                            ct_chunk.size(),
                            &input_consumed));

               result.test_gt("some input consumed", input_consumed, 0);
               result.test_lte("at most, all input consumed", input_consumed, ct_chunk.size());
               ct_slicer = ct_slicer.subspan(input_consumed);

               if(requires_entire_message) {
                  result.test_eq("no output produced", output_written, 0);
               } else {
                  result.test_eq("all bytes produced", output_written, input_consumed);
                  pt_stuffer = pt_stuffer.subspan(output_written);
               }
            }

            const size_t expected_final_size_dec = requires_entire_message ? plaintext.size() : pt_stuffer.size();
            auto pt_chunk = pt_stuffer.first(expected_final_size_dec);

            size_t final_output_written_dec = 42;
            size_t final_input_consumed_dec = 1337;

            TEST_FFI_OK(botan_cipher_update,
                        (cipher_decrypt,
                         BOTAN_CIPHER_UPDATE_FLAG_FINAL,
                         pt_chunk.data(),
                         pt_chunk.size(),
                         &final_output_written_dec,
                         ct_slicer.data(),  // remaining bytes (typically 0)
                         ct_slicer.size(),
                         &final_input_consumed_dec));

            result.test_eq("remaining bytes consumed in final (decrypt)", final_input_consumed_dec, ct_slicer.size());
            result.test_eq("bytes written in final (decrypt)", final_output_written_dec, expected_final_size_dec);
            result.test_eq("dummy buffer unchanged", dummy_buffer, dummy_buffer_reference);

            result.test_eq("decrypted plaintext", decrypted, plaintext);

            TEST_FFI_OK(botan_cipher_destroy, (cipher_decrypt));

            merged_result.merge(result, true /* ignore names */);
         }
      }
};

class FFI_StreamCipher_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI stream ciphers"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_cipher_t ctr;

         if(TEST_FFI_INIT(botan_cipher_init, (&ctr, "AES-128/CTR-BE", BOTAN_CIPHER_INIT_FLAG_ENCRYPT))) {
            const std::vector<uint8_t> key = Botan::hex_decode("2B7E151628AED2A6ABF7158809CF4F3C");
            const std::vector<uint8_t> nonce = Botan::hex_decode("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFF");
            const std::vector<uint8_t> pt = Botan::hex_decode(
               "AE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
            const std::vector<uint8_t> exp_ct = Botan::hex_decode(
               "9806F66B7970FDFF8617187BB9FFFDFF5AE4DF3EDBD5D35E5B4F09020DB03EAB1E031DDA2FBE03D1792170A0F3009CEE");

            std::vector<uint8_t> ct(pt.size());

            size_t update_granularity = 0;
            size_t ideal_granularity = 0;

            TEST_FFI_OK(botan_cipher_get_update_granularity, (ctr, &update_granularity));
            TEST_FFI_OK(botan_cipher_get_ideal_update_granularity, (ctr, &ideal_granularity));

            result.test_eq(
               "ideal granularity is a multiple of update granularity", ideal_granularity % update_granularity, 0);

            TEST_FFI_RC(0, botan_cipher_is_authenticated, (ctr));

            size_t input_consumed = 0;
            size_t output_written = 0;

            TEST_FFI_OK(botan_cipher_set_key, (ctr, key.data(), key.size()));
            TEST_FFI_OK(botan_cipher_start, (ctr, nonce.data(), nonce.size()));

            // Test partial updates...
            TEST_FFI_OK(botan_cipher_update,
                        (ctr, 0, ct.data(), ct.size(), &output_written, pt.data(), 5, &input_consumed));

            result.test_int_eq(output_written, 5, "Expected output written");
            result.test_int_eq(input_consumed, 5, "Expected input consumed");

            TEST_FFI_OK(botan_cipher_update,
                        (ctr, 0, &ct[5], ct.size() - 5, &output_written, &pt[5], pt.size() - 5, &input_consumed));

            result.test_int_eq(output_written, ct.size() - 5, "Expected output written");
            result.test_int_eq(input_consumed, pt.size() - 5, "Expected input consumed");
            result.test_eq("AES-128/CTR ciphertext", ct, exp_ct);

            TEST_FFI_OK(botan_cipher_destroy, (ctr));
         }
      }
};

class FFI_HashFunction_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI hash"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const char* input_str = "ABC";

         botan_hash_t hash;
         TEST_FFI_FAIL("invalid hash name", botan_hash_init, (&hash, "SHA-255", 0));
         TEST_FFI_FAIL("invalid flags", botan_hash_init, (&hash, "SHA-256", 1));

         if(TEST_FFI_INIT(botan_hash_init, (&hash, "SHA-256", 0))) {
            char namebuf[10];
            size_t name_len = 7;
            TEST_FFI_FAIL("output buffer too short", botan_hash_name, (hash, namebuf, &name_len));
            result.test_eq("name len", name_len, 8);

            name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_hash_name, (hash, namebuf, &name_len))) {
               result.test_eq("name len", name_len, 8);
               result.test_eq("name", std::string(namebuf), "SHA-256");
            }

            size_t block_size;
            if(TEST_FFI_OK(botan_hash_block_size, (hash, &block_size))) {
               result.test_eq("hash block size", block_size, 64);
            }

            size_t output_len;
            if(TEST_FFI_OK(botan_hash_output_length, (hash, &output_len))) {
               result.test_eq("hash output length", output_len, 32);

               std::vector<uint8_t> outbuf(output_len);

               // Test that after clear or final the object can be reused
               for(size_t r = 0; r != 2; ++r) {
                  TEST_FFI_OK(botan_hash_update, (hash, reinterpret_cast<const uint8_t*>(input_str), 1));
                  TEST_FFI_OK(botan_hash_clear, (hash));

                  TEST_FFI_OK(botan_hash_update,
                              (hash, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_hash_final, (hash, outbuf.data()));

                  result.test_eq(
                     "SHA-256 output", outbuf, "B5D4045C3F466FA91FE2CC6ABE79232A1A57CDF104F7A26E716E0A1E2789DF78");
               }

               // Test botan_hash_copy_state
               const char* msg = "message digest";
               const char* expected = "F7846F55CF23E14EEBEAB5B4E1550CAD5B509E3348FBC4EFA3A1413D393CB650";
               TEST_FFI_OK(botan_hash_clear, (hash));
               TEST_FFI_OK(botan_hash_update, (hash, reinterpret_cast<const uint8_t*>(&msg[0]), 1));
               botan_hash_t fork;
               if(TEST_FFI_OK(botan_hash_copy_state, (&fork, hash))) {
                  TEST_FFI_OK(botan_hash_update,
                              (fork, reinterpret_cast<const uint8_t*>(&msg[1]), std::strlen(msg) - 2));

                  TEST_FFI_OK(botan_hash_update,
                              (hash, reinterpret_cast<const uint8_t*>(&msg[1]), std::strlen(msg) - 1));
                  TEST_FFI_OK(botan_hash_final, (hash, outbuf.data()));
                  result.test_eq("hashing split", outbuf, expected);

                  TEST_FFI_OK(botan_hash_update,
                              (fork, reinterpret_cast<const uint8_t*>(&msg[std::strlen(msg) - 1]), 1));
                  TEST_FFI_OK(botan_hash_final, (fork, outbuf.data()));
                  result.test_eq("hashing split", outbuf, expected);

                  TEST_FFI_OK(botan_hash_destroy, (fork));
               }
            }

            TEST_FFI_OK(botan_hash_destroy, (hash));
         }
      }
};

class FFI_MAC_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI MAC"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const char* input_str = "ABC";

         // MAC test
         botan_mac_t mac;
         TEST_FFI_FAIL("bad flag", botan_mac_init, (&mac, "HMAC(SHA-256)", 1));
         TEST_FFI_FAIL("bad name", botan_mac_init, (&mac, "HMAC(SHA-259)", 0));

         if(TEST_FFI_INIT(botan_mac_init, (&mac, "HMAC(SHA-256)", 0))) {
            char namebuf[16];
            size_t name_len = 13;
            TEST_FFI_FAIL("output buffer too short", botan_mac_name, (mac, namebuf, &name_len));
            result.test_eq("name len", name_len, 14);

            name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_mac_name, (mac, namebuf, &name_len))) {
               result.test_eq("name len", name_len, 14);
               result.test_eq("name", std::string(namebuf), "HMAC(SHA-256)");
            }

            size_t min_keylen = 0, max_keylen = 0, mod_keylen = 0;
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, nullptr, nullptr, nullptr));
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, &min_keylen, nullptr, nullptr));
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, nullptr, &max_keylen, nullptr));
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, nullptr, nullptr, &mod_keylen));

            result.test_eq("Expected min keylen", min_keylen, 0);
            result.test_eq("Expected max keylen", max_keylen, 4096);
            result.test_eq("Expected mod keylen", mod_keylen, 1);

            size_t output_len;
            if(TEST_FFI_OK(botan_mac_output_length, (mac, &output_len))) {
               result.test_eq("MAC output length", output_len, 32);

               const uint8_t mac_key[] = {0xAA, 0xBB, 0xCC, 0xDD};
               std::vector<uint8_t> outbuf(output_len);

               // Test that after clear or final the object can be reused
               for(size_t r = 0; r != 2; ++r) {
                  TEST_FFI_OK(botan_mac_set_key, (mac, mac_key, sizeof(mac_key)));
                  TEST_FFI_OK(botan_mac_update,
                              (mac, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_mac_clear, (mac));

                  TEST_FFI_OK(botan_mac_set_key, (mac, mac_key, sizeof(mac_key)));
                  TEST_FFI_OK(botan_mac_update,
                              (mac, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_mac_final, (mac, outbuf.data()));

                  result.test_eq(
                     "HMAC output", outbuf, "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7");
               }
            }

            TEST_FFI_OK(botan_mac_destroy, (mac));
         }
      }
};

class FFI_Scrypt_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Scrypt"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         std::vector<uint8_t> output(24);
         const uint8_t salt[8] = {0};
         const char* pass = "password";

         if(TEST_FFI_INIT(botan_scrypt, (output.data(), output.size(), pass, salt, sizeof(salt), 8, 1, 1))) {
            result.test_eq("scrypt output", output, "4B9B888D695288E002CC4F9D90808A4D296A45CE4471AFBB");

            size_t N, r, p;
            TEST_FFI_OK(botan_pwdhash_timed,
                        ("Scrypt", 50, &r, &p, &N, output.data(), output.size(), "bunny", 5, salt, sizeof(salt)));

            std::vector<uint8_t> cmp(output.size());

            TEST_FFI_OK(botan_pwdhash, ("Scrypt", N, r, p, cmp.data(), cmp.size(), "bunny", 5, salt, sizeof(salt)));
            result.test_eq("recomputed scrypt", cmp, output);
         }
      }
};

class FFI_KDF_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI KDF"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         std::vector<uint8_t> outbuf;

         const std::string passphrase = "ltexmfeyylmlbrsyikaw";

         const std::vector<uint8_t> pbkdf_salt = Botan::hex_decode("ED1F39A0A7F3889AAF7E60743B3BC1CC2C738E60");
         const size_t pbkdf_out_len = 10;
         const size_t pbkdf_iterations = 1000;

         outbuf.resize(pbkdf_out_len);

         if(TEST_FFI_INIT(botan_pbkdf,
                          ("PBKDF2(SHA-1)",
                           outbuf.data(),
                           outbuf.size(),
                           passphrase.c_str(),
                           pbkdf_salt.data(),
                           pbkdf_salt.size(),
                           pbkdf_iterations))) {
            result.test_eq("PBKDF output", outbuf, "027AFADD48F4BE8DCC4F");

            size_t iters_10ms, iters_100ms;

            TEST_FFI_OK(botan_pbkdf_timed,
                        ("PBKDF2(SHA-1)",
                         outbuf.data(),
                         outbuf.size(),
                         passphrase.c_str(),
                         pbkdf_salt.data(),
                         pbkdf_salt.size(),
                         10,
                         &iters_10ms));
            TEST_FFI_OK(botan_pbkdf_timed,
                        ("PBKDF2(SHA-1)",
                         outbuf.data(),
                         outbuf.size(),
                         passphrase.c_str(),
                         pbkdf_salt.data(),
                         pbkdf_salt.size(),
                         100,
                         &iters_100ms));

            result.test_note("PBKDF timed 10 ms " + std::to_string(iters_10ms) + " iterations " + "100 ms " +
                             std::to_string(iters_100ms) + " iterations");
         }

         const std::vector<uint8_t> kdf_secret = Botan::hex_decode("92167440112E");
         const std::vector<uint8_t> kdf_salt = Botan::hex_decode("45A9BEDED69163123D0348F5185F61ABFB1BF18D6AEA454F");
         const size_t kdf_out_len = 18;
         outbuf.resize(kdf_out_len);

         if(TEST_FFI_INIT(botan_kdf,
                          ("KDF2(SHA-1)",
                           outbuf.data(),
                           outbuf.size(),
                           kdf_secret.data(),
                           kdf_secret.size(),
                           kdf_salt.data(),
                           kdf_salt.size(),
                           nullptr,
                           0))) {
            result.test_eq("KDF output", outbuf, "3A5DC9AA1C872B4744515AC2702D6396FC2A");
         }

         size_t out_len = 64;
         std::string outstr;
         outstr.resize(out_len);

         int rc =
            botan_bcrypt_generate(reinterpret_cast<uint8_t*>(&outstr[0]), &out_len, passphrase.c_str(), rng, 4, 0);

         if(rc == 0) {
            result.test_eq("bcrypt output size", out_len, 61);

            TEST_FFI_OK(botan_bcrypt_is_valid, (passphrase.c_str(), outstr.data()));
            TEST_FFI_FAIL("bad password", botan_bcrypt_is_valid, ("nope", outstr.data()));
         }
      }
};

class FFI_Blockcipher_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI block ciphers"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         botan_block_cipher_t cipher;

         if(TEST_FFI_INIT(botan_block_cipher_init, (&cipher, "AES-128"))) {
            char namebuf[10];
            size_t name_len = 7;
            TEST_FFI_FAIL("output buffer too short", botan_block_cipher_name, (cipher, namebuf, &name_len));
            result.test_eq("name len", name_len, 8);

            name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_block_cipher_name, (cipher, namebuf, &name_len))) {
               result.test_eq("name len", name_len, 8);
               result.test_eq("name", std::string(namebuf), "AES-128");
            }

            const std::vector<uint8_t> zero16(16, 0);
            std::vector<uint8_t> block(16, 0);

            TEST_FFI_OK(botan_block_cipher_clear, (cipher));

            TEST_FFI_RC(
               BOTAN_FFI_ERROR_KEY_NOT_SET, botan_block_cipher_encrypt_blocks, (cipher, block.data(), block.data(), 1));
            TEST_FFI_RC(
               BOTAN_FFI_ERROR_KEY_NOT_SET, botan_block_cipher_decrypt_blocks, (cipher, block.data(), block.data(), 1));

            TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_block_cipher_encrypt_blocks, (cipher, nullptr, nullptr, 0));
            TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_block_cipher_decrypt_blocks, (cipher, nullptr, nullptr, 0));

            TEST_FFI_RC(16, botan_block_cipher_block_size, (cipher));

            size_t min_keylen = 0, max_keylen = 0, mod_keylen = 0;
            TEST_FFI_RC(0, botan_block_cipher_get_keyspec, (cipher, nullptr, nullptr, nullptr));
            TEST_FFI_RC(0, botan_block_cipher_get_keyspec, (cipher, &min_keylen, nullptr, nullptr));
            TEST_FFI_RC(0, botan_block_cipher_get_keyspec, (cipher, nullptr, &max_keylen, nullptr));
            TEST_FFI_RC(0, botan_block_cipher_get_keyspec, (cipher, nullptr, nullptr, &mod_keylen));

            result.test_eq("Expected min keylen", min_keylen, 16);
            result.test_eq("Expected max keylen", max_keylen, 16);
            result.test_eq("Expected mod keylen", mod_keylen, 1);

            TEST_FFI_OK(botan_block_cipher_set_key, (cipher, zero16.data(), zero16.size()));

            TEST_FFI_OK(botan_block_cipher_encrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 encryption works", block, "66E94BD4EF8A2C3B884CFA59CA342B2E");

            TEST_FFI_OK(botan_block_cipher_encrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 encryption works", block, "F795BD4A52E29ED713D313FA20E98DBC");

            TEST_FFI_OK(botan_block_cipher_decrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 decryption works", block, "66E94BD4EF8A2C3B884CFA59CA342B2E");

            TEST_FFI_OK(botan_block_cipher_decrypt_blocks, (cipher, block.data(), block.data(), 1));
            result.test_eq("AES-128 decryption works", block, "00000000000000000000000000000000");

            TEST_FFI_OK(botan_block_cipher_clear, (cipher));
            botan_block_cipher_destroy(cipher);
         }
      }
};

class FFI_ErrorHandling_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI error handling"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         // delete of null is ok/ignored
         TEST_FFI_RC(0, botan_hash_destroy, (nullptr));

   #if !defined(BOTAN_HAS_SANITIZER_UNDEFINED)
         // Confirm that botan_x_destroy checks the argument type
         botan_mp_t mp;
         botan_mp_init(&mp);
         TEST_FFI_RC(BOTAN_FFI_ERROR_INVALID_OBJECT, botan_hash_destroy, (reinterpret_cast<botan_hash_t>(mp)));
         TEST_FFI_RC(0, botan_mp_destroy, (mp));
   #endif

         std::set<std::string> errors;
         for(int i = -100; i != 50; ++i) {
            const char* err = botan_error_description(i);
            result.confirm("Never a null pointer", err != nullptr);

            if(err) {
               std::string s(err);

               if(s != "Unknown error") {
                  result.confirm("No duplicate messages", !errors.contains(s));
                  errors.insert(s);
               }
            }
         }
      }
};

class FFI_Base64_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI base64"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const uint8_t bin[9] = {0x16, 0x8a, 0x1f, 0x06, 0xe9, 0xe7, 0xcb, 0xdd, 0x34};
         char out_buf[1024] = {0};

         size_t out_len = sizeof(out_buf);
         TEST_FFI_OK(botan_base64_encode, (bin, sizeof(bin), out_buf, &out_len));

         result.test_eq("encoded string", out_buf, "FoofBunny900");

         out_len -= 1;
         TEST_FFI_RC(
            BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_base64_encode, (bin, sizeof(bin), out_buf, &out_len));

         const char* base64 = "U3VjaCBiYXNlNjQgd293IQ==";
         uint8_t out_bin[1024] = {0};

         out_len = 3;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                     botan_base64_decode,
                     (base64, strlen(base64), out_bin, &out_len));

         result.test_eq("output length", out_len, 18);

         out_len = sizeof(out_bin);
         TEST_FFI_OK(botan_base64_decode, (base64, strlen(base64), out_bin, &out_len));

         result.test_eq(
            "decoded string", std::string(reinterpret_cast<const char*>(out_bin), out_len), "Such base64 wow!");
      }
};

class FFI_Hex_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI hex"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const uint8_t bin[4] = {0xDE, 0xAD, 0xBE, 0xEF};
         char hex_buf[16] = {0};

         TEST_FFI_OK(botan_hex_encode, (bin, sizeof(bin), hex_buf, 0));

         result.test_eq("encoded string", hex_buf, "DEADBEEF");

         const char* hex = "67657420796572206A756D626F20736872696D70";
         uint8_t out_bin[1024] = {0};
         size_t out_len = 5;

         TEST_FFI_RC(
            BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_hex_decode, (hex, strlen(hex), out_bin, &out_len));

         out_len = sizeof(out_bin);
         TEST_FFI_OK(botan_hex_decode, (hex, strlen(hex), out_bin, &out_len));

         result.test_eq(
            "decoded string", std::string(reinterpret_cast<const char*>(out_bin), out_len), "get yer jumbo shrimp");
      }
};

class FFI_MP_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI MP"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         char str_buf[1024] = {0};
         size_t str_len = 0;

         botan_mp_t x;
         botan_mp_init(&x);
         TEST_FFI_RC(0, botan_mp_is_odd, (x));
         TEST_FFI_RC(1, botan_mp_is_even, (x));
         TEST_FFI_RC(0, botan_mp_is_negative, (x));
         TEST_FFI_RC(1, botan_mp_is_positive, (x));
         TEST_FFI_RC(1, botan_mp_is_zero, (x));
         botan_mp_destroy(x);

         botan_mp_init(&x);
         size_t bn_bytes = 0;
         TEST_FFI_OK(botan_mp_num_bytes, (x, &bn_bytes));
         result.test_eq("Expected size for MP 0", bn_bytes, 0);

         botan_mp_set_from_int(x, 5);
         TEST_FFI_OK(botan_mp_num_bytes, (x, &bn_bytes));
         result.test_eq("Expected size for MP 5", bn_bytes, 1);

         botan_mp_add_u32(x, x, 75);
         TEST_FFI_OK(botan_mp_num_bytes, (x, &bn_bytes));
         result.test_eq("Expected size for MP 80", bn_bytes, 1);

         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (x, 10, str_buf, &str_len));
         result.test_eq("botan_mp_add", std::string(str_buf), "80");

         botan_mp_sub_u32(x, x, 80);
         TEST_FFI_RC(1, botan_mp_is_zero, (x));
         botan_mp_add_u32(x, x, 259);
         TEST_FFI_OK(botan_mp_num_bytes, (x, &bn_bytes));
         result.test_eq("Expected size for MP 259", bn_bytes, 2);

         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (x, 10, str_buf, &str_len));
         result.test_eq("botan_mp_add", std::string(str_buf), "259");

         TEST_FFI_RC(1, botan_mp_is_odd, (x));
         TEST_FFI_RC(0, botan_mp_is_even, (x));
         TEST_FFI_RC(0, botan_mp_is_negative, (x));
         TEST_FFI_RC(1, botan_mp_is_positive, (x));
         TEST_FFI_RC(0, botan_mp_is_zero, (x));

         {
            botan_mp_t zero;
            botan_mp_init(&zero);
            int cmp;
            TEST_FFI_OK(botan_mp_cmp, (&cmp, x, zero));
            result.confirm("bigint_mp_cmp(+, 0)", cmp == 1);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, zero, x));
            result.confirm("bigint_mp_cmp(0, +)", cmp == -1);

            TEST_FFI_RC(0, botan_mp_is_negative, (x));
            TEST_FFI_RC(1, botan_mp_is_positive, (x));
            TEST_FFI_OK(botan_mp_flip_sign, (x));
            TEST_FFI_RC(1, botan_mp_is_negative, (x));
            TEST_FFI_RC(0, botan_mp_is_positive, (x));

            // test no negative zero
            TEST_FFI_RC(0, botan_mp_is_negative, (zero));
            TEST_FFI_RC(1, botan_mp_is_positive, (zero));
            TEST_FFI_OK(botan_mp_flip_sign, (zero));
            TEST_FFI_RC(0, botan_mp_is_negative, (zero));
            TEST_FFI_RC(1, botan_mp_is_positive, (zero));

            TEST_FFI_OK(botan_mp_cmp, (&cmp, x, zero));
            result.confirm("bigint_mp_cmp(-, 0)", cmp == -1);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, zero, x));
            result.confirm("bigint_mp_cmp(0, -)", cmp == 1);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, zero, zero));
            result.confirm("bigint_mp_cmp(0, 0)", cmp == 0);

            TEST_FFI_OK(botan_mp_cmp, (&cmp, x, x));
            result.confirm("bigint_mp_cmp(x, x)", cmp == 0);

            TEST_FFI_OK(botan_mp_flip_sign, (x));

            botan_mp_destroy(zero);
         }

         size_t x_bits = 0;
         TEST_FFI_OK(botan_mp_num_bits, (x, &x_bits));
         result.test_eq("botan_mp_num_bits", x_bits, 9);

         TEST_FFI_OK(botan_mp_to_hex, (x, str_buf));
         result.test_eq("botan_mp_to_hex", std::string(str_buf), "0x0103");

         uint32_t x_32;
         TEST_FFI_OK(botan_mp_to_uint32, (x, &x_32));
         result.test_eq("botan_mp_to_uint32", size_t(x_32), size_t(0x103));

         TEST_FFI_RC(1, botan_mp_get_bit, (x, 1));
         TEST_FFI_RC(0, botan_mp_get_bit, (x, 87));
         TEST_FFI_OK(botan_mp_set_bit, (x, 87));
         TEST_FFI_RC(1, botan_mp_get_bit, (x, 87));
         TEST_FFI_OK(botan_mp_to_hex, (x, str_buf));
         result.test_eq("botan_mp_set_bit", std::string(str_buf), "0x8000000000000000000103");

         TEST_FFI_OK(botan_mp_clear_bit, (x, 87));
         TEST_FFI_OK(botan_mp_to_hex, (x, str_buf));
         result.test_eq("botan_mp_set_bit", std::string(str_buf), "0x0103");

         botan_mp_t y;
         TEST_FFI_OK(botan_mp_init, (&y));
         TEST_FFI_OK(botan_mp_set_from_int, (y, 0x1234567));

         botan_mp_t r;
         botan_mp_init(&r);

         TEST_FFI_OK(botan_mp_add, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_add", std::string(str_buf), "19089002");

         TEST_FFI_OK(botan_mp_mul, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_mul", std::string(str_buf), "4943984437");
         TEST_FFI_RC(0, botan_mp_is_negative, (r));

         botan_mp_t q;
         botan_mp_init(&q);
         TEST_FFI_OK(botan_mp_div, (q, r, y, x));

         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (q, 10, str_buf, &str_len));
         result.test_eq("botan_mp_div_q", std::string(str_buf), "73701");

         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_div_r", std::string(str_buf), "184");

         TEST_FFI_OK(botan_mp_set_from_str, (y, "4943984437"));
         TEST_FFI_OK(botan_mp_sub, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_sub", std::string(str_buf), "-4943984178");
         TEST_FFI_RC(1, botan_mp_is_negative, (r));

         TEST_FFI_OK(botan_mp_lshift, (r, x, 39));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_lshift", std::string(str_buf), "142386755796992");

         TEST_FFI_OK(botan_mp_rshift, (r, r, 3));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_rshift", std::string(str_buf), "17798344474624");

         TEST_FFI_OK(botan_mp_gcd, (r, x, y));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_gcd", std::string(str_buf), "259");

         botan_mp_t p;
         botan_mp_init(&p);
         const uint8_t M127[] = {
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
         TEST_FFI_OK(botan_mp_from_bin, (p, M127, sizeof(M127)));
         TEST_FFI_RC(1, botan_mp_is_prime, (p, rng, 64));

         size_t p_bits = 0;
         TEST_FFI_OK(botan_mp_num_bits, (p, &p_bits));
         result.test_eq("botan_mp_num_bits", p_bits, 127);

         TEST_FFI_OK(botan_mp_mod_inverse, (r, x, p));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_mod_inverse", std::string(str_buf), "40728777507911553541948312086427855425");

         TEST_FFI_OK(botan_mp_powmod, (r, x, r, p));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_powmod", std::string(str_buf), "40550417419160441638948180641668117560");

         TEST_FFI_OK(botan_mp_num_bytes, (r, &bn_bytes));
         result.test_eq("botan_mp_num_bytes", bn_bytes, 16);

         std::vector<uint8_t> bn_buf;
         bn_buf.resize(bn_bytes);
         botan_mp_to_bin(r, bn_buf.data());
         result.test_eq("botan_mp_to_bin", bn_buf, "1E81B9EFE0BE1902F6D03F9F5E5FB438");

         TEST_FFI_OK(botan_mp_set_from_mp, (y, r));
         TEST_FFI_OK(botan_mp_mod_mul, (r, x, y, p));
         str_len = sizeof(str_buf);
         TEST_FFI_OK(botan_mp_to_str, (r, 10, str_buf, &str_len));
         result.test_eq("botan_mp_mod_mul", std::string(str_buf), "123945920473931248854653259523111998693");

         str_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE, botan_mp_to_str, (r, 10, str_buf, &str_len));

         size_t x_bytes;
         botan_mp_rand_bits(x, rng, 512);
         TEST_FFI_OK(botan_mp_num_bytes, (x, &x_bytes));
         result.test_lte("botan_mp_num_bytes", x_bytes, 512 / 8);

         TEST_FFI_OK(botan_mp_set_from_radix_str, (x, "909A", 16));
         TEST_FFI_OK(botan_mp_to_uint32, (x, &x_32));
         result.test_eq("botan_mp_set_from_radix_str(16)", x_32, static_cast<size_t>(0x909A));

         TEST_FFI_OK(botan_mp_set_from_radix_str, (x, "9098135", 10));
         TEST_FFI_OK(botan_mp_to_uint32, (x, &x_32));
         result.test_eq("botan_mp_set_from_radix_str(10)", x_32, static_cast<size_t>(9098135));

         botan_mp_destroy(p);
         botan_mp_destroy(x);
         botan_mp_destroy(y);
         botan_mp_destroy(r);
         botan_mp_destroy(q);
      }
};

class FFI_FPE_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI FPE"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const uint8_t key[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

         botan_mp_t n;
         botan_mp_init(&n);
         botan_mp_set_from_str(n, "1000000000");

         botan_fpe_t fpe;
         if(!TEST_FFI_INIT(botan_fpe_fe1_init, (&fpe, n, key, sizeof(key), 5, 0))) {
            botan_mp_destroy(n);
            return;
         }

         botan_mp_t x;
         botan_mp_init(&x);
         botan_mp_set_from_str(x, "178051120");

         TEST_FFI_OK(botan_fpe_encrypt, (fpe, x, nullptr, 0));

         uint32_t xval = 0;
         TEST_FFI_OK(botan_mp_to_uint32, (x, &xval));
         result.test_eq("Expected FPE ciphertext", xval, size_t(605648666));

         TEST_FFI_OK(botan_fpe_encrypt, (fpe, x, nullptr, 0));
         TEST_FFI_OK(botan_fpe_decrypt, (fpe, x, nullptr, 0));
         TEST_FFI_OK(botan_fpe_decrypt, (fpe, x, nullptr, 0));

         TEST_FFI_OK(botan_mp_to_uint32, (x, &xval));
         result.test_eq("FPE round trip", xval, size_t(178051120));

         TEST_FFI_OK(botan_fpe_destroy, (fpe));
         TEST_FFI_OK(botan_mp_destroy, (x));
         TEST_FFI_OK(botan_mp_destroy, (n));
      }
};

class FFI_TOTP_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI TOTP"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const std::vector<uint8_t> key = Botan::hex_decode("3132333435363738393031323334353637383930");
         const size_t digits = 8;
         const size_t timestep = 30;
         botan_totp_t totp;

         if(!TEST_FFI_INIT(botan_totp_init, (&totp, key.data(), key.size(), "SHA-1", digits, timestep))) {
            return;
         }

         uint32_t code;
         TEST_FFI_OK(botan_totp_generate, (totp, &code, 59));
         result.confirm("TOTP code", code == 94287082);

         TEST_FFI_OK(botan_totp_generate, (totp, &code, 1111111109));
         result.confirm("TOTP code 2", code == 7081804);

         TEST_FFI_OK(botan_totp_check, (totp, 94287082, 59 + 60, 60));
         TEST_FFI_RC(1, botan_totp_check, (totp, 94287082, 59 + 31, 1));
         TEST_FFI_RC(1, botan_totp_check, (totp, 94287082, 59 + 61, 1));

         TEST_FFI_OK(botan_totp_destroy, (totp));
      }
};

class FFI_HOTP_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI HOTP"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const std::vector<uint8_t> key = Botan::hex_decode("3132333435363738393031323334353637383930");
         const size_t digits = 6;

         botan_hotp_t hotp;
         uint32_t hotp_val;

         if(!TEST_FFI_INIT(botan_hotp_init, (&hotp, key.data(), key.size(), "SHA-1", digits))) {
            return;
         }

         TEST_FFI_OK(botan_hotp_generate, (hotp, &hotp_val, 0));
         result.confirm("Valid value for counter 0", hotp_val == 755224);
         TEST_FFI_OK(botan_hotp_generate, (hotp, &hotp_val, 1));
         result.confirm("Valid value for counter 0", hotp_val == 287082);
         TEST_FFI_OK(botan_hotp_generate, (hotp, &hotp_val, 2));
         result.confirm("Valid value for counter 0", hotp_val == 359152);
         TEST_FFI_OK(botan_hotp_generate, (hotp, &hotp_val, 0));
         result.confirm("Valid value for counter 0", hotp_val == 755224);

         uint64_t next_ctr = 0;

         TEST_FFI_OK(botan_hotp_check, (hotp, &next_ctr, 755224, 0, 0));
         result.confirm("HOTP resync", next_ctr == 1);
         TEST_FFI_OK(botan_hotp_check, (hotp, nullptr, 359152, 2, 0));
         TEST_FFI_RC(1, botan_hotp_check, (hotp, nullptr, 359152, 1, 0));
         TEST_FFI_OK(botan_hotp_check, (hotp, &next_ctr, 359152, 0, 2));
         result.confirm("HOTP resync", next_ctr == 3);

         TEST_FFI_OK(botan_hotp_destroy, (hotp));
      }
};

class FFI_Keywrap_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Keywrap"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const uint8_t key[16] = {0};
         const uint8_t kek[16] = {0xFF, 0};

         uint8_t wrapped[16 + 8] = {0};
         size_t wrapped_keylen = sizeof(wrapped);

         if(TEST_FFI_INIT(botan_key_wrap3394, (key, sizeof(key), kek, sizeof(kek), wrapped, &wrapped_keylen))) {
            const uint8_t expected_wrapped_key[16 + 8] = {0x04, 0x13, 0x37, 0x39, 0x82, 0xCF, 0xFA, 0x31,
                                                          0x81, 0xCA, 0x4F, 0x59, 0x74, 0x4D, 0xED, 0x29,
                                                          0x1F, 0x3F, 0xE5, 0x24, 0x00, 0x1B, 0x93, 0x20};

            result.test_eq("Expected wrapped keylen size", wrapped_keylen, 16 + 8);

            result.test_eq(
               nullptr, "Wrapped key", wrapped, wrapped_keylen, expected_wrapped_key, sizeof(expected_wrapped_key));

            uint8_t dec_key[16] = {0};
            size_t dec_keylen = sizeof(dec_key);
            TEST_FFI_OK(botan_key_unwrap3394, (wrapped, sizeof(wrapped), kek, sizeof(kek), dec_key, &dec_keylen));

            result.test_eq(nullptr, "Unwrapped key", dec_key, dec_keylen, key, sizeof(key));
         }
      }
};

class FFI_XMSS_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI XMSS"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_privkey_t priv;
         if(TEST_FFI_INIT(botan_privkey_create, (&priv, "XMSS", "XMSS-SHA2_10_256", rng))) {
            TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

            TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_privkey_stateful_operation, (priv, nullptr));
            TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_privkey_remaining_operations, (priv, nullptr));

            int stateful;
            TEST_FFI_OK(botan_privkey_stateful_operation, (priv, &stateful));
            result.confirm("key is stateful", stateful, true);

            uint64_t remaining;
            TEST_FFI_OK(botan_privkey_remaining_operations, (priv, &remaining));
            result.confirm("key has remaining operations", remaining == 1024, true);

            TEST_FFI_OK(botan_privkey_destroy, (priv));
         }
      }
};

class FFI_RSA_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI RSA"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_privkey_t priv;

         if(TEST_FFI_INIT(botan_privkey_create_rsa, (&priv, rng, 1024))) {
            TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

            int stateful;
            TEST_FFI_OK(botan_privkey_stateful_operation, (priv, &stateful));
            result.confirm("key is not stateful", stateful, false);

            uint64_t remaining;
            TEST_FFI_FAIL("key is not stateful", botan_privkey_remaining_operations, (priv, &remaining));

            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
            TEST_FFI_OK(botan_pubkey_check_key, (pub, rng, 0));

            ffi_test_pubkey_export(result, pub, priv, rng);

            botan_mp_t p, q, d, n, e;
            botan_mp_init(&p);
            botan_mp_init(&q);
            botan_mp_init(&d);
            botan_mp_init(&n);
            botan_mp_init(&e);

            TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_privkey_get_field, (p, priv, "quux"));
            TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_pubkey_get_field, (p, pub, "quux"));

            TEST_FFI_OK(botan_privkey_rsa_get_p, (p, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_q, (q, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_d, (d, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_e, (e, priv));
            TEST_FFI_OK(botan_privkey_rsa_get_n, (n, priv));

            // Confirm same (e,n) values in public key
            {
               botan_mp_t pub_e, pub_n;
               botan_mp_init(&pub_e);
               botan_mp_init(&pub_n);
               TEST_FFI_OK(botan_pubkey_rsa_get_e, (pub_e, pub));
               TEST_FFI_OK(botan_pubkey_rsa_get_n, (pub_n, pub));

               TEST_FFI_RC(1, botan_mp_equal, (pub_e, e));
               TEST_FFI_RC(1, botan_mp_equal, (pub_n, n));
               botan_mp_destroy(pub_e);
               botan_mp_destroy(pub_n);
            }

            TEST_FFI_RC(1, botan_mp_is_prime, (p, rng, 64));
            TEST_FFI_RC(1, botan_mp_is_prime, (q, rng, 64));

            // Test p != q
            TEST_FFI_RC(0, botan_mp_equal, (p, q));

            // Test p * q == n
            botan_mp_t x;
            botan_mp_init(&x);
            TEST_FFI_OK(botan_mp_mul, (x, p, q));

            TEST_FFI_RC(1, botan_mp_equal, (x, n));
            botan_mp_destroy(x);

            botan_privkey_t loaded_privkey;
            // First try loading a bogus key and verify check_key fails
            TEST_FFI_OK(botan_privkey_load_rsa, (&loaded_privkey, n, d, q));
            TEST_FFI_RC(-1, botan_privkey_check_key, (loaded_privkey, rng, 0));
            botan_privkey_destroy(loaded_privkey);

            TEST_FFI_OK(botan_privkey_load_rsa, (&loaded_privkey, p, q, e));
            TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));

            botan_pubkey_t loaded_pubkey;
            TEST_FFI_OK(botan_pubkey_load_rsa, (&loaded_pubkey, n, e));
            TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

            botan_mp_destroy(p);
            botan_mp_destroy(q);
            botan_mp_destroy(d);
            botan_mp_destroy(e);
            botan_mp_destroy(n);

            size_t pkcs1_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_privkey_rsa_get_privkey,
                        (loaded_privkey, nullptr, &pkcs1_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

            std::vector<uint8_t> pkcs1(pkcs1_len);
            TEST_FFI_OK(botan_privkey_rsa_get_privkey,
                        (loaded_privkey, pkcs1.data(), &pkcs1_len, BOTAN_PRIVKEY_EXPORT_FLAG_DER));

            botan_privkey_t privkey_from_pkcs1;
            TEST_FFI_OK(botan_privkey_load_rsa_pkcs1, (&privkey_from_pkcs1, pkcs1.data(), pkcs1_len));
            TEST_FFI_OK(botan_privkey_destroy, (privkey_from_pkcs1));

            pkcs1_len = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_privkey_rsa_get_privkey,
                        (loaded_privkey, nullptr, &pkcs1_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));
            pkcs1.resize(pkcs1_len);
            TEST_FFI_OK(botan_privkey_rsa_get_privkey,
                        (loaded_privkey, pkcs1.data(), &pkcs1_len, BOTAN_PRIVKEY_EXPORT_FLAG_PEM));

            char namebuf[32] = {0};
            size_t name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_pubkey_algo_name, (loaded_pubkey, namebuf, &name_len))) {
               result.test_eq("algo name", std::string(namebuf), "RSA");
            }

            name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_privkey_algo_name, (loaded_privkey, namebuf, &name_len))) {
               result.test_eq("algo name", std::string(namebuf), "RSA");
            }

            botan_pk_op_encrypt_t encrypt;
            if(TEST_FFI_INIT(botan_pk_op_encrypt_create, (&encrypt, loaded_pubkey, "OAEP(SHA-256)", 0))) {
               std::vector<uint8_t> plaintext(32);
               TEST_FFI_OK(botan_rng_get, (rng, plaintext.data(), plaintext.size()));

               size_t ctext_len;
               TEST_FFI_OK(botan_pk_op_encrypt_output_length, (encrypt, plaintext.size(), &ctext_len));
               std::vector<uint8_t> ciphertext(ctext_len);

               if(TEST_FFI_OK(botan_pk_op_encrypt,
                              (encrypt, rng, ciphertext.data(), &ctext_len, plaintext.data(), plaintext.size()))) {
                  ciphertext.resize(ctext_len);

                  botan_pk_op_decrypt_t decrypt;
                  if(TEST_FFI_OK(botan_pk_op_decrypt_create, (&decrypt, priv, "OAEP(SHA-256)", 0))) {
                     size_t decrypted_len;
                     TEST_FFI_OK(botan_pk_op_decrypt_output_length, (decrypt, ciphertext.size(), &decrypted_len));
                     std::vector<uint8_t> decrypted(decrypted_len);
                     TEST_FFI_OK(botan_pk_op_decrypt,
                                 (decrypt, decrypted.data(), &decrypted_len, ciphertext.data(), ciphertext.size()));
                     decrypted.resize(decrypted_len);

                     result.test_eq("RSA plaintext", decrypted, plaintext);
                  }

                  TEST_FFI_OK(botan_pk_op_decrypt_destroy, (decrypt));
               }

               TEST_FFI_OK(botan_pk_op_encrypt_destroy, (encrypt));
            }

            TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
         }
      }
};

class FFI_DSA_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI DSA"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_privkey_t priv;

         if(TEST_FFI_INIT(botan_privkey_create, (&priv, "DSA", "dsa/jce/1024", rng))) {
            do_dsa_test(priv, rng, result);
         }

         if(TEST_FFI_INIT(botan_privkey_create_dsa, (&priv, rng, 1024, 160))) {
            do_dsa_test(priv, rng, result);
         }
      }

   private:
      static void do_dsa_test(botan_privkey_t priv, botan_rng_t rng, Test::Result& result) {
         TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

         botan_pubkey_t pub;
         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
         TEST_FFI_OK(botan_pubkey_check_key, (pub, rng, 0));

         ffi_test_pubkey_export(result, pub, priv, rng);

         botan_mp_t p, q, g, x, y;
         botan_mp_init(&p);
         botan_mp_init(&q);
         botan_mp_init(&g);
         botan_mp_init(&x);
         botan_mp_init(&y);

         TEST_FFI_OK(botan_privkey_dsa_get_x, (x, priv));
         TEST_FFI_OK(botan_pubkey_dsa_get_g, (g, pub));
         TEST_FFI_OK(botan_pubkey_dsa_get_p, (p, pub));
         TEST_FFI_OK(botan_pubkey_dsa_get_q, (q, pub));
         TEST_FFI_OK(botan_pubkey_dsa_get_y, (y, pub));

         botan_mp_t cmp;
         botan_mp_init(&cmp);
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_privkey_get_field, (cmp, priv, "quux"));

         TEST_FFI_OK(botan_privkey_get_field, (cmp, priv, "x"));
         TEST_FFI_RC(1, botan_mp_equal, (cmp, x));

         TEST_FFI_OK(botan_privkey_get_field, (cmp, priv, "y"));
         TEST_FFI_RC(1, botan_mp_equal, (cmp, y));

         TEST_FFI_OK(botan_privkey_get_field, (cmp, priv, "p"));
         TEST_FFI_RC(1, botan_mp_equal, (cmp, p));
         botan_mp_destroy(cmp);

         botan_privkey_t loaded_privkey;
         TEST_FFI_OK(botan_privkey_load_dsa, (&loaded_privkey, p, q, g, x));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));

         botan_pubkey_t loaded_pubkey;
         TEST_FFI_OK(botan_pubkey_load_dsa, (&loaded_pubkey, p, q, g, y));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

         botan_mp_destroy(p);
         botan_mp_destroy(q);
         botan_mp_destroy(g);
         botan_mp_destroy(y);
         botan_mp_destroy(x);

         botan_pk_op_sign_t signer;

         std::vector<uint8_t> message(6, 6);
         std::vector<uint8_t> signature;

         if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, loaded_privkey, "SHA-256", 0))) {
            // TODO: break input into multiple calls to update
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message.data(), message.size()));

            size_t sig_len;
            TEST_FFI_OK(botan_pk_op_sign_output_length, (signer, &sig_len));
            signature.resize(sig_len);

            size_t output_sig_len = sig_len;
            TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &output_sig_len));
            result.test_lte("Output length is upper bound", output_sig_len, sig_len);
            signature.resize(output_sig_len);

            TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
         }

         botan_pk_op_verify_t verifier = nullptr;

         if(!signature.empty() && TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, "SHA-256", 0))) {
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            // TODO: randomize this
            signature[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_RC(
               BOTAN_FFI_INVALID_VERIFIER, botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            message[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_RC(
               BOTAN_FFI_INVALID_VERIFIER, botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            signature[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_RC(
               BOTAN_FFI_INVALID_VERIFIER, botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            message[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));
         }

         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
      }
};

class FFI_ECDSA_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI ECDSA"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         static const char* kCurve = "secp384r1";
         botan_privkey_t priv;
         botan_pubkey_t pub;

         if(!TEST_FFI_INIT(botan_privkey_create_ecdsa, (&priv, rng, kCurve))) {
            return;
         }

         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
         ffi_test_pubkey_export(result, pub, priv, rng);

         // Check key load functions
         botan_mp_t private_scalar, public_x, public_y;
         botan_mp_init(&private_scalar);
         botan_mp_init(&public_x);
         botan_mp_init(&public_y);

         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_privkey_get_field, (private_scalar, priv, "quux"));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_pubkey_get_field, (private_scalar, pub, "quux"));

         TEST_FFI_OK(botan_privkey_get_field, (private_scalar, priv, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_x, pub, "public_x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub, "public_y"));

         botan_privkey_t loaded_privkey;
         botan_pubkey_t loaded_pubkey;
         TEST_FFI_OK(botan_privkey_load_ecdsa, (&loaded_privkey, private_scalar, kCurve));
         TEST_FFI_OK(botan_pubkey_load_ecdsa, (&loaded_pubkey, public_x, public_y, kCurve));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

         char namebuf[32] = {0};
         size_t name_len = sizeof(namebuf);

         TEST_FFI_OK(botan_pubkey_algo_name, (pub, &namebuf[0], &name_len));
         result.test_eq(namebuf, namebuf, "ECDSA");

         std::vector<uint8_t> message(1280), signature;
         TEST_FFI_OK(botan_rng_get, (rng, message.data(), message.size()));

         for(uint32_t flags = 0; flags <= 1; ++flags) {
            botan_pk_op_sign_t signer;
            if(TEST_FFI_INIT(botan_pk_op_sign_create, (&signer, loaded_privkey, "SHA-384", flags))) {
               // TODO: break input into multiple calls to update
               TEST_FFI_OK(botan_pk_op_sign_update, (signer, message.data(), message.size()));

               size_t sig_len;
               TEST_FFI_OK(botan_pk_op_sign_output_length, (signer, &sig_len));

               signature.resize(sig_len);

               size_t output_sig_len = signature.size();
               TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &output_sig_len));
               signature.resize(output_sig_len);

               TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
            }

            botan_pk_op_verify_t verifier = nullptr;

            if(!signature.empty() && TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, "SHA-384", flags))) {
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

               // TODO: randomize this
               signature[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_RC(BOTAN_FFI_INVALID_VERIFIER,
                           botan_pk_op_verify_finish,
                           (verifier, signature.data(), signature.size()));

               message[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_RC(BOTAN_FFI_INVALID_VERIFIER,
                           botan_pk_op_verify_finish,
                           (verifier, signature.data(), signature.size()));

               signature[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_RC(BOTAN_FFI_INVALID_VERIFIER,
                           botan_pk_op_verify_finish,
                           (verifier, signature.data(), signature.size()));

               message[0] ^= 1;
               TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
               TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

               TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));
            }
         }

         TEST_FFI_OK(botan_mp_destroy, (private_scalar));
         TEST_FFI_OK(botan_mp_destroy, (public_x));
         TEST_FFI_OK(botan_mp_destroy, (public_y));
         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
      }
};

class FFI_SM2_Sig_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI SM2 Sig"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         static const char* kCurve = "sm2p256v1";
         const std::string sm2_ident = "SM2 Ident Field";
         botan_privkey_t priv;
         botan_pubkey_t pub;
         botan_privkey_t loaded_privkey;
         botan_pubkey_t loaded_pubkey;

         if(!TEST_FFI_INIT(botan_privkey_create, (&priv, "SM2_Sig", kCurve, rng))) {
            return;
         }

         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
         ffi_test_pubkey_export(result, pub, priv, rng);

         uint8_t za[32];
         size_t sizeof_za = sizeof(za);
         TEST_FFI_OK(botan_pubkey_sm2_compute_za, (za, &sizeof_za, "Ident", "SM3", pub));

         // Check key load functions
         botan_mp_t private_scalar, public_x, public_y;
         botan_mp_init(&private_scalar);
         botan_mp_init(&public_x);
         botan_mp_init(&public_y);

         TEST_FFI_OK(botan_privkey_get_field, (private_scalar, priv, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_x, pub, "public_x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub, "public_y"));
         REQUIRE_FFI_OK(botan_privkey_load_sm2, (&loaded_privkey, private_scalar, kCurve));
         REQUIRE_FFI_OK(botan_pubkey_load_sm2, (&loaded_pubkey, public_x, public_y, kCurve));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

         char namebuf[32] = {0};
         size_t name_len = sizeof(namebuf);

         TEST_FFI_OK(botan_pubkey_algo_name, (pub, &namebuf[0], &name_len));
         result.test_eq(namebuf, namebuf, "SM2");

         std::vector<uint8_t> message(1280), signature;
         TEST_FFI_OK(botan_rng_get, (rng, message.data(), message.size()));
         botan_pk_op_sign_t signer;
         if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, loaded_privkey, sm2_ident.c_str(), 0))) {
            // TODO: break input into multiple calls to update
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message.data(), message.size()));

            size_t sig_len;
            TEST_FFI_OK(botan_pk_op_sign_output_length, (signer, &sig_len));

            signature.resize(sig_len);

            TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &sig_len));
            signature.resize(sig_len);

            TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
         }

         botan_pk_op_verify_t verifier = nullptr;

         if(!signature.empty() && TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, sm2_ident.c_str(), 0))) {
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            // TODO: randomize this
            signature[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_RC(
               BOTAN_FFI_INVALID_VERIFIER, botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            message[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_RC(
               BOTAN_FFI_INVALID_VERIFIER, botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            signature[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_RC(
               BOTAN_FFI_INVALID_VERIFIER, botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            message[0] ^= 1;
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));
         }

         TEST_FFI_OK(botan_mp_destroy, (private_scalar));
         TEST_FFI_OK(botan_mp_destroy, (public_x));
         TEST_FFI_OK(botan_mp_destroy, (public_y));
         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
      }
};

class FFI_SM2_Enc_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI SM2 Enc"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         static const char* kCurve = "sm2p256v1";
         botan_privkey_t priv;
         botan_pubkey_t pub;
         botan_privkey_t loaded_privkey;
         botan_pubkey_t loaded_pubkey;

         if(!TEST_FFI_INIT(botan_privkey_create, (&priv, "SM2_Enc", kCurve, rng))) {
            return;
         }

         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
         ffi_test_pubkey_export(result, pub, priv, rng);

         uint8_t za[32];
         size_t sizeof_za = sizeof(za);
         TEST_FFI_OK(botan_pubkey_sm2_compute_za, (za, &sizeof_za, "Ident", "SM3", pub));

         // Check key load functions
         botan_mp_t private_scalar, public_x, public_y;
         botan_mp_init(&private_scalar);
         botan_mp_init(&public_x);
         botan_mp_init(&public_y);

         TEST_FFI_OK(botan_privkey_get_field, (private_scalar, priv, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_x, pub, "public_x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub, "public_y"));
         REQUIRE_FFI_OK(botan_privkey_load_sm2_enc, (&loaded_privkey, private_scalar, kCurve));
         REQUIRE_FFI_OK(botan_pubkey_load_sm2_enc, (&loaded_pubkey, public_x, public_y, kCurve));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey, rng, 0));

         char namebuf[32] = {0};
         size_t name_len = sizeof(namebuf);

         TEST_FFI_OK(botan_pubkey_algo_name, (pub, &namebuf[0], &name_len));
         result.test_eq(namebuf, namebuf, "SM2");

         std::vector<uint8_t> message(32);

         std::vector<uint8_t> ciphertext;
         TEST_FFI_OK(botan_rng_get, (rng, message.data(), message.size()));

         botan_pk_op_encrypt_t enc;
         if(TEST_FFI_OK(botan_pk_op_encrypt_create, (&enc, loaded_pubkey, "", 0))) {
            size_t ctext_len;
            TEST_FFI_OK(botan_pk_op_encrypt_output_length, (enc, message.size(), &ctext_len));

            ciphertext.resize(ctext_len);
            TEST_FFI_OK(botan_pk_op_encrypt, (enc, rng, ciphertext.data(), &ctext_len, message.data(), message.size()));
            ciphertext.resize(ctext_len);

            botan_pk_op_decrypt_t dec;
            TEST_FFI_OK(botan_pk_op_decrypt_create, (&dec, loaded_privkey, "", 0));

            std::vector<uint8_t> recovered(message.size());
            size_t recovered_len = recovered.size();

            TEST_FFI_OK(botan_pk_op_decrypt,
                        (dec, recovered.data(), &recovered_len, ciphertext.data(), ciphertext.size()));

            botan_pk_op_decrypt_destroy(dec);
         }
         botan_pk_op_encrypt_destroy(enc);

         TEST_FFI_OK(botan_mp_destroy, (private_scalar));
         TEST_FFI_OK(botan_mp_destroy, (public_x));
         TEST_FFI_OK(botan_mp_destroy, (public_y));
         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
      }
};

class FFI_ECDH_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI ECDH"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_privkey_t priv1;
         if(!TEST_FFI_INIT(botan_privkey_create_ecdh, (&priv1, rng, "secp256r1"))) {
            return;
         }

         botan_privkey_t priv2;
         REQUIRE_FFI_OK(botan_privkey_create_ecdh, (&priv2, rng, "secp256r1"));

         botan_pubkey_t pub1;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub1, priv1));

         botan_pubkey_t pub2;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub2, priv2));

         /* Reload key-pair1 in order to test functions for key loading */
         botan_mp_t private_scalar, public_x, public_y;
         botan_mp_init(&private_scalar);
         botan_mp_init(&public_x);
         botan_mp_init(&public_y);

         TEST_FFI_OK(botan_privkey_get_field, (private_scalar, priv1, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_x, pub1, "public_x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub1, "public_y"));

         botan_privkey_t loaded_privkey1;
         botan_pubkey_t loaded_pubkey1;
         REQUIRE_FFI_OK(botan_privkey_load_ecdh, (&loaded_privkey1, private_scalar, "secp256r1"));
         REQUIRE_FFI_OK(botan_pubkey_load_ecdh, (&loaded_pubkey1, public_x, public_y, "secp256r1"));
         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey1, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey1, rng, 0));

         ffi_test_pubkey_export(result, loaded_pubkey1, priv1, rng);
         ffi_test_pubkey_export(result, pub2, priv2, rng);

   #if defined(BOTAN_HAS_KDF2) && defined(BOTAN_HAS_SHA_256)
         constexpr bool has_kdf2_sha256 = true;
   #else
         constexpr bool has_kdf2_sha256 = false;
   #endif

         const char* kdf = has_kdf2_sha256 ? "KDF2(SHA-256)" : "Raw";
         constexpr size_t salt_len = has_kdf2_sha256 ? 32 : 0;

         botan_pk_op_ka_t ka1;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka1, loaded_privkey1, kdf, 0));
         botan_pk_op_ka_t ka2;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka2, priv2, kdf, 0));

         size_t pubkey1_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                     botan_pk_op_key_agreement_export_public,
                     (priv1, nullptr, &pubkey1_len));
         std::vector<uint8_t> pubkey1(pubkey1_len);
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_export_public, (priv1, pubkey1.data(), &pubkey1_len));
         size_t pubkey2_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                     botan_pk_op_key_agreement_export_public,
                     (priv2, nullptr, &pubkey2_len));
         std::vector<uint8_t> pubkey2(pubkey2_len);
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_export_public, (priv2, pubkey2.data(), &pubkey2_len));

         std::vector<uint8_t> salt(salt_len);
         TEST_FFI_OK(botan_rng_get, (rng, salt.data(), salt.size()));

         const size_t shared_key_len = 32;

         std::vector<uint8_t> key1(shared_key_len);
         size_t key1_len = key1.size();
         TEST_FFI_OK(botan_pk_op_key_agreement,
                     (ka1, key1.data(), &key1_len, pubkey2.data(), pubkey2.size(), salt.data(), salt.size()));

         std::vector<uint8_t> key2(shared_key_len);
         size_t key2_len = key2.size();
         TEST_FFI_OK(botan_pk_op_key_agreement,
                     (ka2, key2.data(), &key2_len, pubkey1.data(), pubkey1.size(), salt.data(), salt.size()));

         result.test_eq("shared ECDH key", key1, key2);

         TEST_FFI_OK(botan_mp_destroy, (private_scalar));
         TEST_FFI_OK(botan_mp_destroy, (public_x));
         TEST_FFI_OK(botan_mp_destroy, (public_y));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka1));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka2));
         TEST_FFI_OK(botan_privkey_destroy, (priv1));
         TEST_FFI_OK(botan_privkey_destroy, (priv2));
         TEST_FFI_OK(botan_pubkey_destroy, (pub1));
         TEST_FFI_OK(botan_pubkey_destroy, (pub2));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey1));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey1));
      }
};

class FFI_McEliece_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI McEliece"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_privkey_t priv;
         if(TEST_FFI_INIT(botan_privkey_create_mceliece, (&priv, rng, 2048, 50))) {
            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            ffi_test_pubkey_export(result, pub, priv, rng);

            char namebuf[32] = {0};
            size_t name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_pubkey_algo_name, (pub, namebuf, &name_len))) {
               result.test_eq("algo name", std::string(namebuf), "McEliece");
            }

            // TODO test KEM

            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
         }
      }
};

class FFI_Ed25519_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Ed25519"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_pubkey_t pub;
         botan_privkey_t priv;

         // From draft-koch-eddsa-for-openpgp-04
         const std::vector<uint8_t> seed =
            Botan::hex_decode("1a8b1ff05ded48e18bf50166c664ab023ea70003d78d9e41f5758a91d850f8d2");
         const std::vector<uint8_t> pubkey =
            Botan::hex_decode("3f098994bdd916ed4053197934e4a87c80733a1280d62f8010992e43ee3b2406");
         const std::vector<uint8_t> message = Botan::hex_decode("4f70656e504750040016080006050255f95f9504ff0000000c");
         const std::vector<uint8_t> exp_sig = Botan::hex_decode(
            "56f90cca98e2102637bd983fdb16c131dfd27ed82bf4dde5606e0d756aed3366"
            "d09c4fa11527f038e0f57f2201d82f2ea2c9033265fa6ceb489e854bae61b404");

         if(!TEST_FFI_INIT(botan_privkey_load_ed25519, (&priv, seed.data()))) {
            return;
         }

         uint8_t retr_privkey[64];
         TEST_FFI_OK(botan_privkey_ed25519_get_privkey, (priv, retr_privkey));

         result.test_eq(nullptr, "Public key matches", retr_privkey + 32, 32, pubkey.data(), pubkey.size());

         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

         uint8_t retr_pubkey[32];
         TEST_FFI_OK(botan_pubkey_ed25519_get_pubkey, (pub, retr_pubkey));
         result.test_eq(nullptr, "Public key matches", retr_pubkey, 32, pubkey.data(), pubkey.size());

         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_pubkey_load_ed25519, (&pub, pubkey.data()));

         botan_pk_op_sign_t signer;
         std::vector<uint8_t> signature;

         if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, priv, "SHA-256", 0))) {
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message.data(), message.size()));

            size_t sig_len;
            TEST_FFI_OK(botan_pk_op_sign_output_length, (signer, &sig_len));

            signature.resize(sig_len);

            TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &sig_len));
            signature.resize(sig_len);

            TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
         }

         result.test_eq("Expected signature", signature, exp_sig);

         botan_pk_op_verify_t verifier;

         if(TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, "SHA-256", 0))) {
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message.data(), message.size()));
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));
         }

         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
      }
};

class FFI_Ed448_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Ed448"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_pubkey_t pub;
         botan_privkey_t priv;

         // RFC 8032: Testvector Ed448, 1 octet
         const auto sk = Botan::hex_decode(
            "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
         const auto pk_ref = Botan::hex_decode(
            "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
         const auto msg = Botan::hex_decode("03");
         const auto sig_ref = Botan::hex_decode(
            "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00");

         if(!TEST_FFI_INIT(botan_privkey_load_ed448, (&priv, sk.data()))) {
            return;
         }

         std::vector<uint8_t> retr_privkey(57);
         TEST_FFI_OK(botan_privkey_ed448_get_privkey, (priv, retr_privkey.data()));
         result.test_is_eq("Private key matches", retr_privkey, sk);

         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

         std::vector<uint8_t> retr_pubkey(57);
         TEST_FFI_OK(botan_pubkey_ed448_get_pubkey, (pub, retr_pubkey.data()));
         result.test_is_eq("Public key matches", retr_pubkey, pk_ref);

         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_pubkey_load_ed448, (&pub, pk_ref.data()));

         botan_pk_op_sign_t signer;
         std::vector<uint8_t> signature;

         if(TEST_FFI_OK(botan_pk_op_sign_create, (&signer, priv, "Pure", 0))) {
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, msg.data(), msg.size()));

            size_t sig_len;
            TEST_FFI_OK(botan_pk_op_sign_output_length, (signer, &sig_len));

            signature.resize(sig_len);

            TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &sig_len));
            signature.resize(sig_len);

            TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
         }

         result.test_eq("Expected signature", signature, sig_ref);

         botan_pk_op_verify_t verifier;

         if(TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, "Pure", 0))) {
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, msg.data(), msg.size()));
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));

            TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));
         }

         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
      }
};

class FFI_X25519_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI X25519"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         // From RFC 8037

         const std::vector<uint8_t> a_pub_bits =
            Botan::hex_decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
         const std::vector<uint8_t> b_priv_bits =
            Botan::hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
         const std::vector<uint8_t> b_pub_bits =
            Botan::hex_decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
         const std::vector<uint8_t> shared_secret_bits =
            Botan::hex_decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

         botan_privkey_t b_priv;
         if(!TEST_FFI_INIT(botan_privkey_load_x25519, (&b_priv, b_priv_bits.data()))) {
            return;
         }

         std::vector<uint8_t> privkey_read(32);
         TEST_FFI_OK(botan_privkey_x25519_get_privkey, (b_priv, privkey_read.data()));
         result.test_eq("X25519 private key", privkey_read, b_priv_bits);

         std::vector<uint8_t> pubkey_read(32);

         botan_pubkey_t b_pub;
         TEST_FFI_OK(botan_privkey_export_pubkey, (&b_pub, b_priv));
         TEST_FFI_OK(botan_pubkey_x25519_get_pubkey, (b_pub, pubkey_read.data()));
         result.test_eq("X25519 public key b", pubkey_read, b_pub_bits);

         botan_pubkey_t a_pub;
         TEST_FFI_OK(botan_pubkey_load_x25519, (&a_pub, a_pub_bits.data()));
         TEST_FFI_OK(botan_pubkey_x25519_get_pubkey, (a_pub, pubkey_read.data()));
         result.test_eq("X25519 public key a", pubkey_read, a_pub_bits);

         botan_pk_op_ka_t ka;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka, b_priv, "Raw", 0));

         std::vector<uint8_t> shared_output(32);
         size_t shared_len = shared_output.size();
         TEST_FFI_OK(botan_pk_op_key_agreement,
                     (ka, shared_output.data(), &shared_len, a_pub_bits.data(), a_pub_bits.size(), nullptr, 0));

         result.test_eq("Shared secret matches expected", shared_secret_bits, shared_output);

         TEST_FFI_OK(botan_pubkey_destroy, (a_pub));
         TEST_FFI_OK(botan_pubkey_destroy, (b_pub));
         TEST_FFI_OK(botan_privkey_destroy, (b_priv));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka));
      }
};

class FFI_X448_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI X448"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         // From RFC 7748 Section 6.2
         const auto a_pub_ref = Botan::hex_decode(
            "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
         const auto b_priv_ref = Botan::hex_decode(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
         const auto b_pub_ref = Botan::hex_decode(
            "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
         const auto shared_secret_ref = Botan::hex_decode(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

         botan_privkey_t b_priv;
         if(!TEST_FFI_INIT(botan_privkey_load_x448, (&b_priv, b_priv_ref.data()))) {
            return;
         }

         std::vector<uint8_t> privkey_read(56);
         TEST_FFI_OK(botan_privkey_x448_get_privkey, (b_priv, privkey_read.data()));
         result.test_eq("X448 private key", privkey_read, b_priv_ref);

         std::vector<uint8_t> pubkey_read(56);

         botan_pubkey_t b_pub;
         TEST_FFI_OK(botan_privkey_export_pubkey, (&b_pub, b_priv));
         TEST_FFI_OK(botan_pubkey_x448_get_pubkey, (b_pub, pubkey_read.data()));
         result.test_eq("X448 public key b", pubkey_read, b_pub_ref);

         botan_pubkey_t a_pub;
         TEST_FFI_OK(botan_pubkey_load_x448, (&a_pub, a_pub_ref.data()));
         TEST_FFI_OK(botan_pubkey_x448_get_pubkey, (a_pub, pubkey_read.data()));
         result.test_eq("X448 public key a", pubkey_read, a_pub_ref);

         botan_pk_op_ka_t ka;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka, b_priv, "Raw", 0));

         std::vector<uint8_t> shared_output(56);
         size_t shared_len = shared_output.size();
         TEST_FFI_OK(botan_pk_op_key_agreement,
                     (ka, shared_output.data(), &shared_len, a_pub_ref.data(), a_pub_ref.size(), nullptr, 0));

         result.test_eq("Shared secret matches expected", shared_secret_ref, shared_output);

         TEST_FFI_OK(botan_pubkey_destroy, (a_pub));
         TEST_FFI_OK(botan_pubkey_destroy, (b_pub));
         TEST_FFI_OK(botan_privkey_destroy, (b_priv));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka));
      }
};

/**
 * Helper class for testing "view"-style API functions that take a callback
 * that gets passed a variable-length buffer of bytes.
 *
 * Example:
 *   botan_privkey_t priv;
 *   ViewBytesSink sink;
 *   botan_privkey_view_raw(priv, sink.delegate(), sink.callback());
 *   std::cout << hex_encode(sink.get()) << std::endl;
 */
class ViewBytesSink final {
   public:
      void* delegate() { return this; }

      botan_view_bin_fn callback() { return &write_fn; }

      const std::vector<uint8_t>& get() { return m_buf; }

   private:
      static int write_fn(void* ctx, const uint8_t buf[], size_t len) {
         if(!ctx || !buf) {
            return BOTAN_FFI_ERROR_NULL_POINTER;
         }

         auto* sink = static_cast<ViewBytesSink*>(ctx);
         sink->m_buf.assign(buf, buf + len);

         return 0;
      }

   private:
      std::vector<uint8_t> m_buf;
};

/**
 * See ViewBytesSink for how to use this. Works for `botan_view_str_fn` instead.
*/
class ViewStringSink final {
   public:
      void* delegate() { return this; }

      botan_view_str_fn callback() { return &write_fn; }

      std::string_view get() { return m_str; }

   private:
      static int write_fn(void* ctx, const char* str, size_t len) {
         if(!ctx || !str) {
            return BOTAN_FFI_ERROR_NULL_POINTER;
         }

         auto* sink = static_cast<ViewStringSink*>(ctx);
         // discard the null terminator
         sink->m_str = std::string(str, len - 1);

         return 0;
      }

   private:
      std::string m_str;
};

/**
 * Base class for roundtrip tests of FFI bindings for Key Encapsulation Mechanisms.
 */
class FFI_KEM_Roundtrip_Test : public FFI_Test {
   protected:
      using privkey_loader_fn_t = int (*)(botan_privkey_t*, const uint8_t[], size_t, const char*);
      using pubkey_loader_fn_t = int (*)(botan_pubkey_t*, const uint8_t[], size_t, const char*);

   protected:
      virtual const char* algo() const = 0;
      virtual privkey_loader_fn_t private_key_load_function() const = 0;
      virtual pubkey_loader_fn_t public_key_load_function() const = 0;
      virtual std::vector<const char*> modes() const = 0;

   public:
      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         for(auto mode : modes()) {
            // generate a key pair
            botan_privkey_t priv;
            botan_pubkey_t pub;
            if(!TEST_FFI_INIT(botan_privkey_create, (&priv, algo(), mode, rng))) {
               continue;
            }
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            // raw-encode the key pair
            ViewBytesSink priv_bytes;
            ViewBytesSink pub_bytes;
            TEST_FFI_OK(botan_privkey_view_raw, (priv, priv_bytes.delegate(), priv_bytes.callback()));
            TEST_FFI_OK(botan_pubkey_view_raw, (pub, pub_bytes.delegate(), pub_bytes.callback()));

            // decode the key pair from raw encoding
            botan_privkey_t priv_loaded;
            botan_pubkey_t pub_loaded;
            TEST_FFI_OK(private_key_load_function(),
                        (&priv_loaded, priv_bytes.get().data(), priv_bytes.get().size(), mode));
            TEST_FFI_OK(public_key_load_function(),
                        (&pub_loaded, pub_bytes.get().data(), pub_bytes.get().size(), mode));

            // re-encode and compare to the first round
            ViewBytesSink priv_bytes2;
            ViewBytesSink pub_bytes2;
            TEST_FFI_OK(botan_privkey_view_raw, (priv_loaded, priv_bytes2.delegate(), priv_bytes2.callback()));
            TEST_FFI_OK(botan_pubkey_view_raw, (pub_loaded, pub_bytes2.delegate(), pub_bytes2.callback()));
            result.test_eq("private key encoding", priv_bytes.get(), priv_bytes2.get());
            result.test_eq("public key encoding", pub_bytes.get(), pub_bytes2.get());

            // KEM encryption (using the loaded public key)
            botan_pk_op_kem_encrypt_t kem_enc;
            TEST_FFI_OK(botan_pk_op_kem_encrypt_create, (&kem_enc, pub_loaded, "Raw"));

            // explicitly query output lengths
            size_t shared_key_length = 0;
            size_t ciphertext_length = 0;
            TEST_FFI_OK(botan_pk_op_kem_encrypt_shared_key_length, (kem_enc, 0, &shared_key_length));
            TEST_FFI_OK(botan_pk_op_kem_encrypt_encapsulated_key_length, (kem_enc, &ciphertext_length));

            // check that insufficient buffer space is handled correctly
            size_t shared_key_length_out = 0;
            size_t ciphertext_length_out = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_pk_op_kem_encrypt_create_shared_key,
                        (kem_enc,
                         rng,
                         nullptr /* no salt */,
                         0,
                         0 /* default key length */,
                         nullptr,
                         &shared_key_length_out,
                         nullptr,
                         &ciphertext_length_out));

            // TODO: should this report both lengths for usage convenience?
            result.confirm("at least one buffer length is reported",
                           shared_key_length_out == shared_key_length || ciphertext_length_out == ciphertext_length);

            // allocate buffers (with additional space) and perform the actual encryption
            shared_key_length_out = shared_key_length * 2;
            ciphertext_length_out = ciphertext_length * 2;
            Botan::secure_vector<uint8_t> shared_key(shared_key_length_out);
            std::vector<uint8_t> ciphertext(ciphertext_length_out);
            TEST_FFI_OK(botan_pk_op_kem_encrypt_create_shared_key,
                        (kem_enc,
                         rng,
                         nullptr /* no salt */,
                         0,
                         0 /* default key length */,
                         shared_key.data(),
                         &shared_key_length_out,
                         ciphertext.data(),
                         &ciphertext_length_out));
            result.test_eq("shared key length", shared_key_length, shared_key_length_out);
            result.test_eq("ciphertext length", ciphertext_length, ciphertext_length_out);
            shared_key.resize(shared_key_length_out);
            ciphertext.resize(ciphertext_length_out);
            TEST_FFI_OK(botan_pk_op_kem_encrypt_destroy, (kem_enc));

            // KEM decryption (using the generated private key)
            botan_pk_op_kem_decrypt_t kem_dec;
            TEST_FFI_OK(botan_pk_op_kem_decrypt_create, (&kem_dec, priv, "Raw"));
            size_t shared_key_length2 = 0;
            TEST_FFI_OK(botan_pk_op_kem_decrypt_shared_key_length, (kem_dec, shared_key_length, &shared_key_length2));
            result.test_eq("shared key lengths are consistent", shared_key_length, shared_key_length2);

            // check that insufficient buffer space is handled correctly
            shared_key_length_out = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_pk_op_kem_decrypt_shared_key,
                        (kem_dec,
                         nullptr /* no salt */,
                         0,
                         ciphertext.data(),
                         ciphertext.size(),
                         0 /* default length */,
                         nullptr,
                         &shared_key_length_out));
            result.test_eq("reported buffer length requirement", shared_key_length, shared_key_length_out);

            // allocate buffer (double the size) and perform the actual decryption
            shared_key_length_out = shared_key_length * 2;
            Botan::secure_vector<uint8_t> shared_key2(shared_key_length_out);
            TEST_FFI_OK(botan_pk_op_kem_decrypt_shared_key,
                        (kem_dec,
                         nullptr /* no salt */,
                         0,
                         ciphertext.data(),
                         ciphertext.size(),
                         0 /* default length */,
                         shared_key2.data(),
                         &shared_key_length_out));
            result.test_eq("shared key output length", shared_key_length, shared_key_length_out);
            shared_key2.resize(shared_key_length_out);
            TEST_FFI_OK(botan_pk_op_kem_decrypt_destroy, (kem_dec));

            // final check and clean up
            result.test_eq("shared keys match", shared_key, shared_key2);

            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_pubkey_destroy, (pub_loaded));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            TEST_FFI_OK(botan_privkey_destroy, (priv_loaded));
         }
      }
};

/**
 * Base class for roundtrip tests of FFI bindings for Signature Mechanisms.
 */
class FFI_Signature_Roundtrip_Test : public FFI_Test {
   protected:
      using privkey_loader_fn_t = int (*)(botan_privkey_t*, const uint8_t[], size_t, const char*);
      using pubkey_loader_fn_t = int (*)(botan_pubkey_t*, const uint8_t[], size_t, const char*);

   protected:
      virtual const char* algo() const = 0;
      virtual privkey_loader_fn_t private_key_load_function() const = 0;
      virtual pubkey_loader_fn_t public_key_load_function() const = 0;
      virtual std::vector<const char*> modes() const = 0;
      virtual const char* hash_algo_or_padding() const = 0;

   public:
      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         const std::vector<uint8_t> message1 = {'H', 'e', 'l', 'l', 'o', ' '};
         const std::vector<uint8_t> message2 = {'W', 'o', 'r', 'l', 'd', '!'};

         for(auto mode : modes()) {
            // generate a key pair
            botan_privkey_t priv;
            botan_pubkey_t pub;
            if(!TEST_FFI_INIT(botan_privkey_create, (&priv, algo(), mode, rng))) {
               continue;
            }
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            // raw-encode the key pair
            ViewBytesSink priv_bytes;
            ViewBytesSink pub_bytes;
            TEST_FFI_OK(botan_privkey_view_raw, (priv, priv_bytes.delegate(), priv_bytes.callback()));
            TEST_FFI_OK(botan_pubkey_view_raw, (pub, pub_bytes.delegate(), pub_bytes.callback()));

            // decode the key pair from raw encoding
            botan_privkey_t priv_loaded;
            botan_pubkey_t pub_loaded;
            TEST_FFI_OK(private_key_load_function(),
                        (&priv_loaded, priv_bytes.get().data(), priv_bytes.get().size(), mode));
            TEST_FFI_OK(public_key_load_function(),
                        (&pub_loaded, pub_bytes.get().data(), pub_bytes.get().size(), mode));

            // re-encode and compare to the first round
            ViewBytesSink priv_bytes2;
            ViewBytesSink pub_bytes2;
            TEST_FFI_OK(botan_privkey_view_raw, (priv_loaded, priv_bytes2.delegate(), priv_bytes2.callback()));
            TEST_FFI_OK(botan_pubkey_view_raw, (pub_loaded, pub_bytes2.delegate(), pub_bytes2.callback()));
            result.test_eq("private key encoding", priv_bytes.get(), priv_bytes2.get());
            result.test_eq("public key encoding", pub_bytes.get(), pub_bytes2.get());

            // Signature Creation (using the loaded private key)
            botan_pk_op_sign_t signer;
            TEST_FFI_OK(botan_pk_op_sign_create, (&signer, priv_loaded, hash_algo_or_padding(), 0));

            // explicitly query the signature output length
            size_t sig_output_length = 0;
            TEST_FFI_OK(botan_pk_op_sign_output_length, (signer, &sig_output_length));

            // pass a message to the signer
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message1.data(), message1.size()));
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message2.data(), message2.size()));

            // check that insufficient buffer space is handled correctly
            size_t sig_output_length_out = 0;
            TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                        botan_pk_op_sign_finish,
                        (signer, rng, nullptr, &sig_output_length_out));
            result.test_eq("reported sig lengths are equal", sig_output_length, sig_output_length_out);

            // Recreate signer and try again
            TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));
            TEST_FFI_OK(botan_pk_op_sign_create, (&signer, priv_loaded, hash_algo_or_padding(), 0));
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message1.data(), message1.size()));
            TEST_FFI_OK(botan_pk_op_sign_update, (signer, message2.data(), message2.size()));

            // allocate buffers (with additional space) and perform the actual signing
            sig_output_length_out = sig_output_length * 2;
            Botan::secure_vector<uint8_t> signature(sig_output_length_out);
            TEST_FFI_OK(botan_pk_op_sign_finish, (signer, rng, signature.data(), &sig_output_length_out));
            result.test_eq("signature length", sig_output_length, sig_output_length_out);
            signature.resize(sig_output_length_out);
            TEST_FFI_OK(botan_pk_op_sign_destroy, (signer));

            // Signature verification (using the generated public key)
            botan_pk_op_verify_t verifier;
            TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, hash_algo_or_padding(), 0));
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message1.data(), message1.size()));
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message2.data(), message2.size()));

            // Verify signature
            TEST_FFI_OK(botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));
            TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));

            // Verify signature with wrong message (only first half)
            TEST_FFI_OK(botan_pk_op_verify_create, (&verifier, pub, hash_algo_or_padding(), 0));
            TEST_FFI_OK(botan_pk_op_verify_update, (verifier, message1.data(), message1.size()));
            TEST_FFI_RC(
               BOTAN_FFI_INVALID_VERIFIER, botan_pk_op_verify_finish, (verifier, signature.data(), signature.size()));
            TEST_FFI_OK(botan_pk_op_verify_destroy, (verifier));

            // Cleanup
            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_pubkey_destroy, (pub_loaded));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
            TEST_FFI_OK(botan_privkey_destroy, (priv_loaded));
         }
      }
};

class FFI_Kyber512_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Kyber512"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const std::vector<uint8_t> a_pub_bits = Botan::hex_decode(
            "5fc44b99d7584f38cd28360cc5625a905b96af12930ed5b5fe2a82fc5aa7dc4b829fe37635f13f5af2a6d3081dad878785698a0aa914374c4e43b89f094a7892aa149a38b49c06a068d829a8d249e753a375d097a0f162e6c3a4dfe8c79761410c605ed3899a3fc44378e14f28879e8f148077e6bc3bb2ae56178c491611bf6aaf5f9a9cb9b5659223007940bcd6f8a23280a56015330e8577259587b12606f4c937ea13606cb3bb046066ad294261e2b22022bcc74678a5520570d88e4ceb42692631e7e3711c4b2fd5347f0328598340cb3c65c8f55ac02716831094cb6eb90f175b173d9c650329aaf513633633bb2ce6858e7447abc41b6fb06da8782572c332b09660366926bf529ed8caaa6243ccdb152b36ba6e47c714145c86f5b3b61de84ef1470d03fa0135e35194fa1fb3bc860fa500d1299aee88ce56054376c1199c553dd90a8d6f9cc763c811d0c66da6f851abf1056635a34a68aa7815868f153a3a5c77fcc8b1eb1807fbf62a6fb43b355700e78230943a2ba1e11b181345b11b4d46266e7b359f074a500c8857d79ba60f64262d662ccd9c8489a4c19df67437db193f95b9765181d9152262b1166f97be53497f001cb1be79024d6a2289bcc704e1b1d821015366a3cc8a484e6bc2e1f1b889f19323e3101aa09ad9ea62ba4005039bbfb5998055f93fbf77b14433116d5958422654dada1127213f02b78717a5a0454271d5b0c02517a6c27a3c3610101d753c09a25571775477dc13b2e404db4965b9a9350330c73a8a3642d39af8a23839ab85c6355b12f279f849813c280d54c5913e99b6946a0aaf012c8cab025396b255f002d837c761d42a4aeb38c5f456aaf79e162700c6b4048eca6f9a7367f90238d67bcf8e6a0d8a553c071522f9d2394e28483d2048be2a8f9c8c8e39991a41273c7eacaefc6a308be870b45b41176412954a1a0fd83d362a5ab288663dec5456b6286d0b2cecb01922fb3d473802ea2b86639bce02450339261cffb114e1e725e90677826a1688f686b29a78779c9822315dafc55753e98c8ed3221f2b3220805c8a28983355207da36fb72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d");
         const std::vector<uint8_t> b_priv_bits = Botan::hex_decode(
            "cf8c33fabbc3e6685f60779a456412e9060a792a3f67d90389815773e06dd2071e3906a1159921485b6221b73dfc723da9d45bbc99523c55b203f81856ba8d38f731c6594a0a9796f485c7cad02ee3a80a737cada2e40b580a1060a1364d365169539ce4d800eab9723153c5b266853b3a33112ccb03491e77f57aeb74c7670426c5bb02615b1907b353beda51f38a788774b1c9eb3c49f89df59ba00e196f180a37fd9acd6691b493d78f95a49906b26fa46125663a37b0b2614197473ba012956bc9348a9afc8907527bb7c2dcbd384b85630b3687096ffd9a93d603121706c06c05baca286bebea0ecdf391ba489d7ff6a7a1c7c3dd0c521c02bb3fa7c3e5b98f19509486ab33f1597346b03c7197865792896c1a553e8379c6f51729e9907d09b4fbc5b4279298f60195998225d95c2aef335c9e6a26f4988e0f19c307fc00f8aa0b21090daab0c540363f121044729322bebb97427227e8b01705826879ab4d42e30bf191068b705527a3ae9a5b3e30371c50b5b75d189903e60175f904c1488be7e872d3dc3be1bb31921027cb075f6bb051c28980c65b9959e8acf2d38671d27285d03419512008335492476e0c23ac6263425f8a65fbc1a38110b38db641f3a9872fa312d26b9c81f11de1d9378b629e9bdc7ca31496ac9511bff42a7a96b28f740a84c2904fe4056ca1989b28439222cee31c554e982d318366037070c4bb778b261e3479c605317922947e4340560732ca8fda63e2a7ac8cc67015e97d308c361e634f8cdb1e836b572367334c949011a9c52f391194baa91f08a71e847d3be202554ab1c4f871c9b26db5f4992db5b3688b1ea877925d02895d470b9659c51213b206b82de489455c6502856b841d000aab3c065ff6720f9222914b6421224d716684a7762fc98ba7f4655f4cfa82fc52472b01b1e22255fc990b20240b802034c99777b71b5c0d8a4c733b69d5f76ddfdb1128da3e194c1169a924f5d868d1dbc4ddcb30197c25005391c1fcc098010af1e9ab72bc8c3bd1c58b15583035bc2dd0898e148fb20b8c502a31489b00dd645ab24709bff5c37d1a7fee5c56d7490ae77a61b1c5951e359d2a89a946f200b1f647c0283de5d403282c693dfccca1c1b54804ab86f36e1f16550a77b75328916c770c225b142dfb750659ba6d532003f8b6d48825b122682051acda7c20f09117b3e5c93e8c1bd446672512947d964f0484a05b85af82f4401d323484d23373c0c6c8990a3fba70f8a2c13e7350ce945c8f4882b1929f10d18bb45a883c116d1ce06493a50580069743d26062da9171006405d27e2f7220a897024dca507b737a6c32ba3d925e15c9789589507a768ca075beb2fb17a17144c52810566a972dba60ad806a2ff15957a3bbd85a8f1ef34445d18cc668ca7a8ac5fc7545934221a4c92c60024069cc34d592ac30c88c3376bc133622e2b192e9b4b60a9a84e5304873e62d6f98103cc8c43f6024fb7739418cc2602b21416040220cb3ec588679c033d61a3c697c403463c17c13a63d7304044a9f024b907b440b39b7b6423723dda943447a900af0170144755d9a968f634e26f892ee19cd00a97b48d5041b4473ec8741e077126f85bbb8334b8b2cbd63429afa543a540740c1e56893f6b2f2f7c42a12bcd48c647726cca06841212656ff9b3d3e799e92c48414d653a61ca8dc2c49b7342469a868b7938db8d7844e6311134b2c30538ffa927ee3961a44e0a66438c5643aa1d13658fe8a7c2a84702a8211422831994ca1e801131ab88a25162d3cd988ebe09e6cb01ca7324256691635c536f576990664841b7c89b0dc325472271fdc2b0824a9514b5eb46a743f9734ee20648a407f5d505cc9614748f344a16950b5483e45516236d43afd1494d564c23e20b64a124593604404c879a776a5bd9399629600e86aa1a641be7a13418cda318bbc3af0c2a66c999841251a1c2868b05028f6a56a72c33d8a653c77f69af4247dc6f80d329921ce3355894605c35372ddf0c84cacb42d6ccbdf39a55b672a891749622a011747a01625764c788413f2c0fd877275c88fd5730fa9e87a3c783702223a4443525cc5b5381c976dd9cb08ac47490125ca5c70baac01ff9143bc40ceeb2a16c1529d70c07074a0013749656ff4b16d890868b26c99bf8461495793bbb1b12ca369c825cb31d68731326bf4764b416bb3338e5d6352d5a5006d7cd901489e7f851711c08e00cd4162ccfc2564d5893d52b2c7300e2d894b0eaa40a6ab254506d8c1176a33c4a1b2879604b1b80df48d31dd");
         const std::vector<uint8_t> b_pub_bits = Botan::hex_decode(
            "ee5c56d7490ae77a61b1c5951e359d2a89a946f200b1f647c0283de5d403282c693dfccca1c1b54804ab86f36e1f16550a77b75328916c770c225b142dfb750659ba6d532003f8b6d48825b122682051acda7c20f09117b3e5c93e8c1bd446672512947d964f0484a05b85af82f4401d323484d23373c0c6c8990a3fba70f8a2c13e7350ce945c8f4882b1929f10d18bb45a883c116d1ce06493a50580069743d26062da9171006405d27e2f7220a897024dca507b737a6c32ba3d925e15c9789589507a768ca075beb2fb17a17144c52810566a972dba60ad806a2ff15957a3bbd85a8f1ef34445d18cc668ca7a8ac5fc7545934221a4c92c60024069cc34d592ac30c88c3376bc133622e2b192e9b4b60a9a84e5304873e62d6f98103cc8c43f6024fb7739418cc2602b21416040220cb3ec588679c033d61a3c697c403463c17c13a63d7304044a9f024b907b440b39b7b6423723dda943447a900af0170144755d9a968f634e26f892ee19cd00a97b48d5041b4473ec8741e077126f85bbb8334b8b2cbd63429afa543a540740c1e56893f6b2f2f7c42a12bcd48c647726cca06841212656ff9b3d3e799e92c48414d653a61ca8dc2c49b7342469a868b7938db8d7844e6311134b2c30538ffa927ee3961a44e0a66438c5643aa1d13658fe8a7c2a84702a8211422831994ca1e801131ab88a25162d3cd988ebe09e6cb01ca7324256691635c536f576990664841b7c89b0dc325472271fdc2b0824a9514b5eb46a743f9734ee20648a407f5d505cc9614748f344a16950b5483e45516236d43afd1494d564c23e20b64a124593604404c879a776a5bd9399629600e86aa1a641be7a13418cda318bbc3af0c2a66c999841251a1c2868b05028f6a56a72c33d8a653c77f69af4247dc6f80d329921ce3355894605c35372ddf0c84cacb42d6ccbdf39a55b672a891749622a011747a01625764c788413f2c0fd877275c88fd5730fa9e87a3c783702223a4443525cc5b5381c976dd9cb08ac47490125ca5c70baac01ff9143bc40ceeb2a16c1529d70c07074a0013749656ff4b16d890868b26c99bf8461495793bbb1b12ca369c825cb31d68731326bf4764b416bb333");

         botan_privkey_t b_priv;
         if(!TEST_FFI_INIT(botan_privkey_load_kyber, (&b_priv, b_priv_bits.data(), 1632))) {
            return;
         }

         ViewBytesSink privkey_read;
         ViewBytesSink privkey_read_raw;
         TEST_FFI_OK(botan_privkey_view_kyber_raw_key, (b_priv, privkey_read.delegate(), privkey_read.callback()));
         TEST_FFI_OK(botan_privkey_view_raw, (b_priv, privkey_read_raw.delegate(), privkey_read_raw.callback()));
         result.test_eq("kyber512 private key", privkey_read.get(), b_priv_bits);
         result.test_eq("kyber512 private key raw", privkey_read_raw.get(), b_priv_bits);

         ViewBytesSink pubkey_read;
         ViewBytesSink pubkey_read_raw;

         botan_pubkey_t b_pub;
         TEST_FFI_OK(botan_privkey_export_pubkey, (&b_pub, b_priv));
         TEST_FFI_OK(botan_pubkey_view_kyber_raw_key, (b_pub, pubkey_read.delegate(), pubkey_read.callback()));
         TEST_FFI_OK(botan_pubkey_view_raw, (b_pub, pubkey_read_raw.delegate(), pubkey_read_raw.callback()));
         result.test_eq("kyber512 public key b", pubkey_read.get(), b_pub_bits);
         result.test_eq("kyber512 raw public key b", pubkey_read_raw.get(), b_pub_bits);

         botan_pubkey_t a_pub;
         TEST_FFI_OK(botan_pubkey_load_kyber, (&a_pub, a_pub_bits.data(), 800));
         TEST_FFI_OK(botan_pubkey_view_kyber_raw_key, (a_pub, pubkey_read.delegate(), pubkey_read.callback()));
         result.test_eq("kyber512 public key a", pubkey_read.get(), a_pub_bits);

         TEST_FFI_OK(botan_pubkey_destroy, (a_pub));
         TEST_FFI_OK(botan_pubkey_destroy, (b_pub));
         TEST_FFI_OK(botan_privkey_destroy, (b_priv));
      }
};

class FFI_Kyber768_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Kyber768"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const std::vector<uint8_t> a_pub_bits = Botan::hex_decode(
            "38d4851e5c010da39a7470bc1c80916f78c7bd5891dcd3b1ea84b6f051b346b803c1b97c94604020b7279b27836c3049ea0b9a3758510b7559593237ade72587462206b709f365848c96559326a5fe6c6f4cf531fd1a18477267f66ba14af20163c41f1138a01995147f271ddfc2be5361b281e6029d210584b2859b7383667284f767bb32782baad10933da0138a3a0660a149531c03f9c8ffccb33e3c3a5a7984e21fab26aa72a8a6b942f265e52551a9c800e5a44805f0c0141a05554213387f105df56458496bd8f469051886da223cb9fe78e7b390bf94b0a937691af9550082b76d045cb4d29c23c67942608d078a1c80f24767a945d19f077d82c9b9b197073464abe69cf7c5626177308f384672d5263b0c4826db4470e1a70e4751e3918abe8fcbc3bc0531ae89e5512214b5cc94a16a014bcb3826c79fbf4add0825eeefbab88cb7cff37bb8d491f8de902578a1e961655565b7718782a23504fdc13c783f130e177925e305d1fbc63cc8c15c2c67f85500cca785de9f480490558ef71aaf0fb5b513914401269b309c4c59c64d2a757d8855f58465615925f1ea6812cb143fff383e1048e285118bf932944b86fbdf4b1b9e65685664a07775c46952aaada1168f54b47c7a231e7355c64637467b5a3c09cab67bb35f58640c2726283bb63530a15f66eca48a840c00ca8862e283c73bfbb413a2915b8d1159a043f12c59bfa828248249b76106faa61a127a0280c586350e7a42cb74ca49cabd606891ec7cb8e84affe4b2e14c71658332b755611bab7977fa76ce736b21ed34a17ac0ec3561ca9b282d4a2bc407697924b1cf918ba83d3a4fdc82564c95bd904bdeee91ed6ccb36baa88a05c80712901bf280aee6538ec2078c2a84ee5862fc137cd92e97968d69fc3453a1e1cb161c50c9f2473a0d09037b188a0fa01efc344c2ac8fe8592b0a58456662a95033659a158a2d90a6e50c253a87975785ce29c4570000a154d4b3b2c642205c8c7cf9ac6b1071fbb368ab950a744b88c95ba5243017831120a9048338d29847830d12a933a09abd21a46b828cb14e808cd35129c9dc6e5b931d4a126fefe07909618e2b4586e7b6b424963b7323ba505ba112bb9b834a7d1b78ad0df53d556a1c69369f09148b1dc9938df59223f087fd6833be5b2bc2651fe58911ac01467f9297dfdc22b41a0f1702718710b78cf35b1865813a896d45214d338155b6c043c532330c002d520739467a504a866637fb3451c849f8f83e6a94147f168da53acdf9d8affd968a84124a9abc09af960cd3b29f2344831bb41e67605eebf00df202857117399dd748b6514aed61bb2f6cb841d168d5f35e20054573a331cd4882a04b072c179158825bcf471266da0dcceab1a021c73254751d5a161c1a92062c220a217a69d9823314b4de996fe8d45f6db5af16c1561495a4c43090bc394c94e1b0ec738eb56267201c2ecd1c7b4993c0efc0284bdc9a091c294f95703a7178822c8a95b79b1e4591e0998d893875c1a879c08a073cc67df426bba792c18ae6c1feba879bec54812c2affa012973b700ad48e271078280864268600a7aa309eaa1098750a0f8a522eb929577b412f7855613688b72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d");
         const std::vector<uint8_t> b_priv_bits = Botan::hex_decode(
            "9bc4986eec853ac90896c7300f914216773baa687f57f81f94e6b5a26515c0a74c73b19dc6b9888755a1d1db6a1128b02c5144ed9ba75e874a68a14dee3a9bf770b767121fbbdb292e097444757fe2f324a875b0a07a4fbdcc8fd6137fce80c69f412be103b01f8b3bed392600f830d1b20d73ca0b386666d16c5d96db10e309041890bfd4ab7bdec27191979abe7637e76153918cc2af1545724abfd95ca496281a0cc6ca63a87819b75aa86452e5027d429cad64a9c029112a3a7b9fb993c6a6d0671f6c9e24986b83f67cf1236d94c051559616826a947eaa15074025d1ab810c80220e8a8c2c222d4e8594bf35811b444a57e9bf94fb2479d174d6b38c8c3b4730437c244b2513232ec798adec4a8e597bca83bca5948468f93c022ba65311a91e3d95c299c70c3f1a43cd0c83dd500bd2211b9b385b82f2c003b10d295765b3e367563a5f19033fc1231db9620f835c95f5a261190a5da1c24ed528316f0a1520d223e208a8c99b24d28598ade74fc88370e7f45102c5a6411891c661b356b9a32e1cc0fafaa085d7670e8bcb5e768eb255204f2445b5b73b04079881903a553c865744343a925c7899777b1c9dd5579a481512f8157061606a9a67c041d38bc179048be17dd9e19dc0a572bce595afa3b68ff21bf78a63a7560636b6bb01ec3362e2aaabc8965818b7f2417ca8f66a5a2a67f72a3931e125d638a872862a7b680a54aa1f25d90dbd567635ec6664919e29517325a5c5048cc8d1c31af5e4866e85025b9184a7b75ed7f2c9c8d88259fa2ec5b05ed3751584f88308c67ff1a72fa2453305160baf404db7d4be56f1547b20bb7dec23f02b10db584b28ca40d8b39c1c3ab9f3d7bbda0822604ca48f26694d69810aa888ae3c0983c5ba4cb74211f7a5361ccdee694f4202aebe13a75b1b2dda1b3232376be213582afc4fde3474766671fe865e2fd98384eb65b2f349f1e24269b91bd9d08c80849735a9951304afd130b5c2211314630aed4b6ac3b1252a0999ff5a3ec26a283342389d219fd243706128b389eb2334fb2a6184a4eab6735d7428df5633ce030b8f853ee47c4401fc5d06b43c9b66b7aeeb23b5f000a30a6f88f027ee3994fe8b63e51b83bc24bb733a3773a35cbe138f6d9c91a3a3898bca6776030d740ac355176547d624719656a9a44e91c63faf7699dc6c2c45575718d48828828b39043c2fda2af416837efc38d17c56d4b63c63a5ab43434647d029f7b236b288958f06910763610f8b2f027a8dcd780039ab34a6871427476ff6500240e83b87c95dcfa45ac5315ef34b343fb609eb296e915c849bb8c57f57c69b177eaa8456377403fe8c6627a3282d45308f675d67085a15f0b1b55aa2a8f21afd6c05c3c00e9eb8c32418cb41963ce427b43e7545c58325c7b9368db2333de424dbeb3430f007d18a68d73b7dc67960b28206a68a1be400a770b5cd9d45a72824ca00345ac56491c1414fe5287a2eb2ad61f3bdcd0c84c335b04a703425d79dbd02b0a0e90de5b331c3c29f6562969e04cdf7095b2a7646b3d006b0b83cb68580b5ccb71de1b4d9f131bac133d6088e10613a00599d81d4818403a4bea83905304cc45ca645a9b2c6484cf9490f1755c744d9988ed60475e6ae44355ed15c7b549366f29581ec2721fd6704e0ca3f878812805675141c0a15a7b7ac35a9e3f8b2a010bc184981c57852895b2695d56131e32326717f6b101df1bc82b3ba0222d52656d118538c4ca3416be1c76ba37a9901a36e4883be6c541f2bbb561818cd2f136b98f658250545c1fa5bcfdc04374016db1c5132447fd6d568866451c25412f72967de868eaeb9c546fb40ea88cd84a1a586ca51c74bc9c3e56e104323afb658d1ac003151bdc35879a4b6762648bff0caa682f1b3319805d2326d5a46af832aacefbaa1ea820568ea3925870e9b6577eb93898e1b0cfbd1c995cb4cd6cabb979813819749b40a9952f50e97c4365e777dcfe9084219294c205acb350e07db9c98f53444546460962e2bf5aa1cc12273d882fcc215a7397b3f9b307c56b9a0429b30f88453a2376669b28b4bc4b84b51714b6652b7a1a0b53e9ec61b55ca51cdb38243239ee5f18243e515f178768a888f475b3d9060136bb22ee355b3da02c16ad83bdbb4aaa13809cb4bcd5bb53710737d3883632f9254e3336af61621a376720572450e3937c0d930e349adbfa7642ff822b9135e18f943e0178617604d10e0c09ffb3e09783c09d12cbe93311757af9857b77d1488ed39321ca97c3745c5bc176ca81274c8321bcb2029938b32bbd01aec137032f9760849701649120050b50d8353c36b8bb7724a67e7660fc93324065d63912c35a86d8fe60683067bbd2685c552ad8c65c77c57c937676fd61595c453174bf996e9d3a9ccb837b25464115c1ba3343ac097b80735aed3225091167cd8f841ffe49c5e698ef542124253084623179394433a4b61547b9ee09c98c2736ea086bd69d1bc7ae68a6ae5ce682a215860006b4604dee45a3e212f97643acb77a79a880382e483537c5198d4483a176d25aac9c3670a3f30956f18ad441904776bcd48131c7d6465bce0c133010f3176c92ec962f5c6b84d4c3ae949619cf48172997ca3b1ccf5c8cc7a67923e1295801048a3d40ac4f2c6467c750fc71314a0c1fc22637dd52e7ea50907ea973d765a6a9bb2b11aa405b9187f72026696710e61af3e41c33da1a05eb65e6523704f078e74e32f10e00247967aee3a8c6546889ef67cd613ad7236583f2104122ac6c6a40a84dc96d81c569e76a952c0a25f396e48337a4fe029a4c91cc7406872706a55573b75f160a4facad7c85fab141c63454bf48990729096ce9965604c7cc1e60ae6868dcc41bc3df71c3e5593f0488b0c6a3063e817f9f4bacb17599c8666ff3591126b4891fb7f5d29660bab60cf5007043a4311d41ab3b29787184f3d3c9ab7cc247f635145b67e970505ba44ad0e06b11ec5cda4175295199d19d660204cbdc17947cc66442d3a2cd408a20fe98174f31ee4e5bb3fa8bcd102bedc26527e9bae836442978a6ccbe510f93ab77569ab1f09d0e6312dd0cc0bcaf095fa8a52a7212d14714a7bf852416c9b026301bd965c30a43d24d97298346a46b2c4bc814ba4059653358b03c9456c60bf0193932eaa2f24ea8e4b010a5a4425ce4540fbab90d8e55c97ac2687f15ff5299278824a08d4743e1a62e1c6619cd3278cd75a97a5b4e3a38668b26c99bf8461495793bbb1b12ca369c825cb31d68731326bf4764b416bb3339ae9c9ce46d9da0e714c0bae8712a670d0e5dcfdd1dd0d045932c79c559b2ab3c7300e2d894b0eaa40a6ab254506d8c1176a33c4a1b2879604b1b80df48d31dd");
         const std::vector<uint8_t> b_pub_bits = Botan::hex_decode(
            "f9490f1755c744d9988ed60475e6ae44355ed15c7b549366f29581ec2721fd6704e0ca3f878812805675141c0a15a7b7ac35a9e3f8b2a010bc184981c57852895b2695d56131e32326717f6b101df1bc82b3ba0222d52656d118538c4ca3416be1c76ba37a9901a36e4883be6c541f2bbb561818cd2f136b98f658250545c1fa5bcfdc04374016db1c5132447fd6d568866451c25412f72967de868eaeb9c546fb40ea88cd84a1a586ca51c74bc9c3e56e104323afb658d1ac003151bdc35879a4b6762648bff0caa682f1b3319805d2326d5a46af832aacefbaa1ea820568ea3925870e9b6577eb93898e1b0cfbd1c995cb4cd6cabb979813819749b40a9952f50e97c4365e777dcfe9084219294c205acb350e07db9c98f53444546460962e2bf5aa1cc12273d882fcc215a7397b3f9b307c56b9a0429b30f88453a2376669b28b4bc4b84b51714b6652b7a1a0b53e9ec61b55ca51cdb38243239ee5f18243e515f178768a888f475b3d9060136bb22ee355b3da02c16ad83bdbb4aaa13809cb4bcd5bb53710737d3883632f9254e3336af61621a376720572450e3937c0d930e349adbfa7642ff822b9135e18f943e0178617604d10e0c09ffb3e09783c09d12cbe93311757af9857b77d1488ed39321ca97c3745c5bc176ca81274c8321bcb2029938b32bbd01aec137032f9760849701649120050b50d8353c36b8bb7724a67e7660fc93324065d63912c35a86d8fe60683067bbd2685c552ad8c65c77c57c937676fd61595c453174bf996e9d3a9ccb837b25464115c1ba3343ac097b80735aed3225091167cd8f841ffe49c5e698ef542124253084623179394433a4b61547b9ee09c98c2736ea086bd69d1bc7ae68a6ae5ce682a215860006b4604dee45a3e212f97643acb77a79a880382e483537c5198d4483a176d25aac9c3670a3f30956f18ad441904776bcd48131c7d6465bce0c133010f3176c92ec962f5c6b84d4c3ae949619cf48172997ca3b1ccf5c8cc7a67923e1295801048a3d40ac4f2c6467c750fc71314a0c1fc22637dd52e7ea50907ea973d765a6a9bb2b11aa405b9187f72026696710e61af3e41c33da1a05eb65e6523704f078e74e32f10e00247967aee3a8c6546889ef67cd613ad7236583f2104122ac6c6a40a84dc96d81c569e76a952c0a25f396e48337a4fe029a4c91cc7406872706a55573b75f160a4facad7c85fab141c63454bf48990729096ce9965604c7cc1e60ae6868dcc41bc3df71c3e5593f0488b0c6a3063e817f9f4bacb17599c8666ff3591126b4891fb7f5d29660bab60cf5007043a4311d41ab3b29787184f3d3c9ab7cc247f635145b67e970505ba44ad0e06b11ec5cda4175295199d19d660204cbdc17947cc66442d3a2cd408a20fe98174f31ee4e5bb3fa8bcd102bedc26527e9bae836442978a6ccbe510f93ab77569ab1f09d0e6312dd0cc0bcaf095fa8a52a7212d14714a7bf852416c9b026301bd965c30a43d24d97298346a46b2c4bc814ba4059653358b03c9456c60bf0193932eaa2f24ea8e4b010a5a4425ce4540fbab90d8e55c97ac2687f15ff5299278824a08d4743e1a62e1c6619cd3278cd75a97a5b4e3a38668b26c99bf8461495793bbb1b12ca369c825cb31d68731326bf4764b416bb333");

         botan_privkey_t b_priv;
         if(!TEST_FFI_INIT(botan_privkey_load_kyber, (&b_priv, b_priv_bits.data(), 2400))) {
            return;
         }

         ViewBytesSink privkey_read;
         ViewBytesSink privkey_read_raw;
         TEST_FFI_OK(botan_privkey_view_kyber_raw_key, (b_priv, privkey_read.delegate(), privkey_read.callback()));
         TEST_FFI_OK(botan_privkey_view_raw, (b_priv, privkey_read_raw.delegate(), privkey_read_raw.callback()));
         result.test_eq("kyber768 private key", privkey_read.get(), b_priv_bits);
         result.test_eq("kyber768 private key raw", privkey_read_raw.get(), b_priv_bits);

         ViewBytesSink pubkey_read;
         ViewBytesSink pubkey_read_raw;

         botan_pubkey_t b_pub;
         TEST_FFI_OK(botan_privkey_export_pubkey, (&b_pub, b_priv));
         TEST_FFI_OK(botan_pubkey_view_kyber_raw_key, (b_pub, pubkey_read.delegate(), pubkey_read.callback()));
         TEST_FFI_OK(botan_pubkey_view_raw, (b_pub, pubkey_read_raw.delegate(), pubkey_read_raw.callback()));
         result.test_eq("kyber768 public key b", pubkey_read.get(), b_pub_bits);
         result.test_eq("kyber768 public key raw b", pubkey_read_raw.get(), b_pub_bits);

         botan_pubkey_t a_pub;
         TEST_FFI_OK(botan_pubkey_load_kyber, (&a_pub, a_pub_bits.data(), 1184));
         TEST_FFI_OK(botan_pubkey_view_kyber_raw_key, (a_pub, pubkey_read.delegate(), pubkey_read.callback()));
         result.test_eq("kyber768 public key a", pubkey_read.get(), a_pub_bits);

         TEST_FFI_OK(botan_pubkey_destroy, (a_pub));
         TEST_FFI_OK(botan_pubkey_destroy, (b_pub));
         TEST_FFI_OK(botan_privkey_destroy, (b_priv));
      }
};

class FFI_Kyber1024_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI Kyber1024"; }

      void ffi_test(Test::Result& result, botan_rng_t /*unused*/) override {
         const std::vector<uint8_t> a_pub_bits = Botan::hex_decode(
            "9779a4d1fc45ec261f048b9c9daa38c9ec228b6505e8905226b38486802059c2c5c89601560634cb1337b1315365144842bc405a292e683cafa4514526945c4dfb68ee2acdb8b79532836696d53125a045bdbb8a3bcc8123083d1e682c5bd7820c76c448351151474f69d601d7708dbb2c979d77527494b68520a8ff66c34162ca2aec8072a2a51ff259389648e75b95c16abe14604edbfabaf400b76a7a0f07db61dce19102f43b2d1060747b02c4425485341fd5d9bffaa7016061374963b985209c6b9a7db3f94958311d027900a3d8c44f8435b093a236a0509f1928df7719ce8c4e90228f4db87cb9e882f2712180238845d31eb906c60eb63e0ff55e84b867a91b79ae74a03ac00473c8c1b3e6aedcc37f1e69b8e136019bdb01c374a122e164c32584b2fbcf5e013a45127c893326b6860378cb5525a48b522b30132b7688214b69808dd19aa4ff033e16252016fc9479222424393e51db7115e38114e6893cdcc8ae1117a4316548010ab4629fb672148d031a6c601a6a4a661d872d8ef693750a115958716ab9263eb0516357102358cde5256464805ca8f59661751ad6a475a7ec78cb7319c3bbc544e1bb1185aaaeb751ba0b3923246e33f40a4ff4780b745362a218d169474d7208a9f7577228308af20f8d2403a27477cf53cff133a247d5c2b298bf21bac6dc44649e63afcef54ad3a07a74e447b36bacca295e053368ef7c146e1c28edb31b3777c941a7c27dc559437b0ff83c2910f827ef244d7726af2b9708654bcfb139a26844c6f4b79cd9e4747065a77596b927f96cbdbc7267ac9e32ac396f6c4ce739aa0aa60fccac178edab1e04688fe71a74201a99bc64b55f8cb89e11545e5275af48626ec667520ba8a7c88c2307e793455ef8780fae16412ea59e92406f595902dc21c612b142801cf31abc0475c7bde772d51c55a2dfc651bc5ab4143022813cc4c8cc6f52c8d27e3cd7851849a8c4343f0c7ed6c6cb9f765c5047e55bc48aad5b932128287f70939db753a61c0d7db1830c256288c1c85cc9bbce58366dac528c893d61b69850bcb82758e836936e1f8163861586482cad35b4db1437fad6980b66280b1652d72f52407a8015f85c29e75b2158933a4f5887db320b583cdcbca274eac21f8702879b8bc4afb62ba056d146512921554c765464d4c96bd3c9a9720187c3339d0593bc4bba59155469ff6b8688a5fc5fa6b46d4070668bd168c5f796492760940999927628236b2412968438d2cbc2a978abc097320291b0ed7e4631ec9bbe28ac63ab6860e976ac1552afc43897d6937a092432dc481a914c3a1273c43009e8ec523cb93ced9898f90905340ba6e01bc572d03a893fa21c4342d88dc3e77b33b1fc063dcdb689d8c4ffc840ce879cfb3471385512cc7c7591383b1fac89832bb1cb3324e6d2868918844cb20ca4df812b42824192a43380430a37a7f3ac41ed064cfe055157b91b5c0108fb7a613a0112af4d64e48f8a345328a99b7bf0c91cb037215b0177ad4c263e6d78f5958c848158e4fd2117c248e0cab3cf98c1e27868838f8428ba0562df6b61e8736e2b8b266607918e0ce2ce3af67c81fa5c2a4d2bc8e871825b702b3beca397b33a518dac8b1393d494a90900c01b55925857cbf8027051d36a4f141a4d2dc440341305e033cb50a074be459c76a339a9a52c447360dea2a5699ccea683a42430aa6fc9545c75c0492641af7a4e9267bcc384e55714cf49741eba3b69d6417a555475d3c021112b8b3588c63747b5ce2ccfee91297fa419f9c4298978fff0870d8a855b48899ca9bb47d836d62d2038cc3816f3a698bb3bbff78c7a015b0ea1960634292e1d50b03e1043a98ca9b27063e668b05e2c17d692d382b181365a818518ec747720337ca1868596af42a90fab1870373d74b8f6d42ac86b18bca3ab04764680cf2060c529abe5b8ef4474dc8cc47a8033ebd884d3e0a0f1a94420d8a3c9162b7af87a2c8a394647434f4a3bc2b477813ac82cf387185b587f7f68938eccddd6934d143ba17bb4a712566d2a55aaddb3323713667401b4a20b86c23bf1076439cb6b8c115389dba4e6f0c915be7602b9703b535070e4a5c5649a5d7080515026706b2604575cbd0687f2729a92a997d21ea7200c41ed8315275f4c7b72f9bc85c0a13b9d041586fd583feb12afd5a402dd33b43543f5fa4eb436c8d");
         const std::vector<uint8_t> b_priv_bits = Botan::hex_decode(
            "9bc4986eec853ac90896c7300f914216773baa687f57f81f94e6b5a26515c0a74c73b19dc6b9888755a1d1db6a1128b02c5144ed9ba75e874a68a14dee3a9bf770b767121fbbdb292e097444757fe2f324a875b0a07a4fbdcc8fd6137fce80c69f412be103b01f8b3bed392600f830d1b20d73ca0b386666d16c5d96db10e309041890bfd4ab7bdec27191979abe7637e76153918cc2af1545724abfd95ca496281a0cc6ca63a87819b75aa86452e5027d429cad64a9c029112a3a7b9fb993c6a6d0671f6c9e24986b83f67cf1236d94c051559616826a947eaa15074025d1ab810c80220e8a8c2c222d4e8594bf35811b444a57e9bf94fb2479d174d6b38c8c3b4730437c244b2513232ec798adec4a8e597bca83bca5948468f93c022ba65311a91e3d95c299c70c3f1a43cd0c83dd500bd2211b9b385b82f2c003b10d295765b3e367563a5f19033fc1231db9620f835c95f5a261190a5da1c24ed528316f0a1520d223e208a8c99b24d28598ade74fc88370e7f45102c5a6411891c661b356b9a32e1cc0fafaa085d7670e8bcb5e768eb255204f2445b5b73b04079881903a553c865744343a925c7899777b1c9dd5579a481512f8157061606a9a67c041d38bc179048be17dd9e19dc0a572bce595afa3b68ff21bf78a63a7560636b6bb01ec3362e2aaabc8965818b7f2417ca8f66a5a2a67f72a3931e125d638a872862a7b680a54aa1f25d90dbd567635ec6664919e29517325a5c5048cc8d1c31af5e4866e85025b9184a7b75ed7f2c9c8d88259fa2ec5b05ed3751584f88308c67ff1a72fa2453305160baf404db7d4be56f1547b20bb7dec23f02b10db584b28ca40d8b39c1c3ab9f3d7bbda0822604ca48f26694d69810aa888ae3c0983c5ba4cb74211f7a5361ccdee694f4202aebe13a75b1b2dda1b3232376be213582afc4fde3474766671fe865e2fd98384eb65b2f349f1e24269b91bd9d08c80849735a9951304afd130b5c2211314630aed4b6ac3b1252a0999ff5a3ec26a283342389d219fd243706128b389eb2334fb2a6184a4eab6735d7428df5633ce030b8f853ee47c4401fc5d06b43c9b66b7aeeb23b5f000a30a6f88f027ee3994fe8b63e51b83bc24bb733a3773a35cbe138f6d9c91a3a3898bca6776030d740ac355176547d624719656a9a44e91c63faf7699dc6c2c45575718d48828828b39043c2fda2af416837efc38d17c56d4b63c63a5ab43434647d029f7b236b288958f06910763610f8b2f027a8dcd780039ab34a6871427476ff6500240e83b87c95dcfa45ac5315ef34b343fb609eb296e915c849bb8c57f57c69b177eaa8456377403fe8c6627a3282d45308f675d67085a15f0b1b55aa2a8f21afd6c05c3c00e9eb8c32418cb41963ce427b43e7545c58325c7b9368db2333de424dbeb3430f007d18a68d73b7dc67960b28206a68a1be400a770b5cd9d45a72824ca00345ac56491c1414fe5287a2eb2ad61f3bdcd0c84c335b04a703425d79dbd02b0a0e90de5b331c3c29f6562969e04cdf7095b2a7646b3d006b0b83cb68580b5ccb71de1b4d9f131bac133d6088e10613a00599d81d4818403a4bea83905304cc45ca645a9b2c6484ce4f7bfbe3597f0c2c50784065abc214b5518ed8c7d427205392987d807cdfa571d09932e0a1217e7c5703dfc9be7c4a0f2f33338f316b8c203c6b84285a0957c363d3722145b592f9d6277b1b7446aa2005663b9898901da3b8978eaa8aee87a209c72bfd6cd10a2bedac527f26c419b4bb9a4ca13dba14cff5671461c4cff238d213988120c3cae3b15b607269420c14a9b23a6bb887ad048e6688528137dd5c071172bcaddd5ba4fb9acfb1712ca04aa267b0686a237414b16c4ac03525a45513a393605a29f3b4c07dc5cd082c67b770e69723c6425a23f573216c4cabd6c9c39533f16643bc6151672c466dea63fb8e2180fbcb453c5670b01c0fc7043d198b6c320bf0dfc5016d00f46dc0ba75c7369fc13b65733301b3a92c0cf8dcc1f01e33291a9974d5b5debfa3be5531c69a066a6f4230ba778502654b7e76191d3ba68b1488c848d8ef11bb9ac5a5374af6ccacd02432b247a963685127728825a162c43c1cc79a7b60f571481a3a635a18f0050cbe6f4af1a5a2224044622bb3893bc837be699d5279dac78c9d49818ebc91d4ff6cb54b294e4c378d8eb584f561d21ca87b7c77b1c551f52112ba72c4b6514bb286856e89b48b0a62bad093894474b246a515f849056c9aeb572060ee11b93e236204a8ff1784ede0c3f4c0cd0cdb2a50bd4bcb1225c0dd2caa8a129fdcb01f0e1a75da465b6b8742e4946dbe3ab21ca6c4e592d398a5700375b7b770c17e117663b51313824854585ece4a1520c59a513555f548afdc6748eb9b770b7af8adc9b3c1861efc00ebde93f91fa1539c3411ec9b154c93d1f508b9714cdd0aaabcb436951aa54978b84faa8bd838c29a12657a6389fa658237326bf80e44cff183d9c9107d30c7b4df83908a8badbc1bb5328ae61e6451291710408196261bb913b285c168fe5c7456cd74970377330139beb4c8b4c00c5954254a748308bc30f3a1ccabed83628422e5515b294e80bfed024902a81518c0e6827caa13230016b72aec10d31aab9f9b072652486c3b779c845804d001b223b4065667a5e318b4e0b27c41a099168ce763ac245c1c26354cfc8214cacf01dc8c99c5fc855639cb7486a7a6b71766d62369ee6349f521591344fb8026099fc055c3a0ca2002271c9361f52acaf4675a97b3593f3447b284ad69a9711501411e14e48f080e2a0bceba07a02f79dc15c3c971c1e671a66bf7144395a94d08c46603c4369b25b38d924693492f6500745cb1d2a037e2cd814fac70d8254aea4526e061648d227350dec1ba6305299a45bde4029a9f63e4f62acb5246ba8b54208a37b98fa77e4b720f02b18969635cc16cb6e236ff78111b621cab0339c60b529a9207c94a74925aa3d177636a6d205d72b429f614d452358b98582e42c2f3a32c94202a8625a760483807bbac74c083a7a786ae7b46aff3810a5318e3f479e67e83b4c94587d345ffda17273a55e0432281c670e36b76539263636445e4d110fa1c92b2e65b1ee993b26c41c8c66b181206ff559728993503e7611fa0ca24156642d29a52cbb6aeff88fa1bb790b4344472503ae77967d11a904550a95cc47c3435f1e44b4b890cf5dc4cbd7486a6cab60d1a6622e40c67e854ed0e6a0c4c2aa92a29731e69bc6b3ca9e83893df4bdb37338055bc16bc7cd875b0691d0212109b77236b10b0c72b7a76e9ce346061028be3271c480435e2482d3d2733ed619c2d3698d29a3225a7731a62db4f214a0b11569e91895fbccb8a92d18f94d307a542ff96d2ce8c2bbaa8fab948c83365162268124cabe934b3a5e6530b7f74397a980c243bdce2989747565dd9ba65a7498aa7c3ee711c3be239e93cb45134c082a900cc951756afa42e74a65001822cab95f41798fdef89ea8a751740842e2f7a271e98dbd5158d7455fe9b9cdcd0a0f68c91e59b00979673a1deabf8d213971f994c0bb08899a91e0b896319b9fc69651e3453b14d1cc94462341548fc81c643ab0b10303c7be2c3458b226d0e45f58b21658a853b84615ac5234da9bc5699646fc53c0df907f9a3c598dab6c409b7884a7a84e1a51c2caa80779cd86b77314dabae85caa28972bb6503273a82eb96ab24af6bb0ad0c9ba07ce24216696e265206abc9e147ceef1ad2e343d17aabbc4803496366c7afb53f604c92323c70be5c1e3f601c215c888f3ab239c72aba0634a2901a71891f5d072d41b524e410c7f276ff1109878d7196b5615f1f50c13976257600a821909cb36cf8d2857a2f801cf258913f56a5153234640b9e61bbd4e7b69f83a1eb8ac6b92cb841e808b700aa784a733451048211797563cccc748c9fbb54b3b65445cba676149c7ae9a9a2ecab6599b8505bc561ad85d8c052ed9669e50e684270c86f1cb4fd6708a6746c643392c8a088477dc8bf58ba4a54a8b79e523fc19a28bd47d7e5a334d8296ec86c7f52b7e73b475a0716422953cdd8a8aed0b3a84dc8425145c240c55870240a23977215b364c5596286bc496728717c329dd4b5d0b310980bc0b3f591a2d5cb2c9eaccfa1c7d3a096fc11091a4007a0f23a59782699c3171da53bc7b914f26c95391d6445073a1bd7a44691bafab9c9aceccc7ec389255c3a0ff24c71b30b6bf80c010803383485a7b295991d759cefbae257bbdee1806818565ebd09bf814c98686bbf44a0b14d28735f79ca2261bf9a31b2ca090c7667168b26c99bf8461495793bbb1b12ca369c825cb31d68731326bf4764b416bb33357e74a31d3cd71513fb880e1e177438f29009bab0a131fec4cc24752015efe71c7300e2d894b0eaa40a6ab254506d8c1176a33c4a1b2879604b1b80df48d31dd");
         const std::vector<uint8_t> b_pub_bits = Botan::hex_decode(
            "93bc837be699d5279dac78c9d49818ebc91d4ff6cb54b294e4c378d8eb584f561d21ca87b7c77b1c551f52112ba72c4b6514bb286856e89b48b0a62bad093894474b246a515f849056c9aeb572060ee11b93e236204a8ff1784ede0c3f4c0cd0cdb2a50bd4bcb1225c0dd2caa8a129fdcb01f0e1a75da465b6b8742e4946dbe3ab21ca6c4e592d398a5700375b7b770c17e117663b51313824854585ece4a1520c59a513555f548afdc6748eb9b770b7af8adc9b3c1861efc00ebde93f91fa1539c3411ec9b154c93d1f508b9714cdd0aaabcb436951aa54978b84faa8bd838c29a12657a6389fa658237326bf80e44cff183d9c9107d30c7b4df83908a8badbc1bb5328ae61e6451291710408196261bb913b285c168fe5c7456cd74970377330139beb4c8b4c00c5954254a748308bc30f3a1ccabed83628422e5515b294e80bfed024902a81518c0e6827caa13230016b72aec10d31aab9f9b072652486c3b779c845804d001b223b4065667a5e318b4e0b27c41a099168ce763ac245c1c26354cfc8214cacf01dc8c99c5fc855639cb7486a7a6b71766d62369ee6349f521591344fb8026099fc055c3a0ca2002271c9361f52acaf4675a97b3593f3447b284ad69a9711501411e14e48f080e2a0bceba07a02f79dc15c3c971c1e671a66bf7144395a94d08c46603c4369b25b38d924693492f6500745cb1d2a037e2cd814fac70d8254aea4526e061648d227350dec1ba6305299a45bde4029a9f63e4f62acb5246ba8b54208a37b98fa77e4b720f02b18969635cc16cb6e236ff78111b621cab0339c60b529a9207c94a74925aa3d177636a6d205d72b429f614d452358b98582e42c2f3a32c94202a8625a760483807bbac74c083a7a786ae7b46aff3810a5318e3f479e67e83b4c94587d345ffda17273a55e0432281c670e36b76539263636445e4d110fa1c92b2e65b1ee993b26c41c8c66b181206ff559728993503e7611fa0ca24156642d29a52cbb6aeff88fa1bb790b4344472503ae77967d11a904550a95cc47c3435f1e44b4b890cf5dc4cbd7486a6cab60d1a6622e40c67e854ed0e6a0c4c2aa92a29731e69bc6b3ca9e83893df4bdb37338055bc16bc7cd875b0691d0212109b77236b10b0c72b7a76e9ce346061028be3271c480435e2482d3d2733ed619c2d3698d29a3225a7731a62db4f214a0b11569e91895fbccb8a92d18f94d307a542ff96d2ce8c2bbaa8fab948c83365162268124cabe934b3a5e6530b7f74397a980c243bdce2989747565dd9ba65a7498aa7c3ee711c3be239e93cb45134c082a900cc951756afa42e74a65001822cab95f41798fdef89ea8a751740842e2f7a271e98dbd5158d7455fe9b9cdcd0a0f68c91e59b00979673a1deabf8d213971f994c0bb08899a91e0b896319b9fc69651e3453b14d1cc94462341548fc81c643ab0b10303c7be2c3458b226d0e45f58b21658a853b84615ac5234da9bc5699646fc53c0df907f9a3c598dab6c409b7884a7a84e1a51c2caa80779cd86b77314dabae85caa28972bb6503273a82eb96ab24af6bb0ad0c9ba07ce24216696e265206abc9e147ceef1ad2e343d17aabbc4803496366c7afb53f604c92323c70be5c1e3f601c215c888f3ab239c72aba0634a2901a71891f5d072d41b524e410c7f276ff1109878d7196b5615f1f50c13976257600a821909cb36cf8d2857a2f801cf258913f56a5153234640b9e61bbd4e7b69f83a1eb8ac6b92cb841e808b700aa784a733451048211797563cccc748c9fbb54b3b65445cba676149c7ae9a9a2ecab6599b8505bc561ad85d8c052ed9669e50e684270c86f1cb4fd6708a6746c643392c8a088477dc8bf58ba4a54a8b79e523fc19a28bd47d7e5a334d8296ec86c7f52b7e73b475a0716422953cdd8a8aed0b3a84dc8425145c240c55870240a23977215b364c5596286bc496728717c329dd4b5d0b310980bc0b3f591a2d5cb2c9eaccfa1c7d3a096fc11091a4007a0f23a59782699c3171da53bc7b914f26c95391d6445073a1bd7a44691bafab9c9aceccc7ec389255c3a0ff24c71b30b6bf80c010803383485a7b295991d759cefbae257bbdee1806818565ebd09bf814c98686bbf44a0b14d28735f79ca2261bf9a31b2ca090c7667168b26c99bf8461495793bbb1b12ca369c825cb31d68731326bf4764b416bb333");

         botan_privkey_t b_priv;
         if(!TEST_FFI_INIT(botan_privkey_load_kyber, (&b_priv, b_priv_bits.data(), 3168))) {
            return;
         }

         ViewBytesSink privkey_read;
         ViewBytesSink privkey_read_raw;
         TEST_FFI_OK(botan_privkey_view_kyber_raw_key, (b_priv, privkey_read.delegate(), privkey_read.callback()));
         TEST_FFI_OK(botan_privkey_view_raw, (b_priv, privkey_read_raw.delegate(), privkey_read_raw.callback()));
         result.test_eq("kyber1024 private key", privkey_read.get(), b_priv_bits);
         result.test_eq("kyber1024 private key raw", privkey_read_raw.get(), b_priv_bits);

         ViewBytesSink pubkey_read;
         ViewBytesSink pubkey_read_raw;

         botan_pubkey_t b_pub;
         TEST_FFI_OK(botan_privkey_export_pubkey, (&b_pub, b_priv));
         TEST_FFI_OK(botan_pubkey_view_kyber_raw_key, (b_pub, pubkey_read.delegate(), pubkey_read.callback()));
         TEST_FFI_OK(botan_pubkey_view_raw, (b_pub, pubkey_read_raw.delegate(), pubkey_read_raw.callback()));
         result.test_eq("kyber1024 public key b", pubkey_read.get(), b_pub_bits);
         result.test_eq("kyber1024 public key raw b", pubkey_read_raw.get(), b_pub_bits);

         botan_pubkey_t a_pub;
         TEST_FFI_OK(botan_pubkey_load_kyber, (&a_pub, a_pub_bits.data(), 1568));
         TEST_FFI_OK(botan_pubkey_view_kyber_raw_key, (a_pub, pubkey_read.delegate(), pubkey_read.callback()));
         result.test_eq("kyber1024 public key a", pubkey_read.get(), a_pub_bits);

         TEST_FFI_OK(botan_pubkey_destroy, (a_pub));
         TEST_FFI_OK(botan_pubkey_destroy, (b_pub));
         TEST_FFI_OK(botan_privkey_destroy, (b_priv));
      }
};

class FFI_ML_KEM_Test final : public FFI_KEM_Roundtrip_Test {
   public:
      std::string name() const override { return "FFI ML-KEM"; }

   private:
      const char* algo() const override { return "ML-KEM"; }

      privkey_loader_fn_t private_key_load_function() const override { return botan_privkey_load_ml_kem; }

      pubkey_loader_fn_t public_key_load_function() const override { return botan_pubkey_load_ml_kem; }

      std::vector<const char*> modes() const override { return {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}; }
};

class FFI_FrodoKEM_Test final : public FFI_KEM_Roundtrip_Test {
   public:
      std::string name() const override { return "FFI FrodoKEM"; }

   protected:
      const char* algo() const override { return "FrodoKEM"; }

      privkey_loader_fn_t private_key_load_function() const override { return botan_privkey_load_frodokem; }

      pubkey_loader_fn_t public_key_load_function() const override { return botan_pubkey_load_frodokem; }

      std::vector<const char*> modes() const override {
         return std::vector{
            "FrodoKEM-640-SHAKE",
            "FrodoKEM-976-SHAKE",
            "FrodoKEM-1344-SHAKE",
            "eFrodoKEM-640-SHAKE",
            "eFrodoKEM-976-SHAKE",
            "eFrodoKEM-1344-SHAKE",
            "FrodoKEM-640-AES",
            "FrodoKEM-976-AES",
            "FrodoKEM-1344-AES",
            "eFrodoKEM-640-AES",
            "eFrodoKEM-976-AES",
            "eFrodoKEM-1344-AES",
         };
      }
};

class FFI_ML_DSA_Test final : public FFI_Signature_Roundtrip_Test {
   public:
      std::string name() const override { return "FFI ML-DSA"; }

   private:
      const char* algo() const override { return "ML-DSA"; }

      privkey_loader_fn_t private_key_load_function() const override { return botan_privkey_load_ml_dsa; }

      pubkey_loader_fn_t public_key_load_function() const override { return botan_pubkey_load_ml_dsa; }

      std::vector<const char*> modes() const override {
         return {
            "ML-DSA-4x4",
            "ML-DSA-6x5",
            "ML-DSA-8x7",
         };
      }

      const char* hash_algo_or_padding() const override { return ""; }
};

class FFI_SLH_DSA_Test final : public FFI_Signature_Roundtrip_Test {
   public:
      std::string name() const override { return "FFI SLH-DSA"; }

   private:
      const char* algo() const override { return "SLH-DSA"; }

      privkey_loader_fn_t private_key_load_function() const override { return botan_privkey_load_slh_dsa; }

      pubkey_loader_fn_t public_key_load_function() const override { return botan_pubkey_load_slh_dsa; }

      std::vector<const char*> modes() const override {
         auto modes = std::vector{
            "SLH-DSA-SHA2-128f",
            "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHA2-192f",
            "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-256f",
         };

         if(Test::run_long_tests()) {
            modes = Botan::concat(modes,
                                  std::vector{
                                     "SLH-DSA-SHA2-128s",
                                     "SLH-DSA-SHA2-192s",
                                     "SLH-DSA-SHA2-256s",
                                     "SLH-DSA-SHAKE-128s",
                                     "SLH-DSA-SHAKE-192s",
                                     "SLH-DSA-SHAKE-256s",
                                  });
         }

         return modes;
      }

      const char* hash_algo_or_padding() const override { return ""; }
};

class FFI_Classic_McEliece_Test final : public FFI_KEM_Roundtrip_Test {
   public:
      std::string name() const override { return "FFI Classic McEliece"; }

   protected:
      const char* algo() const override { return "ClassicMcEliece"; }

      privkey_loader_fn_t private_key_load_function() const override { return botan_privkey_load_classic_mceliece; }

      pubkey_loader_fn_t public_key_load_function() const override { return botan_pubkey_load_classic_mceliece; }

      std::vector<const char*> modes() const override {
         auto modes = std::vector{
            "348864f",
            "460896f",
         };
         if(Test::run_long_tests()) {
            modes = Botan::concat(modes,
                                  std::vector{
                                     "348864",
                                     "460896",
                                     "6688128",
                                     "6688128f",
                                     "6688128pc",
                                     "6688128pcf",
                                     "6960119",
                                     "6960119f",
                                     "6960119pc",
                                     "6960119pcf",
                                     "8192128",
                                     "8192128f",
                                     "8192128pc",
                                     "8192128pcf",
                                  });
         }
         return modes;
      }
};

class FFI_ElGamal_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI ElGamal"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_privkey_t priv;

         if(TEST_FFI_INIT(botan_privkey_create, (&priv, "ElGamal", "modp/ietf/1024", rng))) {
            do_elgamal_test(priv, rng, result);
         }

         if(TEST_FFI_INIT(botan_privkey_create_elgamal, (&priv, rng, 1024, 160))) {
            do_elgamal_test(priv, rng, result);
         }
      }

   private:
      static void do_elgamal_test(botan_privkey_t priv, botan_rng_t rng, Test::Result& result) {
         TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

         botan_pubkey_t pub;
         TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));
         TEST_FFI_OK(botan_pubkey_check_key, (pub, rng, 0));

         ffi_test_pubkey_export(result, pub, priv, rng);
         botan_mp_t p, g, x, y;
         botan_mp_init(&p);
         botan_mp_init(&g);
         botan_mp_init(&x);
         botan_mp_init(&y);

         TEST_FFI_OK(botan_pubkey_get_field, (p, pub, "p"));
         TEST_FFI_OK(botan_pubkey_get_field, (g, pub, "g"));
         TEST_FFI_OK(botan_pubkey_get_field, (y, pub, "y"));
         TEST_FFI_OK(botan_privkey_get_field, (x, priv, "x"));

         size_t p_len = 0;
         TEST_FFI_OK(botan_mp_num_bytes, (p, &p_len));

         botan_privkey_t loaded_privkey;
         TEST_FFI_OK(botan_privkey_load_elgamal, (&loaded_privkey, p, g, x));

         botan_pubkey_t loaded_pubkey;
         TEST_FFI_OK(botan_pubkey_load_elgamal, (&loaded_pubkey, p, g, y));

         botan_mp_destroy(p);
         botan_mp_destroy(g);
         botan_mp_destroy(y);
         botan_mp_destroy(x);

         std::vector<uint8_t> plaintext(16, 0xFF);
         std::vector<uint8_t> ciphertext;
         std::vector<uint8_t> decryption;

   #if defined(BOTAN_HAS_OAEP) && defined(BOTAN_HAS_SHA2_32)
         const std::string padding = "OAEP(SHA-256)";
   #else
         const std::string padding = "Raw";
   #endif

         // Test encryption
         botan_pk_op_encrypt_t op_enc;
         if(TEST_FFI_OK(botan_pk_op_encrypt_create, (&op_enc, loaded_pubkey, padding.c_str(), 0))) {
            size_t ctext_len;
            TEST_FFI_OK(botan_pk_op_encrypt_output_length, (op_enc, plaintext.size(), &ctext_len));
            ciphertext.resize(ctext_len);
            TEST_FFI_OK(botan_pk_op_encrypt,
                        (op_enc, rng, ciphertext.data(), &ctext_len, plaintext.data(), plaintext.size()));
            ciphertext.resize(ctext_len);
            TEST_FFI_OK(botan_pk_op_encrypt_destroy, (op_enc));
         }

         // Test decryption
         botan_pk_op_decrypt_t op_dec;
         if(TEST_FFI_OK(botan_pk_op_decrypt_create, (&op_dec, loaded_privkey, padding.c_str(), 0))) {
            size_t ptext_len;
            TEST_FFI_OK(botan_pk_op_decrypt_output_length, (op_dec, ciphertext.size(), &ptext_len));
            decryption.resize(ptext_len);
            TEST_FFI_OK(botan_pk_op_decrypt,
                        (op_dec, decryption.data(), &ptext_len, ciphertext.data(), ciphertext.size()));
            decryption.resize(ptext_len);
            TEST_FFI_OK(botan_pk_op_decrypt_destroy, (op_dec));
         }

         result.test_eq("decryption worked", decryption, plaintext);

         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey));
         TEST_FFI_OK(botan_pubkey_destroy, (pub));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey));
         TEST_FFI_OK(botan_privkey_destroy, (priv));
      }
};

class FFI_DH_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI DH"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_privkey_t priv1;
         if(!TEST_FFI_INIT(botan_privkey_create_dh, (&priv1, rng, "modp/ietf/2048"))) {
            return;
         }

         botan_privkey_t priv2;
         REQUIRE_FFI_OK(botan_privkey_create_dh, (&priv2, rng, "modp/ietf/2048"));

         botan_pubkey_t pub1;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub1, priv1));

         botan_pubkey_t pub2;
         REQUIRE_FFI_OK(botan_privkey_export_pubkey, (&pub2, priv2));

         // Reload key-pair1 in order to test functions for key loading
         botan_mp_t private_x, public_g, public_p, public_y;

         botan_mp_init(&private_x);
         botan_mp_init(&public_g);
         botan_mp_init(&public_p);
         botan_mp_init(&public_y);

         TEST_FFI_OK(botan_privkey_get_field, (private_x, priv1, "x"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_g, pub1, "g"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_p, pub1, "p"));
         TEST_FFI_OK(botan_pubkey_get_field, (public_y, pub1, "y"));

         botan_privkey_t loaded_privkey1;
         botan_pubkey_t loaded_pubkey1;
         TEST_FFI_OK(botan_privkey_load_dh, (&loaded_privkey1, public_p, public_g, private_x));
         TEST_FFI_OK(botan_pubkey_load_dh, (&loaded_pubkey1, public_p, public_g, public_y));

         TEST_FFI_OK(botan_privkey_check_key, (loaded_privkey1, rng, 0));
         TEST_FFI_OK(botan_pubkey_check_key, (loaded_pubkey1, rng, 0));

         botan_mp_t loaded_public_g, loaded_public_p, loaded_public_y;
         botan_mp_init(&loaded_public_g);
         botan_mp_init(&loaded_public_p);
         botan_mp_init(&loaded_public_y);

         TEST_FFI_OK(botan_pubkey_get_field, (loaded_public_g, loaded_pubkey1, "g"));
         TEST_FFI_OK(botan_pubkey_get_field, (loaded_public_p, loaded_pubkey1, "p"));
         TEST_FFI_OK(botan_pubkey_get_field, (loaded_public_y, loaded_pubkey1, "y"));

         int cmp;

         TEST_FFI_OK(botan_mp_cmp, (&cmp, loaded_public_g, public_g));
         result.confirm("bigint_mp_cmp(g, g)", cmp == 0);

         TEST_FFI_OK(botan_mp_cmp, (&cmp, loaded_public_p, public_p));
         result.confirm("bigint_mp_cmp(p, p)", cmp == 0);

         TEST_FFI_OK(botan_mp_cmp, (&cmp, loaded_public_y, public_y));
         result.confirm("bigint_mp_cmp(y, y)", cmp == 0);

         botan_pk_op_ka_t ka1;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka1, loaded_privkey1, "Raw", 0));
         botan_pk_op_ka_t ka2;
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_create, (&ka2, priv2, "Raw", 0));

         size_t pubkey1_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                     botan_pk_op_key_agreement_export_public,
                     (priv1, nullptr, &pubkey1_len));
         std::vector<uint8_t> pubkey1(pubkey1_len);
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_export_public, (priv1, pubkey1.data(), &pubkey1_len));
         size_t pubkey2_len = 0;
         TEST_FFI_RC(BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE,
                     botan_pk_op_key_agreement_export_public,
                     (priv2, nullptr, &pubkey2_len));
         std::vector<uint8_t> pubkey2(pubkey2_len);
         REQUIRE_FFI_OK(botan_pk_op_key_agreement_export_public, (priv2, pubkey2.data(), &pubkey2_len));

         const size_t shared_key_len = 256;

         std::vector<uint8_t> key1(shared_key_len);
         size_t key1_len = key1.size();

         TEST_FFI_OK(botan_pk_op_key_agreement,
                     (ka1, key1.data(), &key1_len, pubkey2.data(), pubkey2.size(), nullptr, 0));

         std::vector<uint8_t> key2(shared_key_len);
         size_t key2_len = key2.size();

         TEST_FFI_OK(botan_pk_op_key_agreement,
                     (ka2, key2.data(), &key2_len, pubkey1.data(), pubkey1.size(), nullptr, 0));

         result.test_eq("shared DH key", key1, key2);

         TEST_FFI_OK(botan_mp_destroy, (private_x));
         TEST_FFI_OK(botan_mp_destroy, (public_p));
         TEST_FFI_OK(botan_mp_destroy, (public_g));
         TEST_FFI_OK(botan_mp_destroy, (public_y));

         TEST_FFI_OK(botan_mp_destroy, (loaded_public_p));
         TEST_FFI_OK(botan_mp_destroy, (loaded_public_g));
         TEST_FFI_OK(botan_mp_destroy, (loaded_public_y));

         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka1));
         TEST_FFI_OK(botan_pk_op_key_agreement_destroy, (ka2));
         TEST_FFI_OK(botan_privkey_destroy, (priv1));
         TEST_FFI_OK(botan_privkey_destroy, (priv2));
         TEST_FFI_OK(botan_pubkey_destroy, (pub1));
         TEST_FFI_OK(botan_pubkey_destroy, (pub2));
         TEST_FFI_OK(botan_privkey_destroy, (loaded_privkey1));
         TEST_FFI_OK(botan_pubkey_destroy, (loaded_pubkey1));
      }
};

class FFI_OID_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI OID"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         botan_asn1_oid_t oid;
         botan_asn1_oid_t new_oid;
         botan_asn1_oid_t new_oid_from_string;
         botan_asn1_oid_t oid_a;
         botan_asn1_oid_t oid_b;
         botan_asn1_oid_t oid_c;

         TEST_FFI_FAIL("empty oid", botan_oid_from_string, (&oid, ""));
         TEST_FFI_OK(botan_oid_from_string, (&oid, "1.2.3.4.5"));

         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_oid_from_string, (&new_oid, "a.a.a"));
         TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_oid_from_string, (&new_oid, "0.40"));
         TEST_FFI_RC(
            BOTAN_FFI_ERROR_BAD_PARAMETER, botan_oid_from_string, (&new_oid, "random-name-that-definitely-has-no-oid"));

         TEST_FFI_OK(botan_oid_from_string, (&new_oid, "1.2.3.4.5.6.7.8"));
         TEST_FFI_OK(botan_oid_register, (new_oid, "random-name-that-definitely-has-no-oid"));

         TEST_FFI_OK(botan_oid_from_string, (&new_oid_from_string, "random-name-that-definitely-has-no-oid"));
         TEST_FFI_RC(1, botan_oid_equal, (new_oid, new_oid_from_string));

         TEST_FFI_OK(botan_oid_from_string, (&oid_a, "1.2.3.4.5.6"));
         TEST_FFI_OK(botan_oid_from_string, (&oid_b, "1.2.3.4.5.6"));
         TEST_FFI_OK(botan_oid_from_string, (&oid_c, "1.2.3.4.4"));

         TEST_FFI_RC(1, botan_oid_equal, (oid_a, oid_b));
         TEST_FFI_RC(0, botan_oid_equal, (oid_a, oid_c));

         int res;

         TEST_FFI_OK(botan_oid_cmp, (&res, oid_a, oid_b));
         result.confirm("oid_a and oid_b are equal", res == 0);

         TEST_FFI_OK(botan_oid_cmp, (&res, oid_a, oid_c));
         result.confirm("oid_a is bigger", res == 1);

         TEST_FFI_OK(botan_oid_cmp, (&res, oid_c, oid_a));
         result.confirm("oid_c is smaller", res == -1);

         TEST_FFI_OK(botan_oid_destroy, (oid));
         TEST_FFI_OK(botan_oid_destroy, (new_oid));
         TEST_FFI_OK(botan_oid_destroy, (new_oid_from_string));
         TEST_FFI_OK(botan_oid_destroy, (oid_a));
         TEST_FFI_OK(botan_oid_destroy, (oid_b));
         TEST_FFI_OK(botan_oid_destroy, (oid_c));

         botan_privkey_t priv;
         if(TEST_FFI_INIT(botan_privkey_create_rsa, (&priv, rng, 1024))) {
            TEST_FFI_OK(botan_privkey_check_key, (priv, rng, 0));

            const std::string oid_rsa_expexted = "1.2.840.113549.1.1.1";

            botan_asn1_oid_t rsa_oid_priv;
            botan_asn1_oid_t rsa_oid_pub;
            botan_asn1_oid_t rsa_oid_expected;
            botan_asn1_oid_t rsa_oid_from_name;

            TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_oid_from_string, (&rsa_oid_expected, nullptr));
            TEST_FFI_RC(BOTAN_FFI_ERROR_NULL_POINTER, botan_oid_from_string, (nullptr, "1.2.3.4.5"));
            TEST_FFI_OK(botan_oid_from_string, (&rsa_oid_expected, oid_rsa_expexted.c_str()));
            TEST_FFI_OK(botan_privkey_oid, (&rsa_oid_priv, priv));

            TEST_FFI_RC(1, botan_oid_equal, (rsa_oid_priv, rsa_oid_expected));

            botan_pubkey_t pub;
            TEST_FFI_OK(botan_privkey_export_pubkey, (&pub, priv));

            TEST_FFI_OK(botan_pubkey_oid, (&rsa_oid_pub, pub));
            TEST_FFI_RC(1, botan_oid_equal, (rsa_oid_pub, rsa_oid_expected));

            ViewStringSink oid_string;
            TEST_FFI_OK(botan_oid_view_string, (rsa_oid_expected, oid_string.delegate(), oid_string.callback()));
            std::string oid_actual = {oid_string.get().begin(), oid_string.get().end()};

            result.test_eq("oid to string", oid_actual, oid_rsa_expexted);

            TEST_FFI_OK(botan_oid_from_string, (&rsa_oid_from_name, "RSA"));
            TEST_FFI_RC(1, botan_oid_equal, (rsa_oid_expected, rsa_oid_from_name));

            ViewStringSink rsa_name;
            TEST_FFI_OK(botan_oid_view_name, (rsa_oid_from_name, rsa_name.delegate(), rsa_name.callback()));
            std::string rsa_name_string = {rsa_name.get().begin(), rsa_name.get().end()};
            result.test_eq("oid to name", rsa_name_string, "RSA");

            TEST_FFI_OK(botan_oid_destroy, (rsa_oid_priv));
            TEST_FFI_OK(botan_oid_destroy, (rsa_oid_pub));
            TEST_FFI_OK(botan_oid_destroy, (rsa_oid_expected));
            TEST_FFI_OK(botan_oid_destroy, (rsa_oid_from_name));

            TEST_FFI_OK(botan_pubkey_destroy, (pub));
            TEST_FFI_OK(botan_privkey_destroy, (priv));
         }
      }
};

class FFI_EC_Group_Test final : public FFI_Test {
   public:
      std::string name() const override { return "FFI EC Group"; }

      void ffi_test(Test::Result& result, botan_rng_t rng) override {
         int appl_spec_groups;
         int named_group;
         TEST_FFI_OK(botan_ec_group_supports_application_specific_group, (&appl_spec_groups));
         TEST_FFI_OK(botan_ec_group_supports_named_group, ("secp256r1", &named_group));
         result.confirm("application specific groups support matches build",
                        appl_spec_groups,
                        Botan::EC_Group::supports_application_specific_group());
         result.confirm(
            "named group support matches build", named_group, Botan::EC_Group::supports_named_group("secp256r1"));

         if(named_group) {
            botan_ec_group_t group_from_name;
            botan_asn1_oid_t oid_from_name;
            botan_mp_t p_from_name;
            botan_mp_t a_from_name;
            botan_mp_t b_from_name;
            botan_mp_t g_x_from_name;
            botan_mp_t g_y_from_name;
            botan_mp_t order_from_name;

            TEST_FFI_RC(BOTAN_FFI_ERROR_BAD_PARAMETER, botan_ec_group_from_name, (&group_from_name, ""));

            TEST_FFI_OK(botan_ec_group_from_name, (&group_from_name, "secp256r1"));

            get_group_parameters(group_from_name,
                                 &oid_from_name,
                                 &p_from_name,
                                 &a_from_name,
                                 &b_from_name,
                                 &g_x_from_name,
                                 &g_y_from_name,
                                 &order_from_name,
                                 result);

            botan_asn1_oid_t group_oid;
            botan_ec_group_t group_from_oid;
            botan_asn1_oid_t oid_from_oid;
            botan_mp_t p_from_oid;
            botan_mp_t a_from_oid;
            botan_mp_t b_from_oid;
            botan_mp_t g_x_from_oid;
            botan_mp_t g_y_from_oid;
            botan_mp_t order_from_oid;

            TEST_FFI_OK(botan_oid_from_string, (&group_oid, "1.2.840.10045.3.1.7"));

            TEST_FFI_OK(botan_ec_group_from_oid, (&group_from_oid, group_oid));

            get_group_parameters(group_from_oid,
                                 &oid_from_oid,
                                 &p_from_oid,
                                 &a_from_oid,
                                 &b_from_oid,
                                 &g_x_from_oid,
                                 &g_y_from_oid,
                                 &order_from_oid,
                                 result);

            TEST_FFI_RC(1, botan_oid_equal, (group_oid, oid_from_oid));
            TEST_FFI_RC(1, botan_oid_equal, (oid_from_name, oid_from_oid));

            if(appl_spec_groups) {
               botan_asn1_oid_t group_parameter_oid;
               botan_mp_t p_parameter;
               botan_mp_t a_parameter;
               botan_mp_t b_parameter;
               botan_mp_t g_x_parameter;
               botan_mp_t g_y_parameter;
               botan_mp_t order_parameter;

               botan_ec_group_t group_from_parameters;
               botan_asn1_oid_t oid_from_parameters;
               botan_mp_t p_from_parameters;
               botan_mp_t a_from_parameters;
               botan_mp_t b_from_parameters;
               botan_mp_t g_x_from_parameters;
               botan_mp_t g_y_from_parameters;
               botan_mp_t order_from_parameters;

               TEST_FFI_OK(botan_oid_from_string, (&group_parameter_oid, "1.3.6.1.4.1.25258.100.0"));
               botan_oid_register(group_parameter_oid, "secp256r1-but-manually-registered");
               botan_mp_init(&p_parameter);
               botan_mp_init(&a_parameter);
               botan_mp_init(&b_parameter);
               botan_mp_init(&g_x_parameter);
               botan_mp_init(&g_y_parameter);
               botan_mp_init(&order_parameter);

               botan_mp_set_from_str(p_parameter, "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
               botan_mp_set_from_str(a_parameter, "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
               botan_mp_set_from_str(b_parameter, "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
               botan_mp_set_from_str(g_x_parameter,
                                     "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
               botan_mp_set_from_str(g_y_parameter,
                                     "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
               botan_mp_set_from_str(order_parameter,
                                     "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

               TEST_FFI_OK(botan_ec_group_from_params,
                           (&group_from_parameters,
                            group_parameter_oid,
                            p_parameter,
                            a_parameter,
                            b_parameter,
                            g_x_parameter,
                            g_y_parameter,
                            order_parameter));

               get_group_parameters(group_from_parameters,
                                    &oid_from_parameters,
                                    &p_from_parameters,
                                    &a_from_parameters,
                                    &b_from_parameters,
                                    &g_x_from_parameters,
                                    &g_y_from_parameters,
                                    &order_from_parameters,
                                    result);

               botan_ec_group_t group_from_registered_oid;

               TEST_FFI_OK(botan_ec_group_from_name, (&group_from_registered_oid, "secp256r1-but-manually-registered"));

               // we registered this group under a different oid
               TEST_FFI_RC(0, botan_oid_equal, (oid_from_oid, oid_from_parameters));

               TEST_FFI_RC(1, botan_ec_group_equal, (group_from_name, group_from_parameters));
               TEST_FFI_RC(1, botan_ec_group_equal, (group_from_parameters, group_from_registered_oid));

               std::vector<std::tuple<botan_mp_t, botan_mp_t>> parameters_inner = {
                  {p_from_name, p_from_parameters},
                  {a_from_name, a_from_parameters},
                  {b_from_name, b_from_parameters},
                  {g_x_from_name, g_x_from_parameters},
                  {g_y_from_name, g_y_from_parameters},
                  {order_from_name, order_from_parameters}};

               for(auto [x, y] : parameters_inner) {
                  TEST_FFI_RC(1, botan_mp_equal, (x, y));
                  botan_mp_destroy(y);
               }

               botan_mp_destroy(p_parameter);
               botan_mp_destroy(a_parameter);
               botan_mp_destroy(b_parameter);
               botan_mp_destroy(g_x_parameter);
               botan_mp_destroy(g_y_parameter);
               botan_mp_destroy(order_parameter);

               botan_oid_destroy(group_parameter_oid);
               botan_oid_destroy(oid_from_parameters);

               TEST_FFI_OK(botan_ec_group_destroy, (group_from_parameters));
               TEST_FFI_OK(botan_ec_group_destroy, (group_from_registered_oid));
            }

            botan_oid_destroy(oid_from_name);
            botan_oid_destroy(group_oid);
            botan_oid_destroy(oid_from_oid);

            std::vector<std::tuple<botan_mp_t, botan_mp_t>> parameters = {{p_from_name, p_from_oid},
                                                                          {a_from_name, a_from_oid},
                                                                          {b_from_name, b_from_oid},
                                                                          {g_x_from_name, g_x_from_oid},
                                                                          {g_y_from_name, g_y_from_oid},
                                                                          {order_from_name, order_from_oid}};

            for(auto [x, y] : parameters) {
               TEST_FFI_RC(1, botan_mp_equal, (x, y));
               botan_mp_destroy(x);
               botan_mp_destroy(y);
            }

            botan_ec_group_t secp384r1;
            botan_ec_group_t secp384r1_with_seed;

            TEST_FFI_OK(botan_ec_group_from_name, (&secp384r1, "secp384r1"));
            TEST_FFI_OK(botan_ec_group_from_pem,
                        (&secp384r1_with_seed, Test::read_data_file("x509/ecc/secp384r1_seed.pem").c_str()));

            botan_mp_t p;
            botan_mp_t p_with_seed;
            TEST_FFI_OK(botan_ec_group_get_p, (&p, secp384r1));
            TEST_FFI_OK(botan_ec_group_get_p, (&p_with_seed, secp384r1_with_seed));
            TEST_FFI_RC(1, botan_mp_equal, (p, p_with_seed));
            botan_mp_destroy(p);
            botan_mp_destroy(p_with_seed);

            TEST_FFI_RC(0, botan_ec_group_equal, (group_from_name, secp384r1));
            TEST_FFI_RC(1, botan_ec_group_equal, (group_from_name, group_from_oid));

            ViewBytesSink der_bytes;
            TEST_FFI_OK(botan_ec_group_view_der, (group_from_name, der_bytes.delegate(), der_bytes.callback()));
            botan_ec_group_t group_from_ber;
            TEST_FFI_OK(
               botan_ec_group_from_ber,
               (&group_from_ber, reinterpret_cast<const uint8_t*>(der_bytes.get().data()), der_bytes.get().size()));

            ViewStringSink pem_string;
            TEST_FFI_OK(botan_ec_group_view_pem, (group_from_name, pem_string.delegate(), pem_string.callback()));
            std::string pem_actual = {pem_string.get().begin(), pem_string.get().end()};

            botan_ec_group_t group_from_pem;
            TEST_FFI_OK(botan_ec_group_from_pem, (&group_from_pem, pem_actual.c_str()));

            TEST_FFI_RC(1, botan_ec_group_equal, (group_from_name, group_from_ber));
            TEST_FFI_RC(1, botan_ec_group_equal, (group_from_name, group_from_pem));

            botan_privkey_t priv;
            TEST_FFI_OK(botan_ec_privkey_create, (&priv, "ECDSA", secp384r1, rng));
            char namebuf[32] = {0};
            size_t name_len = sizeof(namebuf);

            TEST_FFI_OK(botan_privkey_algo_name, (priv, &namebuf[0], &name_len));
            result.test_eq("Key name is expected value", namebuf, "ECDSA");

            botan_privkey_destroy(priv);

            TEST_FFI_OK(botan_ec_group_destroy, (group_from_name));
            TEST_FFI_OK(botan_ec_group_destroy, (group_from_oid));
            TEST_FFI_OK(botan_ec_group_destroy, (secp384r1));
            TEST_FFI_OK(botan_ec_group_destroy, (secp384r1_with_seed));
            TEST_FFI_OK(botan_ec_group_destroy, (group_from_ber));
            TEST_FFI_OK(botan_ec_group_destroy, (group_from_pem));
         }
      }

   private:
      static void get_group_parameters(botan_ec_group_t ec_group,
                                       botan_asn1_oid_t* oid,
                                       botan_mp_t* p,
                                       botan_mp_t* a,
                                       botan_mp_t* b,
                                       botan_mp_t* g_x,
                                       botan_mp_t* g_y,
                                       botan_mp_t* order,
                                       Test::Result& result) {
         TEST_FFI_OK(botan_ec_group_get_curve_oid, (oid, ec_group));
         TEST_FFI_OK(botan_ec_group_get_p, (p, ec_group));
         TEST_FFI_OK(botan_ec_group_get_a, (a, ec_group));
         TEST_FFI_OK(botan_ec_group_get_b, (b, ec_group));
         TEST_FFI_OK(botan_ec_group_get_g_x, (g_x, ec_group));
         TEST_FFI_OK(botan_ec_group_get_g_y, (g_y, ec_group));
         TEST_FFI_OK(botan_ec_group_get_order, (order, ec_group));
      }
};

BOTAN_REGISTER_TEST("ffi", "ffi_utils", FFI_Utils_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_rng", FFI_RNG_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_rsa_cert", FFI_RSA_Cert_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_zfec", FFI_ZFEC_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_crl", FFI_CRL_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_cert_validation", FFI_Cert_Validation_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ecdsa_certificate", FFI_ECDSA_Certificate_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_pkcs_hashid", FFI_PKCS_Hashid_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_cbc_cipher", FFI_CBC_Cipher_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_gcm", FFI_GCM_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_chacha", FFI_ChaCha20Poly1305_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_eax", FFI_EAX_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_aead", FFI_AEAD_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_streamcipher", FFI_StreamCipher_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_hashfunction", FFI_HashFunction_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_mac", FFI_MAC_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_scrypt", FFI_Scrypt_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_kdf", FFI_KDF_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_blockcipher", FFI_Blockcipher_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_errorhandling", FFI_ErrorHandling_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_base64", FFI_Base64_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_hex", FFI_Hex_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_mp", FFI_MP_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_fpe", FFI_FPE_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_totp", FFI_TOTP_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_hotp", FFI_HOTP_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_keywrap", FFI_Keywrap_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_xmss", FFI_XMSS_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_rsa", FFI_RSA_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_dsa", FFI_DSA_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ecdsa", FFI_ECDSA_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_sm2_sig", FFI_SM2_Sig_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_sm2_enc", FFI_SM2_Enc_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ecdh", FFI_ECDH_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_mceliece", FFI_McEliece_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ed25519", FFI_Ed25519_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ed448", FFI_Ed448_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_x25519", FFI_X25519_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_x448", FFI_X448_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_kyber512", FFI_Kyber512_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_kyber768", FFI_Kyber768_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_kyber1024", FFI_Kyber1024_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ml_kem", FFI_ML_KEM_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ml_dsa", FFI_ML_DSA_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_slh_dsa", FFI_SLH_DSA_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_frodokem", FFI_FrodoKEM_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_cmce", FFI_Classic_McEliece_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_elgamal", FFI_ElGamal_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_dh", FFI_DH_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_oid", FFI_OID_Test);
BOTAN_REGISTER_TEST("ffi", "ffi_ec_group", FFI_EC_Group_Test);

#endif

}  // namespace

}  // namespace Botan_Tests
