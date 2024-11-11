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
   #include <botan/internal/tpm2_hash.h>

   #include <botan/pubkey.h>
   #include <botan/tpm2_key.h>
   #include <botan/tpm2_rng.h>
   #include <botan/tpm2_session.h>

   #if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
      #include <botan/tpm2_rsa.h>
   #endif

   #if defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
      #include <botan/ecdsa.h>
      #include <botan/tpm2_ecc.h>
   #endif

   #if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
      #include <botan/tpm2_crypto_backend.h>
   #endif

   // for testing externally-provided ESYS context
   #include <tss2/tss2_esys.h>
   #include <tss2/tss2_tctildr.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_TPM2)
namespace {

   #if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND) && defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS)
constexpr bool crypto_backend_should_be_available = true;
   #else
constexpr bool crypto_backend_should_be_available = false;
   #endif

bool validate_context_environment(const std::shared_ptr<Botan::TPM2::Context>& ctx) {
   return (ctx->vendor() == "SW   TPM" && ctx->manufacturer() == "IBM");
}

std::shared_ptr<Botan::TPM2::Context> get_tpm2_context(std::string_view rng_tag) {
   const auto tcti_name = Test::options().tpm2_tcti_name();
   if(tcti_name.value() == "disabled") {
      // skip the test if the special 'disabled' TCTI is configured
      return {};
   }

   auto ctx = Botan::TPM2::Context::create(tcti_name, Test::options().tpm2_tcti_conf());
   if(!validate_context_environment(ctx)) {
      return {};
   }

   if(ctx->supports_botan_crypto_backend()) {
      ctx->use_botan_crypto_backend(Test::new_rng(rng_tag));
   }

   return ctx;
}

/// RAII helper to manage raw transient resources (ESYS_TR) handles
class TR {
   private:
      ESYS_CONTEXT* m_esys_ctx;
      ESYS_TR m_handle;

   public:
      TR(ESYS_CONTEXT* esys_ctx, ESYS_TR handle) : m_esys_ctx(esys_ctx), m_handle(handle) {}

      TR(TR&& other) noexcept { *this = std::move(other); }

      TR& operator=(TR&& other) noexcept {
         if(this != &other) {
            m_esys_ctx = other.m_esys_ctx;
            m_handle = std::exchange(other.m_handle, ESYS_TR_NONE);
         }
         return *this;
      }

      TR(const TR&) = delete;
      TR& operator=(const TR&) = delete;

      ~TR() {
         if(m_esys_ctx && m_handle != ESYS_TR_NONE) {
            Esys_FlushContext(m_esys_ctx, m_handle);
         }
      }

      constexpr operator ESYS_TR() const { return m_handle; }
};

struct esys_context_liberator {
      void operator()(ESYS_CONTEXT* esys_ctx) {
         TSS2_TCTI_CONTEXT* tcti_ctx = nullptr;
         Esys_GetTcti(esys_ctx, &tcti_ctx);  // ignore error in destructor
         if(tcti_ctx != nullptr) {
            Tss2_TctiLdr_Finalize(&tcti_ctx);
         }
         Esys_Finalize(&esys_ctx);
      }
};

auto get_external_tpm2_context() -> std::unique_ptr<ESYS_CONTEXT, esys_context_liberator> {
   const auto tcti_name = Test::options().tpm2_tcti_name();
   const auto tcti_conf = Test::options().tpm2_tcti_conf();
   if(tcti_name.value() == "disabled") {
      // skip the test if the special 'disabled' TCTI is configured
      return nullptr;
   }

   TSS2_RC rc;
   TSS2_TCTI_CONTEXT* tcti_ctx;
   std::unique_ptr<ESYS_CONTEXT, esys_context_liberator> esys_ctx;

   rc = Tss2_TctiLdr_Initialize_Ex(tcti_name->c_str(), tcti_conf->c_str(), &tcti_ctx);
   if(rc != TSS2_RC_SUCCESS) {
      throw Test_Error("failed to initialize external TCTI");
   }

   rc = Esys_Initialize(Botan::out_ptr(esys_ctx), tcti_ctx, nullptr /* ABI version */);
   if(rc != TSS2_RC_SUCCESS) {
      throw Test_Error("failed to initialize external ESYS");
   }

   // This TPM2::Context is created for environment validation only.
   // It is transient, but the 'externally provided' ESYS_CONTEXT will live on!
   auto ctx = Botan::TPM2::Context::create(esys_ctx.get());
   if(!validate_context_environment(ctx)) {
      return nullptr;
   }

   return esys_ctx;
}

void bail_out(Test::Result& result, std::optional<std::string> reason = {}) {
   if(reason.has_value()) {
      result.test_note(reason.value());
   } else if(Test::options().tpm2_tcti_name() == "disabled") {
      result.test_note("TPM2 tests are disabled.");
   } else {
      result.test_failure("Not sure we're on a simulated TPM2, cautiously refusing any action.");
   }
}

Test::Result bail_out() {
   Test::Result result("TPM2 test bail out");
   bail_out(result);
   return result;
}

bool not_zero_64(std::span<const uint8_t> in) {
   Botan::BufferSlicer bs(in);

   while(bs.remaining() > 8) {
      if(Botan::load_be(bs.take<8>()) == 0) {
         return false;
      }
   }
   // Ignore remaining bytes

   return true;
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

         CHECK("Crypto backend",
               [&](Test::Result& result) {
                  const bool backend_supported = ctx->supports_botan_crypto_backend();
                  const bool backend_used = ctx->uses_botan_crypto_backend();
                  result.require("Crypto backend availability",
                                 backend_supported == crypto_backend_should_be_available);
                  result.require("Crypto backend is used in the tests, if it is available",
                                 backend_used == backend_supported);

                  if(backend_used) {
                     result.test_throws<Botan::Invalid_State>(
                        "If the backend is already in use, we cannot enable it once more",
                        [&] { ctx->use_botan_crypto_backend(Test::new_rng(__func__)); });
                  }

                  if(!backend_supported) {
                     result.test_throws<Botan::Not_Implemented>(
                        "If the backend is not supported, we cannot enable it",
                        [&] { ctx->use_botan_crypto_backend(Test::new_rng(__func__)); });
                  }
               }),

   #if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
         // TODO: Since SRK is always RSA in start_tpm2_simulator.sh, the test always requires the RSA adapter?
         CHECK("Fetch Storage Root Key RSA", [&](Test::Result& result) {
            auto srk = ctx->storage_root_key({}, {});
            result.require("SRK is not null", srk != nullptr);
            result.test_eq("Algo", srk->algo_name(), "RSA");
            result.test_eq("Key size", srk->key_length(), 2048);
            result.confirm("Has persistent handle", srk->handles().has_persistent_handle());
         }),
   #endif
   };
}

std::vector<Test::Result> test_external_tpm2_context() {
   auto raw_start_session = [](ESYS_CONTEXT* esys_ctx) -> std::pair<TR, TSS2_RC> {
      const TPMT_SYM_DEF sym_spec{
         .algorithm = TPM2_ALG_AES,
         .keyBits = {.sym = 256},
         .mode = {.sym = TPM2_ALG_CFB},
      };
      ESYS_TR session;

      auto rc = Esys_StartAuthSession(esys_ctx,
                                      ESYS_TR_NONE,
                                      ESYS_TR_NONE,
                                      ESYS_TR_NONE,
                                      ESYS_TR_NONE,
                                      ESYS_TR_NONE,
                                      nullptr,
                                      TPM2_SE_HMAC,
                                      &sym_spec,
                                      TPM2_ALG_SHA256,
                                      &session);

      if(rc == TSS2_RC_SUCCESS) {
         const auto session_attributes = TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT;
         rc = Esys_TRSess_SetAttributes(esys_ctx, session, session_attributes, 0xFF);
      }

      return {TR{esys_ctx, session}, rc};
   };

   auto raw_get_random_bytes = [](ESYS_CONTEXT* esys_ctx, uint16_t bytes, ESYS_TR session = ESYS_TR_NONE) {
      Botan::TPM2::unique_esys_ptr<TPM2B_DIGEST> random_bytes;
      const auto rc =
         Esys_GetRandom(esys_ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, bytes, Botan::out_ptr(random_bytes));
      return std::make_pair(std::move(random_bytes), rc);
   };

   return {
      CHECK("ESYS context is still functional after TPM2::Context destruction",
            [&](Test::Result& result) {
               auto esys_ctx = get_external_tpm2_context();
               if(!esys_ctx) {
                  bail_out(result);
                  return;
               }

               {
                  // Do some TPM2-stuff via the Botan wrappers

                  auto ctx = Botan::TPM2::Context::create(esys_ctx.get());
                  auto session = Botan::TPM2::Session::unauthenticated_session(ctx);
                  auto rng = Botan::TPM2::RandomNumberGenerator(ctx, session);

                  auto bytes = rng.random_vec(16);
                  result.test_eq("some random bytes generated", bytes.size(), 16);

                  // All Botan-wrapped things go out of scope...
               }

               auto [raw_session, rc_session] = raw_start_session(esys_ctx.get());
               Botan::TPM2::check_rc("session creation successful", rc_session);

               auto [bytes, rc_random] = raw_get_random_bytes(esys_ctx.get(), 16, raw_session);
               Botan::TPM2::check_rc("random byte generation successful", rc_random);
               result.test_eq_sz("some raw random bytes generated", bytes->size, 16);
            }),

         CHECK("TPM2::Context-managed crypto backend fails gracefully after TPM2::Context destruction",
               [&](Test::Result& result) {
                  auto esys_ctx = get_external_tpm2_context();
                  if(!esys_ctx) {
                     bail_out(result);
                     return;
                  }

                  {
                     auto ctx = Botan::TPM2::Context::create(esys_ctx.get());
                     if(!ctx->supports_botan_crypto_backend()) {
                        bail_out(result, "skipping, because botan-based crypto backend is not supported");
                        return;
                     }

                     ctx->use_botan_crypto_backend(Test::new_rng(__func__));
                  }

                  auto [session, session_rc1] = raw_start_session(esys_ctx.get());

                  // After the destruction of the TPM2::Context in the anonymous
                  // scope above the botan-based TSS crypto callbacks aren't able
                  // to access the state that was managed by the TPM2::Context.
                  result.require("expected error", session_rc1 == TSS2_ESYS_RC_BAD_REFERENCE);

   #if defined(BOTAN_TSS2_SUPPORTS_CRYPTO_CALLBACKS)
                  // Manually resetting the crypto callbacks (in retrospect) fixes this
                  const auto callbacks_rc = Esys_SetCryptoCallbacks(esys_ctx.get(), nullptr);
                  Botan::TPM2::check_rc("resetting crypto callbacks", callbacks_rc);

                  auto [raw_session, session_rc2] = raw_start_session(esys_ctx.get());
                  Botan::TPM2::check_rc("session creation successful", session_rc2);

                  auto [bytes, rc_random] = raw_get_random_bytes(esys_ctx.get(), 16, raw_session);
                  Botan::TPM2::check_rc("random byte generation successful", rc_random);
                  result.test_eq_sz("some raw random bytes generated", bytes->size, 16);
   #endif
               }),

   #if defined(BOTAN_HAS_TPM2_CRYPTO_BACKEND)
         CHECK("free-standing crypto backend", [&](Test::Result& result) {
            if(!Botan::TPM2::supports_botan_crypto_backend()) {
               bail_out(result, "botan crypto backend is not supported");
               return;
            }

            auto esys_ctx = get_external_tpm2_context();
            if(!esys_ctx) {
               bail_out(result);
               return;
            }

            auto cb_state = Botan::TPM2::use_botan_crypto_backend(esys_ctx.get(), Test::new_rng(__func__));

            auto [raw_session, session_rc2] = raw_start_session(esys_ctx.get());
            Botan::TPM2::check_rc("session creation successful", session_rc2);

            auto [bytes, rc_random] = raw_get_random_bytes(esys_ctx.get(), 16, raw_session);
            Botan::TPM2::check_rc("random byte generation successful", rc_random);
            result.test_eq_sz("some raw random bytes generated", bytes->size, 16);
         }),
   #endif
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

   #if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
         CHECK(
            "Authenticated sessions SRK",
            [&](Test::Result& result) {
               using Session = Botan::TPM2::Session;

               auto srk = ctx->storage_root_key({}, {});
               ok(result, "default", Session::authenticated_session(ctx, *srk));
               ok(result, "CFB(AES-128)", Session::authenticated_session(ctx, *srk, "CFB(AES-128)"));
               ok(result, "CFB(AES-128),SHA-384", Session::authenticated_session(ctx, *srk, "CFB(AES-128)", "SHA-384"));
               ok(result, "CFB(AES-128),SHA-1", Session::authenticated_session(ctx, *srk, "CFB(AES-128)", "SHA-1"));
            }),
   #endif

   #if defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
         CHECK("Authenticated sessions ECC", [&](Test::Result& result) {
            using Session = Botan::TPM2::Session;
            const auto persistent_key_id = Test::options().tpm2_persistent_ecc_handle();

            auto ecc_key = Botan::TPM2::EC_PrivateKey::load_persistent(ctx, persistent_key_id, {}, {});
            result.require("EK is not null", ecc_key != nullptr);
            result.test_eq("Algo", ecc_key->algo_name(), "ECDSA");
            result.confirm("Has persistent handle", ecc_key->handles().has_persistent_handle());

            ok(result, "default", Session::authenticated_session(ctx, *ecc_key));
            ok(result, "CFB(AES-128)", Session::authenticated_session(ctx, *ecc_key, "CFB(AES-128)"));
            ok(result,
               "CFB(AES-128),SHA-384",
               Session::authenticated_session(ctx, *ecc_key, "CFB(AES-128)", "SHA-384"));
            ok(result, "CFB(AES-128),SHA-1", Session::authenticated_session(ctx, *ecc_key, "CFB(AES-128)", "SHA-1"));
         }),
   #endif
   };
}

std::vector<Test::Result> test_tpm2_rng() {
   auto ctx = get_tpm2_context(__func__);
   if(!ctx) {
      return {bail_out()};
   }

   auto rng = Botan::TPM2::RandomNumberGenerator(ctx, Botan::TPM2::Session::unauthenticated_session(ctx));

   return {
      CHECK("Basic functionalities",
            [&](Test::Result& result) {
               result.confirm("Accepts input", rng.accepts_input());
               result.confirm("Is seeded", rng.is_seeded());
               result.test_eq("Right name", rng.name(), "TPM2_RNG");

               result.test_no_throw("Clear", [&] { rng.clear(); });
            }),

      CHECK("Random number generation",
            [&](Test::Result& result) {
               std::array<uint8_t, 8> buf1 = {};
               rng.randomize(buf1);
               result.confirm("Is at least not 0 (8)", not_zero_64(buf1));

               std::array<uint8_t, 15> buf2 = {};
               rng.randomize(buf2);
               result.confirm("Is at least not 0 (15)", not_zero_64(buf2));

               std::array<uint8_t, 256> buf3 = {};
               rng.randomize(buf3);
               result.confirm("Is at least not 0 (256)", not_zero_64(buf3));
            }),

      CHECK("Randomize with inputs",
            [&](Test::Result& result) {
               std::array<uint8_t, 9> buf1 = {};
               rng.randomize_with_input(buf1, std::array<uint8_t, 30>{});
               result.confirm("Randomized with inputs is at least not 0 (9)", not_zero_64(buf1));

               std::array<uint8_t, 66> buf2 = {};
               rng.randomize_with_input(buf2, std::array<uint8_t, 64>{});
               result.confirm("Randomized with inputs is at least not 0 (66)", not_zero_64(buf2));

               std::array<uint8_t, 256> buf3 = {};
               rng.randomize_with_input(buf3, std::array<uint8_t, 196>{});
               result.confirm("Randomized with inputs is at least not 0 (256)", not_zero_64(buf3));
            }),
   };
}

   #if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)

template <typename KeyT>
auto load_persistent(Test::Result& result,
                     const std::shared_ptr<Botan::TPM2::Context>& ctx,
                     uint32_t persistent_key_id,
                     std::span<const uint8_t> auth_value,
                     const std::shared_ptr<Botan::TPM2::Session>& session) {
   const auto persistent_handles = ctx->persistent_handles();
   result.confirm(
      "Persistent key available",
      std::find(persistent_handles.begin(), persistent_handles.end(), persistent_key_id) != persistent_handles.end());

   auto key = [&] {
      if constexpr(std::same_as<Botan::TPM2::RSA_PublicKey, KeyT>) {
         return KeyT::load_persistent(ctx, persistent_key_id, session);
      } else {
         return KeyT::load_persistent(ctx, persistent_key_id, auth_value, session);
      }
   }();

   result.test_eq("Algo", key->algo_name(), "RSA" /* TODO ECC support*/);
   result.test_is_eq("Handle", key->handles().persistent_handle(), persistent_key_id);
   return key;
}

std::vector<Test::Result> test_tpm2_rsa() {
   auto ctx = get_tpm2_context(__func__);
   if(!ctx) {
      return {bail_out()};
   }

   auto session = Botan::TPM2::Session::unauthenticated_session(ctx);

   const auto persistent_key_id = Test::options().tpm2_persistent_rsa_handle();
   const auto password = Test::options().tpm2_persistent_auth_value();

   return {
      CHECK("RSA and its helpers are supported",
            [&](Test::Result& result) {
               result.confirm("RSA is supported", ctx->supports_algorithm("RSA"));
               result.confirm("PKCS1 is supported", ctx->supports_algorithm("PKCS1v15"));
               result.confirm("PKCS1 with hash is supported", ctx->supports_algorithm("PKCS1v15(SHA-1)"));
               result.confirm("OAEP is supported", ctx->supports_algorithm("OAEP"));
               result.confirm("OAEP with hash is supported", ctx->supports_algorithm("OAEP(SHA-256)"));
               result.confirm("PSS is supported", ctx->supports_algorithm("PSS"));
               result.confirm("PSS with hash is supported", ctx->supports_algorithm("PSS(SHA-256)"));
            }),

      CHECK("Load the private key multiple times",
            [&](Test::Result& result) {
               for(size_t i = 0; i < 20; ++i) {
                  auto key =
                     load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
                  result.test_eq(Botan::fmt("Key loaded successfully ({})", i), key->algo_name(), "RSA");
               }
            }),

      CHECK("Sign a message",
            [&](Test::Result& result) {
               auto key =
                  load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);

               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

               // create a message that is larger than the TPM2 max buffer size
               const auto message = [] {
                  std::vector<uint8_t> msg(TPM2_MAX_DIGEST_BUFFER + 5);
                  for(size_t i = 0; i < msg.size(); ++i) {
                     msg[i] = static_cast<uint8_t>(i);
                  }
                  return msg;
               }();
               const auto signature = signer.sign_message(message, null_rng);
               result.require("signature is not empty", !signature.empty());

               auto public_key = key->public_key();
               Botan::PK_Verifier verifier(*public_key, "PSS(SHA-256)");
               result.confirm("Signature is valid", verifier.verify_message(message, signature));
            }),

      CHECK("verify signature",
            [&](Test::Result& result) {
               auto sign = [&](std::span<const uint8_t> message) {
                  auto key =
                     load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
                  return signer.sign_message(message, null_rng);
               };

               auto verify = [&](std::span<const uint8_t> msg, std::span<const uint8_t> sig) {
                  auto key =
                     load_persistent<Botan::TPM2::RSA_PublicKey>(result, ctx, persistent_key_id, password, session);
                  Botan::PK_Verifier verifier(*key, "PSS(SHA-256)");
                  return verifier.verify_message(msg, sig);
               };

               const auto message = Botan::hex_decode("baadcafe");
               const auto signature = sign(message);

               result.confirm("verification successful", verify(message, signature));

               // change the message
               auto rng = Test::new_rng(__func__);
               auto mutated_message = Test::mutate_vec(message, *rng);
               result.confirm("verification failed", !verify(mutated_message, signature));

               // ESAPI manipulates the session attributes internally and does
               // not reset them when an error occurs. A failure to validate a
               // signature is an error, and hence behaves surprisingly by
               // leaving the session attributes in an unexpected state.
               // The Botan wrapper has a workaround for this...
               const auto attrs = session->attributes();
               result.confirm("encrypt flag was not cleared by ESAPI", attrs.encrypt);

               // orignal message again
               result.confirm("verification still successful", verify(message, signature));
            }),

      CHECK("sign and verify multiple messages with the same Signer/Verifier objects",
            [&](Test::Result& result) {
               const std::vector<std::vector<uint8_t>> messages = {
                  Botan::hex_decode("BAADF00D"),
                  Botan::hex_decode("DEADBEEF"),
                  Botan::hex_decode("CAFEBABE"),
               };

               // Generate a few signatures, then deallocate the private key.
               auto signatures = [&] {
                  auto sk =
                     load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*sk, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
                  std::vector<std::vector<uint8_t>> sigs;
                  sigs.reserve(messages.size());
                  for(const auto& message : messages) {
                     sigs.emplace_back(signer.sign_message(message, null_rng));
                  }
                  return sigs;
               }();

               // verify via TPM 2.0
               auto pk = load_persistent<Botan::TPM2::RSA_PublicKey>(result, ctx, persistent_key_id, password, session);
               Botan::PK_Verifier verifier(*pk, "PSS(SHA-256)");
               for(size_t i = 0; i < messages.size(); ++i) {
                  result.confirm(Botan::fmt("verification successful ({})", i),
                                 verifier.verify_message(messages[i], signatures[i]));
               }

               // verify via software
               auto soft_pk = Botan::RSA_PublicKey(pk->algorithm_identifier(), pk->public_key_bits());
               Botan::PK_Verifier soft_verifier(soft_pk, "PSS(SHA-256)");
               for(size_t i = 0; i < messages.size(); ++i) {
                  result.confirm(Botan::fmt("software verification successful ({})", i),
                                 soft_verifier.verify_message(messages[i], signatures[i]));
               }
            }),

      CHECK("Wrong password is not accepted during signing",
            [&](Test::Result& result) {
               auto key = load_persistent<Botan::TPM2::RSA_PrivateKey>(
                  result, ctx, persistent_key_id, Botan::hex_decode("deadbeef"), session);

               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");

               const auto message = Botan::hex_decode("baadcafe");
               result.test_throws<Botan::TPM2::Error>("Fail with wrong password",
                                                      [&] { signer.sign_message(message, null_rng); });
            }),

      CHECK("Encrypt a message",
            [&](Test::Result& result) {
               auto pk = load_persistent<Botan::TPM2::RSA_PublicKey>(result, ctx, persistent_key_id, password, session);
               auto sk =
                  load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);

               const auto plaintext = Botan::hex_decode("feedc0debaadcafe");

               // encrypt a message using the TPM's public key
               Botan::Null_RNG null_rng;
               Botan::PK_Encryptor_EME enc(*pk, null_rng, "OAEP(SHA-256)");
               const auto ciphertext = enc.encrypt(plaintext, null_rng);

               // decrypt the message using the TPM's private RSA key
               Botan::PK_Decryptor_EME dec(*sk, null_rng, "OAEP(SHA-256)");
               const auto decrypted = dec.decrypt(ciphertext);
               result.test_eq("decrypted message", decrypted, plaintext);
            }),

      CHECK("Decrypt a message",
            [&](Test::Result& result) {
               auto key =
                  load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);

               const auto plaintext = Botan::hex_decode("feedface");

               // encrypt a message using a software RSA key for the TPM's private key
               auto pk = key->public_key();
               auto rng = Test::new_rng("tpm2 rsa decrypt");
               Botan::PK_Encryptor_EME enc(*pk, *rng, "OAEP(SHA-256)");
               const auto ciphertext = enc.encrypt(plaintext, *rng);

               // decrypt the message using the TPM's private key
               Botan::Null_RNG null_rng;
               Botan::PK_Decryptor_EME dec(*key, null_rng /* TPM takes care of this */, "OAEP(SHA-256)");
               const auto decrypted = dec.decrypt(ciphertext);
               result.test_eq("decrypted message", decrypted, plaintext);

               // corrupt the ciphertext and try to decrypt it
               auto mutated_ciphertext = Test::mutate_vec(ciphertext, *rng);
               result.test_throws<Botan::Decoding_Error>("Fail with wrong ciphertext",
                                                         [&] { dec.decrypt(mutated_ciphertext); });
            }),

      CHECK("Create a transient key and encrypt/decrypt a message",
            [&](Test::Result& result) {
               auto srk = ctx->storage_root_key({}, {});
               auto authed_session = Botan::TPM2::Session::authenticated_session(ctx, *srk);

               const std::array<uint8_t, 6> secret = {'s', 'e', 'c', 'r', 'e', 't'};
               auto sk =
                  Botan::TPM2::RSA_PrivateKey::create_unrestricted_transient(ctx, authed_session, secret, *srk, 2048);
               auto pk = sk->public_key();

               const auto plaintext = Botan::hex_decode("feedc0debaadcafe");

               // encrypt a message using the TPM's public key
               auto rng = Test::new_rng(__func__);
               Botan::PK_Encryptor_EME enc(*pk, *rng, "OAEP(SHA-256)");
               const auto ciphertext = enc.encrypt(plaintext, *rng);

               // decrypt the message using the TPM's private RSA key
               Botan::Null_RNG null_rng;
               Botan::PK_Decryptor_EME dec(*sk, null_rng, "OAEP(SHA-256)");
               const auto decrypted = dec.decrypt(ciphertext);
               result.test_eq("decrypted message", decrypted, plaintext);

               // encrypt a message using the TPM's public key (using PKCS#1)
               Botan::PK_Encryptor_EME enc_pkcs(*pk, *rng, "PKCS1v15");
               const auto ciphertext_pkcs = enc_pkcs.encrypt(plaintext, *rng);

               // decrypt the message using the TPM's private RSA key (using PKCS#1)
               Botan::PK_Decryptor_EME dec_pkcs(*sk, null_rng, "PKCS1v15");
               const auto decrypted_pkcs = dec_pkcs.decrypt(ciphertext_pkcs);
               result.test_eq("decrypted message", decrypted_pkcs, plaintext);
            }),

      CHECK("Cannot export private key blob from persistent key",
            [&](Test::Result& result) {
               auto key =
                  load_persistent<Botan::TPM2::RSA_PrivateKey>(result, ctx, persistent_key_id, password, session);
               result.test_throws<Botan::Not_Implemented>("Export private key blob not implemented",
                                                          [&] { key->private_key_bits(); });
               result.test_throws<Botan::Invalid_State>("Export raw private key blob not implemented",
                                                        [&] { key->raw_private_key_bits(); });
            }),

      CHECK("Create a new transient key",
            [&](Test::Result& result) {
               auto srk = ctx->storage_root_key({}, {});

               auto authed_session = Botan::TPM2::Session::authenticated_session(ctx, *srk);

               const std::array<uint8_t, 6> secret = {'s', 'e', 'c', 'r', 'e', 't'};

               auto sk =
                  Botan::TPM2::RSA_PrivateKey::create_unrestricted_transient(ctx, authed_session, secret, *srk, 2048);

               result.require("key was created", sk != nullptr);
               result.confirm("is transient", sk->handles().has_transient_handle());
               result.confirm("is not persistent", !sk->handles().has_persistent_handle());

               const auto sk_blob = sk->raw_private_key_bits();
               const auto pk_blob = sk->raw_public_key_bits();
               const auto pk = sk->public_key();

               result.confirm("secret blob is not empty", !sk_blob.empty());
               result.confirm("public blob is not empty", !pk_blob.empty());

               // Perform a round-trip sign/verify test with the new key pair
               std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
               Botan::Null_RNG null_rng;
               Botan::PK_Signer signer(*sk, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
               const auto signature = signer.sign_message(message, null_rng);
               result.require("signature is not empty", !signature.empty());

               Botan::PK_Verifier verifier(*pk, "PSS(SHA-256)");
               result.confirm("Signature is valid", verifier.verify_message(message, signature));

               // Destruct the key and load it again from the encrypted blob
               sk.reset();
               auto sk_loaded =
                  Botan::TPM2::PrivateKey::load_transient(ctx, secret, *srk, pk_blob, sk_blob, authed_session);
               result.require("key was loaded", sk_loaded != nullptr);
               result.test_eq("loaded key is RSA", sk_loaded->algo_name(), "RSA");

               const auto sk_blob_loaded = sk_loaded->raw_private_key_bits();
               const auto pk_blob_loaded = sk_loaded->raw_public_key_bits();

               result.test_is_eq("secret blob did not change", sk_blob, sk_blob_loaded);
               result.test_is_eq("public blob did not change", pk_blob, pk_blob_loaded);

               // Perform a round-trip sign/verify test with the new key pair
               std::vector<uint8_t> message_loaded = {'g', 'u', 't', 'e', 'n', ' ', 't', 'a', 'g'};
               Botan::PK_Signer signer_loaded(*sk_loaded, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
               const auto signature_loaded = signer_loaded.sign_message(message_loaded, null_rng);
               result.require("Next signature is not empty", !signature_loaded.empty());
               result.confirm("Existing verifier can validate signature",
                              verifier.verify_message(message_loaded, signature_loaded));

               // Load the public portion of the key
               auto pk_loaded = Botan::TPM2::PublicKey::load_transient(ctx, pk_blob, {});
               result.require("public key was loaded", pk_loaded != nullptr);

               Botan::PK_Verifier verifier_loaded(*pk_loaded, "PSS(SHA-256)");
               result.confirm("TPM-verified signature is valid",
                              verifier_loaded.verify_message(message_loaded, signature_loaded));

               // Perform a round-trip sign/verify test with the new key pair (PKCS#1)
               std::vector<uint8_t> message_pkcs = {'b', 'o', 'n', 'j', 'o', 'u', 'r'};
               Botan::PK_Signer signer_pkcs(*sk_loaded, null_rng /* TPM takes care of this */, "PKCS1v15(SHA-256)");
               const auto signature_pkcs = signer_pkcs.sign_message(message_pkcs, null_rng);
               result.require("Next signature is not empty", !signature_pkcs.empty());
               result.confirm("Existing verifier cannot validate signature",
                              !verifier.verify_message(message_pkcs, signature_pkcs));

               // Create a verifier for PKCS#1
               Botan::PK_Verifier verifier_pkcs(*pk_loaded, "PKCS1v15(SHA-256)");
               result.confirm("TPM-verified signature is valid",
                              verifier_pkcs.verify_message(message_pkcs, signature_pkcs));
            }),

      CHECK("Make a transient key persistent then remove it again",
            [&](Test::Result& result) {
               auto srk = ctx->storage_root_key({}, {});

               auto sign_verify_roundtrip = [&](const Botan::TPM2::PrivateKey& key) {
                  std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(key, null_rng /* TPM takes care of this */, "PSS(SHA-256)");
                  const auto signature = signer.sign_message(message, null_rng);
                  result.require("signature is not empty", !signature.empty());

                  auto pk = key.public_key();
                  Botan::PK_Verifier verifier(*pk, "PSS(SHA-256)");
                  result.confirm("Signature is valid", verifier.verify_message(message, signature));
               };

               // Create Key
               auto authed_session = Botan::TPM2::Session::authenticated_session(ctx, *srk);

               const std::array<uint8_t, 6> secret = {'s', 'e', 'c', 'r', 'e', 't'};
               auto sk =
                  Botan::TPM2::RSA_PrivateKey::create_unrestricted_transient(ctx, authed_session, secret, *srk, 2048);
               result.require("key was created", sk != nullptr);
               result.confirm("is transient", sk->handles().has_transient_handle());
               result.confirm("is not persistent", !sk->handles().has_persistent_handle());
               result.test_no_throw("use key after creation", [&] { sign_verify_roundtrip(*sk); });

               // Make it persistent
               const auto handles = ctx->persistent_handles().size();
               const auto new_location = ctx->persist(*sk, authed_session, secret);
               result.test_eq("One more handle", ctx->persistent_handles().size(), handles + 1);
               result.confirm("New location occupied", Botan::value_exists(ctx->persistent_handles(), new_location));
               result.confirm("is persistent", sk->handles().has_persistent_handle());
               result.test_is_eq(
                  "Persistent handle is the new handle", sk->handles().persistent_handle(), new_location);
               result.test_throws<Botan::Invalid_Argument>(
                  "Cannot persist to the same location", [&] { ctx->persist(*sk, authed_session, {}, new_location); });
               result.test_throws<Botan::Invalid_Argument>("Cannot persist and already persistent key",
                                                           [&] { ctx->persist(*sk, authed_session); });
               result.test_no_throw("use key after persisting", [&] { sign_verify_roundtrip(*sk); });

               // Evict it
               ctx->evict(std::move(sk), authed_session);
               result.test_eq("One less handle", ctx->persistent_handles().size(), handles);
               result.confirm("New location no longer occupied",
                              !Botan::value_exists(ctx->persistent_handles(), new_location));
            }),
   };
}

   #endif

   #if defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
template <typename KeyT>
auto load_persistent_ecc(Test::Result& result,
                         const std::shared_ptr<Botan::TPM2::Context>& ctx,
                         uint32_t persistent_key_id,
                         std::span<const uint8_t> auth_value,
                         const std::shared_ptr<Botan::TPM2::Session>& session) {
   // TODO: Merge with RSA
   const auto persistent_handles = ctx->persistent_handles();
   result.confirm(
      "Persistent key available",
      std::find(persistent_handles.begin(), persistent_handles.end(), persistent_key_id) != persistent_handles.end());

   auto key = [&] {
      if constexpr(std::same_as<Botan::TPM2::EC_PublicKey, KeyT>) {
         return KeyT::load_persistent(ctx, persistent_key_id, session);
      } else {
         return KeyT::load_persistent(ctx, persistent_key_id, auth_value, session);
      }
   }();

   result.test_eq("Algo", key->algo_name(), "ECDSA");
   result.test_is_eq("Handle", key->handles().persistent_handle(), persistent_key_id);
   return key;
}

std::vector<Test::Result> test_tpm2_ecc() {
   //TODO: Merge with RSA?
   auto ctx = get_tpm2_context(__func__);
   if(!ctx) {
      return {bail_out()};
   }

   auto session = Botan::TPM2::Session::unauthenticated_session(ctx);

   const auto persistent_key_id = Test::options().tpm2_persistent_ecc_handle();
   const auto password = Test::options().tpm2_persistent_auth_value();

   return {
      CHECK("ECC and its helpers are supported",
            [&](Test::Result& result) {
               result.confirm("ECC is supported", ctx->supports_algorithm("ECC"));
               result.confirm("ECDSA is supported", ctx->supports_algorithm("ECDSA"));
            }),
         CHECK("Load the private key multiple times",
               [&](Test::Result& result) {
                  for(size_t i = 0; i < 20; ++i) {
                     auto key = load_persistent_ecc<Botan::TPM2::EC_PrivateKey>(
                        result, ctx, persistent_key_id, password, session);
                     result.test_eq(Botan::fmt("Key loaded successfully ({})", i), key->algo_name(), "ECDSA");
                  }
               }),
         CHECK("Sign a message ECDSA",
               [&](Test::Result& result) {
                  auto key =
                     load_persistent_ecc<Botan::TPM2::EC_PrivateKey>(result, ctx, persistent_key_id, password, session);

                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "SHA-256");

                  // create a message that is larger than the TPM2 max buffer size
                  const auto message = [] {
                     std::vector<uint8_t> msg(TPM2_MAX_DIGEST_BUFFER + 5);
                     for(size_t i = 0; i < msg.size(); ++i) {
                        msg[i] = static_cast<uint8_t>(i);
                     }
                     return msg;
                  }();
                  const auto signature = signer.sign_message(message, null_rng);
                  result.require("signature is not empty", !signature.empty());

                  auto public_key = key->public_key();
                  Botan::PK_Verifier verifier(*public_key, "SHA-256");
                  result.confirm("Signature is valid", verifier.verify_message(message, signature));
               }),
         CHECK("verify signature ECDSA",
               [&](Test::Result& result) {
                  auto sign = [&](std::span<const uint8_t> message) {
                     auto key = load_persistent_ecc<Botan::TPM2::EC_PrivateKey>(
                        result, ctx, persistent_key_id, password, session);
                     Botan::Null_RNG null_rng;
                     Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "SHA-256");
                     return signer.sign_message(message, null_rng);
                  };

                  auto verify = [&](std::span<const uint8_t> msg, std::span<const uint8_t> sig) {
                     auto key = load_persistent_ecc<Botan::TPM2::EC_PublicKey>(
                        result, ctx, persistent_key_id, password, session);
                     Botan::PK_Verifier verifier(*key, "SHA-256");
                     return verifier.verify_message(msg, sig);
                  };

                  const auto message = Botan::hex_decode("baadcafe");
                  const auto signature = sign(message);

                  result.confirm("verification successful", verify(message, signature));

                  // change the message
                  auto rng = Test::new_rng(__func__);
                  auto mutated_message = Test::mutate_vec(message, *rng);
                  result.confirm("verification failed", !verify(mutated_message, signature));

                  // ESAPI manipulates the session attributes internally and does
                  // not reset them when an error occurs. A failure to validate a
                  // signature is an error, and hence behaves surprisingly by
                  // leaving the session attributes in an unexpected state.
                  // The Botan wrapper has a workaround for this...
                  const auto attrs = session->attributes();
                  result.confirm("encrypt flag was not cleared by ESAPI", attrs.encrypt);

                  // orignal message again
                  result.confirm("verification still successful", verify(message, signature));
               }),

         CHECK("sign and verify multiple messages with the same Signer/Verifier objects",
               [&](Test::Result& result) {
                  const std::vector<std::vector<uint8_t>> messages = {
                     Botan::hex_decode("BAADF00D"),
                     Botan::hex_decode("DEADBEEF"),
                     Botan::hex_decode("CAFEBABE"),
                  };

                  // Generate a few signatures, then deallocate the private key.
                  auto signatures = [&] {
                     auto sk = load_persistent_ecc<Botan::TPM2::EC_PrivateKey>(
                        result, ctx, persistent_key_id, password, session);
                     Botan::Null_RNG null_rng;
                     Botan::PK_Signer signer(*sk, null_rng /* TPM takes care of this */, "SHA-256");
                     std::vector<std::vector<uint8_t>> sigs;
                     sigs.reserve(messages.size());
                     for(const auto& message : messages) {
                        sigs.emplace_back(signer.sign_message(message, null_rng));
                     }
                     return sigs;
                  }();

                  // verify via TPM 2.0
                  auto pk =
                     load_persistent_ecc<Botan::TPM2::EC_PublicKey>(result, ctx, persistent_key_id, password, session);
                  Botan::PK_Verifier verifier(*pk, "SHA-256");
                  for(size_t i = 0; i < messages.size(); ++i) {
                     result.confirm(Botan::fmt("verification successful ({})", i),
                                    verifier.verify_message(messages[i], signatures[i]));
                  }

                  // verify via software
                  auto soft_pk =
                     load_persistent_ecc<Botan::TPM2::EC_PrivateKey>(result, ctx, persistent_key_id, password, session)
                        ->public_key();
                  Botan::PK_Verifier soft_verifier(*soft_pk, "SHA-256");
                  for(size_t i = 0; i < messages.size(); ++i) {
                     result.confirm(Botan::fmt("software verification successful ({})", i),
                                    soft_verifier.verify_message(messages[i], signatures[i]));
                  }
               }),

         CHECK("Wrong password is not accepted during ECDSA signing",
               [&](Test::Result& result) {
                  auto key = load_persistent_ecc<Botan::TPM2::EC_PrivateKey>(
                     result, ctx, persistent_key_id, Botan::hex_decode("deadbeef"), session);

                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*key, null_rng /* TPM takes care of this */, "SHA-256");

                  const auto message = Botan::hex_decode("baadcafe");
                  result.test_throws<Botan::TPM2::Error>("Fail with wrong password",
                                                         [&] { signer.sign_message(message, null_rng); });
               }),

      // SRK is an RSA key, so we can only test with the RSA adapter
      #if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
         CHECK("Create a transient ECDSA key and sign/verify a message",
               [&](Test::Result& result) {
                  auto srk = ctx->storage_root_key({}, {});
                  auto ecc_session_key =
                     Botan::TPM2::EC_PrivateKey::load_persistent(ctx, persistent_key_id, password, {});
                  auto authed_session = Botan::TPM2::Session::authenticated_session(ctx, *ecc_session_key);

                  const std::array<uint8_t, 6> secret = {'s', 'e', 'c', 'r', 'e', 't'};
                  auto sk = Botan::TPM2::EC_PrivateKey::create_unrestricted_transient(
                     ctx, authed_session, secret, *srk, Botan::EC_Group::from_name("secp521r1"));
                  auto pk = sk->public_key();

                  const auto plaintext = Botan::hex_decode("feedc0debaadcafe");

                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*sk, null_rng /* TPM takes care of this */, "SHA-256");

                  // create a message that is larger than the TPM2 max buffer size
                  const auto message = [] {
                     std::vector<uint8_t> msg(TPM2_MAX_DIGEST_BUFFER + 5);
                     for(size_t i = 0; i < msg.size(); ++i) {
                        msg[i] = static_cast<uint8_t>(i);
                     }
                     return msg;
                  }();
                  const auto signature = signer.sign_message(message, null_rng);
                  result.require("signature is not empty", !signature.empty());

                  auto public_key = sk->public_key();
                  Botan::PK_Verifier verifier(*public_key, "SHA-256");
                  result.confirm("Signature is valid", verifier.verify_message(message, signature));
               }),

         CHECK("Create a new transient ECDSA key",
               [&](Test::Result& result) {
                  auto srk = ctx->storage_root_key({}, {});
                  auto ecc_session_key =
                     Botan::TPM2::EC_PrivateKey::load_persistent(ctx, persistent_key_id, password, {});

                  auto authed_session = Botan::TPM2::Session::authenticated_session(ctx, *ecc_session_key);

                  const std::array<uint8_t, 6> secret = {'s', 'e', 'c', 'r', 'e', 't'};

                  auto sk = Botan::TPM2::EC_PrivateKey::create_unrestricted_transient(
                     ctx, authed_session, secret, *srk, Botan::EC_Group::from_name("secp384r1"));

                  result.require("key was created", sk != nullptr);
                  result.confirm("is transient", sk->handles().has_transient_handle());
                  result.confirm("is not persistent", !sk->handles().has_persistent_handle());

                  const auto sk_blob = sk->raw_private_key_bits();
                  const auto pk_blob = sk->raw_public_key_bits();
                  const auto pk = sk->public_key();

                  result.confirm("secret blob is not empty", !sk_blob.empty());
                  result.confirm("public blob is not empty", !pk_blob.empty());

                  // Perform a round-trip sign/verify test with the new key pair
                  std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(*sk, null_rng /* TPM takes care of this */, "SHA-256");
                  const auto signature = signer.sign_message(message, null_rng);
                  result.require("signature is not empty", !signature.empty());

                  Botan::PK_Verifier verifier(*pk, "SHA-256");
                  result.confirm("Signature is valid", verifier.verify_message(message, signature));

                  // Destruct the key and load it again from the encrypted blob
                  sk.reset();
                  auto sk_loaded =
                     Botan::TPM2::PrivateKey::load_transient(ctx, secret, *srk, pk_blob, sk_blob, authed_session);
                  result.require("key was loaded", sk_loaded != nullptr);
                  result.test_eq("loaded key is ECDSA", sk_loaded->algo_name(), "ECDSA");

                  const auto sk_blob_loaded = sk_loaded->raw_private_key_bits();
                  const auto pk_blob_loaded = sk_loaded->raw_public_key_bits();

                  result.test_is_eq("secret blob did not change", sk_blob, sk_blob_loaded);
                  result.test_is_eq("public blob did not change", pk_blob, pk_blob_loaded);

                  // Perform a round-trip sign/verify test with the new key pair
                  std::vector<uint8_t> message_loaded = {'g', 'u', 't', 'e', 'n', ' ', 't', 'a', 'g'};
                  Botan::PK_Signer signer_loaded(*sk_loaded, null_rng /* TPM takes care of this */, "SHA-256");
                  const auto signature_loaded = signer_loaded.sign_message(message_loaded, null_rng);
                  result.require("Next signature is not empty", !signature_loaded.empty());
                  result.confirm("Existing verifier can validate signature",
                                 verifier.verify_message(message_loaded, signature_loaded));

                  // Load the public portion of the key
                  auto pk_loaded = Botan::TPM2::PublicKey::load_transient(ctx, pk_blob, {});
                  result.require("public key was loaded", pk_loaded != nullptr);

                  Botan::PK_Verifier verifier_loaded(*pk_loaded, "SHA-256");
                  result.confirm("TPM-verified signature is valid",
                                 verifier_loaded.verify_message(message_loaded, signature_loaded));
               }),

         CHECK(
            "Make a transient ECDSA key persistent then remove it again",
            [&](Test::Result& result) {
               auto srk = ctx->storage_root_key({}, {});
               auto ecc_session_key = Botan::TPM2::EC_PrivateKey::load_persistent(ctx, persistent_key_id, password, {});

               auto sign_verify_roundtrip = [&](const Botan::TPM2::PrivateKey& key) {
                  std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
                  Botan::Null_RNG null_rng;
                  Botan::PK_Signer signer(key, null_rng /* TPM takes care of this */, "SHA-256");
                  const auto signature = signer.sign_message(message, null_rng);
                  result.require("signature is not empty", !signature.empty());

                  auto pk = key.public_key();
                  Botan::PK_Verifier verifier(*pk, "SHA-256");
                  result.confirm("Signature is valid", verifier.verify_message(message, signature));
               };

               // Create Key
               auto authed_session = Botan::TPM2::Session::authenticated_session(ctx, *ecc_session_key);

               const std::array<uint8_t, 6> secret = {'s', 'e', 'c', 'r', 'e', 't'};
               auto sk = Botan::TPM2::EC_PrivateKey::create_unrestricted_transient(
                  ctx, authed_session, secret, *srk, Botan::EC_Group::from_name("secp192r1"));
               result.require("key was created", sk != nullptr);
               result.confirm("is transient", sk->handles().has_transient_handle());
               result.confirm("is not persistent", !sk->handles().has_persistent_handle());
               result.test_no_throw("use key after creation", [&] { sign_verify_roundtrip(*sk); });

               // Make it persistent
               const auto handles = ctx->persistent_handles().size();
               const auto new_location = ctx->persist(*sk, authed_session, secret);
               result.test_eq("One more handle", ctx->persistent_handles().size(), handles + 1);
               result.confirm("New location occupied", Botan::value_exists(ctx->persistent_handles(), new_location));
               result.confirm("is persistent", sk->handles().has_persistent_handle());
               result.test_is_eq(
                  "Persistent handle is the new handle", sk->handles().persistent_handle(), new_location);
               result.test_throws<Botan::Invalid_Argument>(
                  "Cannot persist to the same location", [&] { ctx->persist(*sk, authed_session, {}, new_location); });
               result.test_throws<Botan::Invalid_Argument>("Cannot persist and already persistent key",
                                                           [&] { ctx->persist(*sk, authed_session); });
               result.test_no_throw("use key after persisting", [&] { sign_verify_roundtrip(*sk); });

               // Evict it
               ctx->evict(std::move(sk), authed_session);
               result.test_eq("One less handle", ctx->persistent_handles().size(), handles);
               result.confirm("New location no longer occupied",
                              !Botan::value_exists(ctx->persistent_handles(), new_location));
            }),
      #endif

         CHECK("Read a software public key from a TPM serialization", [&](Test::Result& result) {
            auto pk = load_persistent_ecc<Botan::TPM2::EC_PublicKey>(result, ctx, persistent_key_id, password, session);
            result.test_no_throw("Botan can read serialized ECC public key", [&] {
               auto pk_sw = Botan::ECDSA_PublicKey(pk->algorithm_identifier(), pk->public_key_bits());
            });

            auto sk =
               load_persistent_ecc<Botan::TPM2::EC_PrivateKey>(result, ctx, persistent_key_id, password, session);
            result.test_no_throw("Botan can read serialized public key from ECC private key", [&] {
               auto sk_sw = Botan::ECDSA_PublicKey(sk->algorithm_identifier(), sk->public_key_bits());
            });
         }),
   };
}
   #endif

std::vector<Test::Result> test_tpm2_hash() {
   auto ctx = get_tpm2_context(__func__);
   if(!ctx) {
      return {bail_out()};
   }

   auto test = [&](Test::Result& result, std::string_view algo) {
      auto tpm_hash = [&]() -> std::unique_ptr<Botan::TPM2::HashFunction> {
         try {
            return std::make_unique<Botan::TPM2::HashFunction>(
               ctx, algo, ESYS_TR_RH_NULL, Botan::TPM2::Session::unauthenticated_session(ctx));
         } catch(const Botan::Lookup_Error&) {
            return {};
         }
      }();
      auto soft_hash = Botan::HashFunction::create(algo);

      if(!tpm_hash) {
         result.test_note(Botan::fmt("Skipping {}, TPM 2.0 does not support it", algo));
         return;
      }

      if(!soft_hash) {
         result.test_note(Botan::fmt("Skipping {}, no software equivalent available", algo));
         return;
      }

      result.test_eq("Name", tpm_hash->name(), soft_hash->name());
      result.test_eq("Output length", tpm_hash->output_length(), soft_hash->output_length());

      // multiple update calls
      tpm_hash->update("Hello, ");
      tpm_hash->update("world!");
      result.test_eq("digest (multi-update)", tpm_hash->final(), soft_hash->process("Hello, world!"));

      // single process call
      result.test_eq("digest (single-process)", tpm_hash->process("Hallo, Welt."), soft_hash->process("Hallo, Welt."));

      // create a message that is larger than the TPM2 max buffer size
      const auto long_message = [] {
         std::vector<uint8_t> msg(TPM2_MAX_DIGEST_BUFFER + 5);
         for(size_t i = 0; i < msg.size(); ++i) {
            msg[i] = static_cast<uint8_t>(i);
         }
         return msg;
      }();

      tpm_hash->update(long_message);
      result.test_eq("digest (long msg via update)", tpm_hash->final(), soft_hash->process(long_message));
      result.test_eq(
         "digest (long msg via process)", tpm_hash->process(long_message), soft_hash->process(long_message));

      // test clear
      tpm_hash->update("Hello");
      tpm_hash->clear();
      tpm_hash->update("Bonjour");
      result.test_eq("digest (clear)", tpm_hash->final(), soft_hash->process("Bonjour"));

      // new_object
      auto new_tpm_hash = tpm_hash->new_object();
      result.test_eq("Name (new_object)", new_tpm_hash->name(), tpm_hash->name());
      result.test_eq("Output length (new_object)", new_tpm_hash->output_length(), tpm_hash->output_length());
      result.test_eq("digest (new object)",
                     new_tpm_hash->process("Salut tout le monde!"),
                     soft_hash->process("Salut tout le monde!"));
   };

   return {
      CHECK("Hashes are supported",
            [&](Test::Result& result) {
               result.confirm("SHA-1 is supported", ctx->supports_algorithm("SHA-1"));
               result.confirm("SHA-256 is supported", ctx->supports_algorithm("SHA-256"));
               result.confirm("SHA-384 is supported", ctx->supports_algorithm("SHA-384"));
               result.confirm("SHA-512 is supported", ctx->supports_algorithm("SHA-512"));
            }),

      CHECK("SHA-1", [&](Test::Result& result) { test(result, "SHA-1"); }),
      CHECK("SHA-256", [&](Test::Result& result) { test(result, "SHA-256"); }),
      CHECK("SHA-384", [&](Test::Result& result) { test(result, "SHA-384"); }),
      CHECK("SHA-512", [&](Test::Result& result) { test(result, "SHA-512"); }),
      CHECK("SHA-3(256)", [&](Test::Result& result) { test(result, "SHA-3(256)"); }),
      CHECK("SHA-3(384)", [&](Test::Result& result) { test(result, "SHA-3(384)"); }),
      CHECK("SHA-3(512)", [&](Test::Result& result) { test(result, "SHA-3(512)"); }),

      CHECK("lookup error",
            [&](Test::Result& result) {
               result.test_throws<Botan::Lookup_Error>(
                  "Lookup error", [&] { [[maybe_unused]] auto _ = Botan::TPM2::HashFunction(ctx, "MD-5"); });
            }),

      CHECK("copy_state is not implemented",
            [&](Test::Result& result) {
               auto tpm_hash = Botan::TPM2::HashFunction(ctx, "SHA-256");
               result.test_throws<Botan::Not_Implemented>("TPM2 hash does not support copy_state",
                                                          [&] { [[maybe_unused]] auto _ = tpm_hash.copy_state(); });
            }),

      CHECK("validation ticket",
            [&](Test::Result& result) {
               // using the NULL hierarchy essentially disables the validation ticket
               auto tpm_hash_null = Botan::TPM2::HashFunction(
                  ctx, "SHA-256", ESYS_TR_RH_NULL, Botan::TPM2::Session::unauthenticated_session(ctx));
               tpm_hash_null.update("Hola mundo!");
               const auto [digest_null, ticket_null] = tpm_hash_null.final_with_ticket();
               result.require("digest is set", digest_null != nullptr);
               result.require("ticket is set", ticket_null != nullptr);
               result.confirm("ticket is empty", ticket_null->digest.size == 0);

               // using the OWNER hierarchy (for instance) enables the validation ticket
               auto tpm_hash_owner = Botan::TPM2::HashFunction(
                  ctx, "SHA-256", ESYS_TR_RH_OWNER, Botan::TPM2::Session::unauthenticated_session(ctx));
               tpm_hash_owner.update("Hola mundo!");
               const auto [digest_owner, ticket_owner] = tpm_hash_owner.final_with_ticket();
               result.require("digest is set", digest_owner != nullptr);
               result.require("ticket is set", ticket_owner != nullptr);
               result.confirm("ticket is not empty", ticket_owner->digest.size > 0);

               const auto digest_vec = Botan::TPM2::copy_into<Botan::secure_vector<uint8_t>>(*digest_owner);
               result.test_eq("digest",
                              digest_vec,
                              Botan::hex_decode("1e479f4d871e59e9054aad62105a259726801d5f494acbfcd40591c82f9b3136"));

               result.test_eq("digests are the same, regardless of ticket",
                              Botan::TPM2::copy_into<std::vector<uint8_t>>(*digest_null),
                              digest_vec);
            }),
   };
}

}  // namespace

BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_props", test_tpm2_properties);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_ctx", test_tpm2_context);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_external_ctx", test_external_tpm2_context);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_sessions", test_tpm2_sessions);
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_rng", test_tpm2_rng);
   #if defined(BOTAN_HAS_TPM2_RSA_ADAPTER)
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_rsa", test_tpm2_rsa);
   #endif
   #if defined(BOTAN_HAS_TPM2_ECC_ADAPTER)
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_ecc", test_tpm2_ecc);
   #endif
BOTAN_REGISTER_TEST_FN("tpm2", "tpm2_hash", test_tpm2_hash);

#endif

}  // namespace Botan_Tests
