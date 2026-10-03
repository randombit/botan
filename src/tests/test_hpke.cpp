/*
 * (C) 2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#if defined(BOTAN_HAS_HPKE)
   #include <botan/ec_group.h>
   #include <botan/ecdh.h>
   #include <botan/exceptn.h>
   #include <botan/hex.h>
   #include <botan/hpke.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs8.h>
   #include <botan/rng.h>
   #include <botan/x509_key.h>
   #include <botan/internal/hpke_kem.h>

   #if defined(BOTAN_HAS_X25519)
      #include <botan/x25519.h>
   #endif
   #if defined(BOTAN_HAS_X448)
      #include <botan/x448.h>
   #endif
   #if defined(BOTAN_HAS_ECDSA)
      #include <botan/ecdsa.h>
   #endif
   #if defined(BOTAN_HAS_ECGDSA)
      #include <botan/ecgdsa.h>
   #endif
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HPKE)

namespace {

std::vector<uint8_t> to_bytes(std::string_view s) {
   return std::vector<uint8_t>(s.begin(), s.end());
}

class HPKE_KAT_Tests final : public Text_Based_Test {
   public:
      HPKE_KAT_Tests() :
            Text_Based_Test("pubkey/hpke.vec",
                            "Mode,Kem,Kdf,Aead,Info,IkmR,SkRm,PkRm,IkmE,SkEm,PkEm,Enc,SharedSecret",
                            "Psk,PskId,IkmS,SkSm,PkSm,Aad,Pt,Ct,SkipSeq,SkipAad,SkipPt,SkipCt,"
                            "ExportEmptyCtxVal,ExportCtx,ExportVal") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result("HPKE KAT " + header);

         const auto mode = static_cast<Botan::HPKE::Mode>(vars.get_req_sz("Mode"));
         const Botan::HPKE::Suite suite(static_cast<uint16_t>(vars.get_req_sz("Kem")),
                                        static_cast<uint16_t>(vars.get_req_sz("Kdf")),
                                        static_cast<uint16_t>(vars.get_req_sz("Aead")));

         if(!suite.is_available()) {
            result.note_missing("HPKE suite " + suite.to_string().value_or("unknown"));
            return result;
         }

         auto rng = Test::new_rng("hpke_kat");

         const auto info = vars.get_req_bin("Info");
         const auto enc = vars.get_req_bin("Enc");
         const auto shared_secret = vars.get_req_bin("SharedSecret");
         const auto kem = suite.kem();

         // DeriveKeyPair and key serialization KATs
         const auto skR = Botan::HPKE::Private_Key::derive(kem, vars.get_req_bin("IkmR"));
         result.test_bin_eq("DeriveKeyPair skR", skR.serialize(), vars.get_req_bin("SkRm"));
         result.test_bin_eq("DeriveKeyPair pkR", skR.public_key().serialize(), vars.get_req_bin("PkRm"));

         const auto skE = Botan::HPKE::Private_Key::derive(kem, vars.get_req_bin("IkmE"));
         result.test_bin_eq("DeriveKeyPair skE", skE.serialize(), vars.get_req_bin("SkEm"));
         result.test_bin_eq("DeriveKeyPair pkE", skE.public_key().serialize(), vars.get_req_bin("PkEm"));

         const auto skR2 = Botan::HPKE::Private_Key::deserialize(kem, vars.get_req_bin("SkRm"));
         result.test_bin_eq("DeserializePrivateKey", skR2.public_key().serialize(), vars.get_req_bin("PkRm"));

         const auto pkR = Botan::HPKE::Public_Key::deserialize(kem, vars.get_req_bin("PkRm"));
         result.test_bin_eq("SerializePublicKey", pkR.serialize(), vars.get_req_bin("PkRm"));
         result.test_is_true("public key equality", pkR == skR.public_key());

         std::optional<Botan::HPKE::Private_Key> skS;
         std::optional<Botan::HPKE::Public_Key> pkS;
         if(vars.has_key("SkSm")) {
            skS = Botan::HPKE::Private_Key::derive(kem, vars.get_req_bin("IkmS"));
            result.test_bin_eq("DeriveKeyPair skS", skS->serialize(), vars.get_req_bin("SkSm"));
            pkS = skS->public_key();
            result.test_bin_eq("DeriveKeyPair pkS", pkS->serialize(), vars.get_req_bin("PkSm"));
         }

         std::optional<Botan::HPKE::PSK> psk;
         if(vars.has_key("Psk")) {
            psk.emplace(vars.get_req_bin("Psk"), vars.get_req_bin("PskId"));
         }

         // KEM-level encap/decap KATs using the internal interface, with
         // the ephemeral key fixed from the test vector
         const auto ops = Botan::HPKE::KEM_Ops::create(kem);

         const auto kat_encap = [&]() {
            if(skS.has_value()) {
               return ops->auth_encap_with_ephemeral(pkR.underlying(), skS->underlying(), skE.underlying(), *rng);
            }
            return ops->encap_with_ephemeral(pkR.underlying(), skE.underlying(), *rng);
         }();
         result.test_bin_eq("Encap enc", kat_encap.enc, enc);
         result.test_bin_eq("Encap shared_secret", kat_encap.shared_secret, shared_secret);

         const auto kat_decap = [&]() {
            if(pkS.has_value()) {
               return ops->auth_decap(enc, skR.underlying(), pkS->underlying(), *rng);
            }
            return ops->decap(enc, skR.underlying(), *rng);
         }();
         result.test_bin_eq("Decap shared_secret", kat_decap, shared_secret);

         const auto setup_recipient = [&](std::span<const uint8_t> r_enc) -> Botan::HPKE::Recipient_Context {
            switch(mode) {
               case Botan::HPKE::Mode::Base:
                  return Botan::HPKE::Recipient_Context::setup_base(suite, skR, r_enc, *rng, info);
               case Botan::HPKE::Mode::PSK:
                  return Botan::HPKE::Recipient_Context::setup_psk(suite, skR, r_enc, *rng, *psk, info);
               case Botan::HPKE::Mode::Auth:
                  return Botan::HPKE::Recipient_Context::setup_auth(suite, skR, r_enc, *pkS, *rng, info);
               case Botan::HPKE::Mode::AuthPSK:
                  return Botan::HPKE::Recipient_Context::setup_auth_psk(suite, skR, r_enc, *pkS, *rng, *psk, info);
            }
            throw Test_Error("Invalid HPKE mode in test data");
         };

         // Full recipient-side KAT through the public API
         auto recipient = setup_recipient(enc);

         result.test_is_true("mode round trips", recipient.mode() == mode);

         if(vars.has_key("Ct")) {
            const auto aads = vars.get_req_bin_list("Aad");
            const auto pts = vars.get_req_bin_list("Pt");
            const auto cts = vars.get_req_bin_list("Ct");
            if(!result.test_sz_eq("consistent Aad list", aads.size(), cts.size()) ||
               !result.test_sz_eq("consistent Pt list", pts.size(), cts.size())) {
               return result;
            }

            for(size_t i = 0; i != cts.size(); ++i) {
               result.test_bin_eq("open", recipient.open(aads[i], cts[i]), pts[i]);
            }
            result.test_sz_eq("sequence advanced", static_cast<size_t>(recipient.next_sequence()), cts.size());
         }

         if(vars.has_key("SkipCt")) {
            const uint64_t skip_seq = vars.get_req_sz("SkipSeq");
            const uint64_t seq_before = recipient.next_sequence();
            const auto pt =
               recipient.open_at_sequence(skip_seq, vars.get_req_bin("SkipAad"), vars.get_req_bin("SkipCt"));
            result.test_bin_eq("open_at_sequence", pt, vars.get_req_bin("SkipPt"));
            result.test_u64_eq("open_at_sequence does not consume", recipient.next_sequence(), seq_before);
         }

         if(vars.has_key("ExportEmptyCtxVal")) {
            const auto value = vars.get_req_bin("ExportEmptyCtxVal");
            result.test_bin_eq("export_secret with empty context", recipient.export_secret({}, value.size()), value);
         }

         if(vars.has_key("ExportVal")) {
            const auto contexts = vars.get_req_bin_list("ExportCtx");
            const auto values = vars.get_req_bin_list("ExportVal");
            if(!result.test_sz_eq("consistent export lists", contexts.size(), values.size())) {
               return result;
            }

            for(size_t i = 0; i != values.size(); ++i) {
               result.test_bin_eq("export_secret", recipient.export_secret(contexts[i], values[i].size()), values[i]);
            }
         }

         if(suite.is_export_only()) {
            result.test_throws("open on export-only suite",
                               [&] { recipient.open(to_bytes("aad"), to_bytes("ctext")); });
         }

         // Round trip through the public API with a fresh encapsulation
         auto sender = [&]() -> Botan::HPKE::Sender_Context {
            switch(mode) {
               case Botan::HPKE::Mode::Base:
                  return Botan::HPKE::Sender_Context::setup_base(suite, pkR, *rng, info);
               case Botan::HPKE::Mode::PSK:
                  return Botan::HPKE::Sender_Context::setup_psk(suite, pkR, *rng, *psk, info);
               case Botan::HPKE::Mode::Auth:
                  return Botan::HPKE::Sender_Context::setup_auth(suite, pkR, *skS, *rng, info);
               case Botan::HPKE::Mode::AuthPSK:
                  return Botan::HPKE::Sender_Context::setup_auth_psk(suite, pkR, *skS, *rng, *psk, info);
            }
            throw Test_Error("Invalid HPKE mode in test data");
         }();

         result.test_sz_eq("enc length", sender.encapsulated_key().size(), kem.encapsulation_length());

         auto rt_recipient = setup_recipient(sender.encapsulated_key());

         if(!suite.is_export_only()) {
            const auto msg1 = to_bytes("first message");
            const auto msg2 = to_bytes("second message");
            const auto aad = to_bytes("round trip aad");

            const auto ct1 = sender.seal(aad, msg1);
            result.test_sz_eq("ciphertext length", ct1.size(), msg1.size() + suite.ciphertext_overhead());
            const auto ct2 = sender.seal({}, msg2);

            result.test_bin_eq("round trip 1", rt_recipient.open(aad, ct1), msg1);
            result.test_bin_eq("round trip 2", rt_recipient.open({}, ct2), msg2);
         }

         const auto export_ctx = to_bytes("test export");
         result.test_bin_eq(
            "exporter secrets agree", sender.export_secret(export_ctx, 42), rt_recipient.export_secret(export_ctx, 42));

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "hpke_kat", HPKE_KAT_Tests);

Test::Result test_hpke_psk_checks() {
   Test::Result result("HPKE PSK input checks");

   const std::vector<uint8_t> psk32(32, 0xAB);
   const std::vector<uint8_t> short_psk(16, 0xAB);
   const auto psk_id = to_bytes("psk identity");

   result.test_no_throw("valid PSK accepted", [&] { const Botan::HPKE::PSK psk(psk32, psk_id); });

   result.test_throws("empty PSK identity rejected", [&] { const Botan::HPKE::PSK psk(psk32, {}); });

   result.test_throws("empty PSK rejected", [&] { const Botan::HPKE::PSK psk({}, psk_id); });

   result.test_throws("short PSK rejected", [&] { const Botan::HPKE::PSK psk(short_psk, psk_id); });

   return result;
}

Test::Result test_hpke_suite_ids() {
   Test::Result result("HPKE suite identifiers");

   using namespace Botan::HPKE;

   const Suite grease(0x4A4A, 0x4A4A, 0x4A4A);
   result.test_is_false("GREASE suite is unknown", grease.is_known());
   result.test_is_false("GREASE suite is unavailable", grease.is_available());
   result.test_is_true("GREASE suite has no name", !grease.to_string().has_value());
   result.test_throws("no sizes for unknown KEM", [&] { grease.kem().encapsulation_length(); });

   const KEM_Id x25519(KEM_Code::DHKEM_X25519);
   result.test_sz_eq("DHKEM(X25519) Nenc", x25519.encapsulation_length(), 32);
   result.test_is_true("DHKEM supports auth modes", x25519.supports_auth_modes());

   const Suite suite(KEM_Code::DHKEM_X25519, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
   result.test_str_eq(
      "suite name", suite.to_string().value_or("?"), "DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/AES-128-GCM");

   result.test_is_true("export-only suite",
                       Suite(KEM_Code::DHKEM_X25519, KDF_Code::HKDF_SHA256, AEAD_Code::ExportOnly).is_export_only());

   return result;
}

Test::Result test_hpke_key_type_checks() {
   Test::Result result("HPKE key/suite consistency");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_key_type_checks");

   #if defined(BOTAN_HAS_X25519)
   const KEM_Id p256(KEM_Code::DHKEM_P256);
   const KEM_Id x25519(KEM_Code::DHKEM_X25519);

   if(p256.is_available() && x25519.is_available()) {
      // Adopting a key of the wrong type is rejected
      result.test_throws("from_key rejects mismatched key type",
                         [&] { Private_Key::from_key(p256, std::make_unique<Botan::X25519_PrivateKey>(*rng)); });

      result.test_no_throw("from_key accepts matching key type",
                           [&] { Private_Key::from_key(x25519, std::make_unique<Botan::X25519_PrivateKey>(*rng)); });

      // Using a key with a suite for a different KEM is rejected
      const Suite p256_suite(KEM_Code::DHKEM_P256, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      const auto x_key = Private_Key::generate(x25519, *rng);

      result.test_throws("setup rejects key for wrong KEM",
                         [&] { Sender_Context::setup_base(p256_suite, x_key.public_key(), *rng); });
   }
   #endif

   return result;
}

Test::Result test_hpke_derive_ikm_bounds() {
   Test::Result result("HPKE DeriveKeyPair ikm length");

   using namespace Botan::HPKE;

   const KEM_Id p521(KEM_Code::DHKEM_P521);
   if(p521.is_available()) {
      // MLS (RFC 9420) derives P-521 key pairs from 64 byte node secrets
      const std::vector<uint8_t> ikm64(64, 0x21);
      const auto d1 = Private_Key::derive(p521, ikm64);
      const auto d2 = Private_Key::derive(p521, ikm64);
      result.test_is_true("P-521 derive from 64 bytes is deterministic", d1.public_key() == d2.public_key());
      result.test_sz_eq("P-521 Nsk", d1.serialize().size(), 66);

      result.test_throws("P-521 derive rejects 63 bytes",
                         [&] { Private_Key::derive(p521, std::vector<uint8_t>(63, 0x21)); });
   }

   const KEM_Id p256(KEM_Code::DHKEM_P256);
   if(p256.is_available()) {
      result.test_no_throw("P-256 derive accepts Nsk bytes",
                           [&] { Private_Key::derive(p256, std::vector<uint8_t>(32, 0x21)); });
      result.test_throws("P-256 derive rejects short ikm",
                         [&] { Private_Key::derive(p256, std::vector<uint8_t>(31, 0x21)); });
   }

   #if defined(BOTAN_HAS_X448)
   const KEM_Id x448(KEM_Code::DHKEM_X448);
   if(x448.is_available()) {
      result.test_no_throw("X448 derive accepts Nsk bytes",
                           [&] { Private_Key::derive(x448, std::vector<uint8_t>(56, 0x21)); });
      result.test_throws("X448 derive rejects short ikm",
                         [&] { Private_Key::derive(x448, std::vector<uint8_t>(55, 0x21)); });
   }
   #endif

   return result;
}

Test::Result test_hpke_context_behavior() {
   Test::Result result("HPKE context behavior");

   using namespace Botan::HPKE;

   const Suite suite(KEM_Code::DHKEM_X25519, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
   if(!suite.is_available()) {
      result.note_missing("DHKEM(X25519) suite");
      return result;
   }

   auto rng = Test::new_rng("hpke_context_behavior");

   const auto skR = Private_Key::generate(suite.kem(), *rng);
   const auto info = to_bytes("test info");
   const auto aad = to_bytes("test aad");
   const auto msg = to_bytes("attack at dawn");

   auto sender = Sender_Context::setup_base(suite, skR.public_key(), *rng, info);
   auto ct0 = sender.seal(aad, msg);
   auto ct1 = sender.seal(aad, msg);
   result.test_is_true("nonce varies with sequence", ct0 != ct1);

   auto recipient = Recipient_Context::setup_base(suite, skR, sender.encapsulated_key(), *rng, info);

   // A failed open must not consume the sequence number
   auto tampered = ct0;
   tampered[0] ^= 0x01;
   result.test_throws("tampered ciphertext rejected", [&] { recipient.open(aad, tampered); });
   result.test_u64_eq("failed open does not consume seq", recipient.next_sequence(), 0);

   result.test_throws("wrong aad rejected", [&] { recipient.open(to_bytes("wrong"), ct0); });

   result.test_bin_eq("open succeeds after failures", recipient.open(aad, ct0), msg);

   // Out-of-order/stateless processing via open_at_sequence, as needed
   // for an ECH server handling HelloRetryRequest statelessly
   auto recipient2 = Recipient_Context::setup_base(suite, skR, sender.encapsulated_key(), *rng, info);
   result.test_bin_eq("open_at_sequence(1)", recipient2.open_at_sequence(1, aad, ct1), msg);
   result.test_u64_eq("open_at_sequence leaves counter", recipient2.next_sequence(), 0);
   result.test_bin_eq("sequential open still works", recipient2.open(aad, ct0), msg);

   // Export length limit: at most 255 * Nh
   result.test_no_throw("maximum export length",
                        [&] { sender.export_secret(to_bytes("ctx"), 255 * suite.kdf().output_length()); });
   result.test_throws("oversize export rejected",
                      [&] { sender.export_secret(to_bytes("ctx"), 255 * suite.kdf().output_length() + 1); });

   // Export-only suites cannot seal
   const Suite eo_suite(KEM_Code::DHKEM_X25519, KDF_Code::HKDF_SHA256, AEAD_Code::ExportOnly);
   auto eo_sender = Sender_Context::setup_base(eo_suite, skR.public_key(), *rng, info);
   result.test_throws("export-only cannot seal", [&] { eo_sender.seal(aad, msg); });

   auto eo_recipient = Recipient_Context::setup_base(eo_suite, skR, eo_sender.encapsulated_key(), *rng, info);
   result.test_bin_eq("export-only exports agree",
                      eo_sender.export_secret(to_bytes("ctx"), 64),
                      eo_recipient.export_secret(to_bytes("ctx"), 64));

   return result;
}

Test::Result test_hpke_failed_open() {
   Test::Result result("HPKE failed open recovery");
   using namespace Botan::HPKE;
   auto rng = Test::new_rng("hpke_failed_open");
   const auto msg = to_bytes("message after a failed open");
   const auto aad = to_bytes("aad");

   for(auto aead : {AEAD_Code::AES_128_GCM, AEAD_Code::AES_256_GCM, AEAD_Code::ChaCha20Poly1305}) {
      const Suite suite(KEM_Code::DHKEM_X25519, KDF_Code::HKDF_SHA256, aead);
      if(!suite.is_available()) {
         continue;
      }
      const auto sk = Private_Key::generate(suite.kem(), *rng);
      auto sender = Sender_Context::setup_base(suite, sk.public_key(), *rng);
      auto recipient = Recipient_Context::setup_base(suite, sk, sender.encapsulated_key(), *rng);
      const auto ct = sender.seal(aad, msg);

      for(size_t len = 0; len < suite.aead().tag_length(); ++len) {
         const std::vector<uint8_t> truncated(len);
         result.test_throws<Botan::Invalid_Authentication_Tag>("truncated ciphertext",
                                                               [&] { recipient.open(aad, truncated); });
         result.test_throws<Botan::Invalid_Authentication_Tag>("truncated ciphertext at explicit sequence",
                                                               [&] { recipient.open_at_sequence(0, aad, truncated); });
         result.test_bin_eq("valid open after truncation", recipient.open_at_sequence(0, aad, ct), msg);
         result.test_u64_eq("failed and explicit opens preserve sequence", recipient.next_sequence(), 0);
      }
      auto tampered = ct;
      tampered.back() ^= 1;
      result.test_throws<Botan::Invalid_Authentication_Tag>("invalid tag", [&] { recipient.open(aad, tampered); });
      result.test_bin_eq("sequential open after failures", recipient.open(aad, ct), msg);
      result.test_u64_eq("successful open advances sequence", recipient.next_sequence(), 1);
   }
   return result;
}

Test::Result test_hpke_ec_key_encoding() {
   Test::Result result("HPKE imported EC key encoding");
   using namespace Botan::HPKE;
   auto rng = Test::new_rng("hpke_ec_key_encoding");
   const auto msg = to_bytes("uncompressed HPKE encoding");

   BOTAN_DIAGNOSTIC_PUSH
   BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS
   for(auto kem : {KEM_Code::DHKEM_P256, KEM_Code::DHKEM_P384, KEM_Code::DHKEM_P521}) {
      const Suite suite(kem, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      if(!suite.is_available()) {
         continue;
      }
      const auto generated = Private_Key::generate(kem, *rng);
      const auto canonical_pk = generated.public_key().serialize();
      for(auto format : {Botan::EC_Point_Format::Compressed, Botan::EC_Point_Format::Hybrid}) {
         auto underlying_pk = generated.underlying().public_key();
         dynamic_cast<Botan::ECDH_PublicKey&>(*underlying_pk).set_point_encoding(format);
         const auto pk = Public_Key::from_key(kem, std::move(underlying_pk));
         result.test_bin_eq("imported public key encoding", pk.serialize(), canonical_pk);

         auto underlying_sk = KEM_Ops::create(kem)->deserialize_private(generated.serialize());
         dynamic_cast<Botan::ECDH_PrivateKey&>(*underlying_sk).set_point_encoding(format);
         const auto sk = Private_Key::from_key(kem, std::move(underlying_sk));
         result.test_bin_eq("imported private key public encoding", sk.public_key().serialize(), canonical_pk);

         // Both roles use imported keys, including the sender identity in Auth.
         auto sender = Sender_Context::setup_auth(suite, pk, sk, *rng);
         auto recipient = Recipient_Context::setup_auth(suite, sk, sender.encapsulated_key(), pk, *rng);
         result.test_bin_eq("imported keys round trip", recipient.open({}, sender.seal({}, msg)), msg);
      }
   }
   BOTAN_DIAGNOSTIC_POP
   return result;
}

Test::Result test_hpke_ec_key_adoption() {
   Test::Result result("HPKE EC key adoption");

   #if defined(BOTAN_HAS_ECDSA)
   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_ec_key_adoption");
   const auto msg = to_bytes("adopted key");

   const std::vector<std::pair<KEM_Code, std::string>> kems = {
      {KEM_Code::DHKEM_P256, "secp256r1"},
      {KEM_Code::DHKEM_P384, "secp384r1"},
      {KEM_Code::DHKEM_P521, "secp521r1"},
   };

   for(const auto& kem_and_curve : kems) {
      // Not a structured binding: clang 14 cannot capture those in lambdas
      const KEM_Code kem_code = kem_and_curve.first;
      const std::string& curve = kem_and_curve.second;
      const Suite suite(kem_code, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      if(!suite.is_available()) {
         continue;
      }
      const auto group = Botan::EC_Group::from_name(curve);

      // Keys with the id-ecPublicKey OID, as in X.509 certificates and PKCS #8,
      // load as ECDSA keys; these are accepted and converted to ECDH
      const Botan::ECDSA_PrivateKey ecdsa(*rng, group);

      auto loaded_sk = Botan::PKCS8::load_key(Botan::PKCS8::BER_encode(ecdsa));
      result.test_str_eq("PKCS #8 key loads as ECDSA", loaded_sk->algo_name(), "ECDSA");
      const auto sk = Private_Key::from_key(kem_code, std::move(loaded_sk));
      result.test_str_eq("adopted private key is ECDH", sk.underlying().algo_name(), "ECDH");
      result.test_bin_eq("adopted private key scalar", sk.serialize(), ecdsa.raw_private_key_bits());

      auto loaded_pk = Botan::X509::load_key(ecdsa.subject_public_key());
      result.test_str_eq("SPKI loads as ECDSA", loaded_pk->algo_name(), "ECDSA");
      const auto pk = Public_Key::from_key(kem_code, std::move(loaded_pk));
      result.test_str_eq("adopted public key is ECDH", pk.underlying().algo_name(), "ECDH");
      result.test_is_true("adopted keys correspond", pk == sk.public_key());
      result.test_bin_eq("adopted public key matches DeserializePrivateKey",
                         pk.serialize(),
                         Private_Key::deserialize(kem_code, ecdsa.raw_private_key_bits()).public_key().serialize());

      auto sender = Sender_Context::setup_auth(suite, pk, sk, *rng);
      auto recipient = Recipient_Context::setup_auth(suite, sk, sender.encapsulated_key(), pk, *rng);
      result.test_bin_eq("adopted keys round trip", recipient.open({}, sender.seal({}, msg)), msg);

      // Keys on another curve are rejected, whether ECDH or ECDSA
      const auto* const other_curve = curve == "secp256r1" ? "secp384r1" : "secp256r1";
      if(Botan::EC_Group::supports_named_group(other_curve)) {
         const auto other_group = Botan::EC_Group::from_name(other_curve);
         result.test_throws<Botan::Invalid_Argument>("ECDSA private key on wrong curve rejected", [&] {
            Private_Key::from_key(kem_code, std::make_unique<Botan::ECDSA_PrivateKey>(*rng, other_group));
         });
         result.test_throws<Botan::Invalid_Argument>("ECDH private key on wrong curve rejected", [&] {
            Private_Key::from_key(kem_code, std::make_unique<Botan::ECDH_PrivateKey>(*rng, other_group));
         });
         result.test_throws<Botan::Invalid_Argument>("ECDSA public key on wrong curve rejected", [&] {
            Public_Key::from_key(kem_code, Botan::ECDSA_PrivateKey(*rng, other_group).public_key());
         });
      }

      #if defined(BOTAN_HAS_ECGDSA)
      // Other EC algorithms are not accepted, even on the right curve
      result.test_throws<Botan::Invalid_Argument>("ECGDSA private key rejected", [&] {
         Private_Key::from_key(kem_code, std::make_unique<Botan::ECGDSA_PrivateKey>(*rng, group));
      });
      result.test_throws<Botan::Invalid_Argument>("ECGDSA public key rejected", [&] {
         Public_Key::from_key(kem_code, Botan::ECGDSA_PrivateKey(*rng, group).public_key());
      });
      #endif
   }
   #endif

   return result;
}

Test::Result test_hpke_ecx_private_key_clamping() {
   Test::Result result("HPKE X25519/X448 private key clamping");

   using namespace Botan::HPKE;

   /*
   * RFC 9180 Section 7.1.2 requires SerializePrivateKey to clamp its output
   * and DeserializePrivateKey to clamp its input (RFC 7748 Section 5). The
   * unclamped values below are private keys as published in the RFC test
   * vectors, and the clamped values are those of erratum 7121.
   */
   #if defined(BOTAN_HAS_X25519)
   const KEM_Id x25519(KEM_Code::DHKEM_X25519);
   if(x25519.is_available()) {
      // RFC 9180 Appendix A.1.1 skEm, pkEm and ikmE
      const auto unclamped = Botan::hex_decode("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
      const auto clamped = Botan::hex_decode("50c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f776");
      const auto pk = Botan::hex_decode("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
      const auto ikm = Botan::hex_decode("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");

      const auto from_unclamped = Private_Key::deserialize(x25519, unclamped);
      result.test_bin_eq("X25519 deserialize clamps its input", from_unclamped.serialize(), clamped);
      result.test_bin_eq("X25519 public key of unclamped input", from_unclamped.public_key().serialize(), pk);

      const auto from_clamped = Private_Key::deserialize(x25519, clamped);
      result.test_bin_eq("X25519 clamped input is unchanged", from_clamped.serialize(), clamped);
      result.test_bin_eq("X25519 public key of clamped input", from_clamped.public_key().serialize(), pk);

      result.test_bin_eq(
         "X25519 derived key serializes clamped", Private_Key::derive(x25519, ikm).serialize(), clamped);

      // A key adopted from outside HPKE may hold an unclamped scalar
      const auto adopted = Private_Key::from_key(x25519, std::make_unique<Botan::X25519_PrivateKey>(unclamped));
      result.test_bin_eq("X25519 serialize clamps an adopted key", adopted.serialize(), clamped);
      result.test_bin_eq("X25519 public key of adopted key", adopted.public_key().serialize(), pk);
   }
   #endif

   #if defined(BOTAN_HAS_X448)
   const KEM_Id x448(KEM_Code::DHKEM_X448);
   if(x448.is_available()) {
      // The first DHKEM(X448) vector of the RFC 9180 test vector set: skRm, pkRm and ikmR
      const auto unclamped = Botan::hex_decode(
         "27a4354608f3bdd38f1f5af305f3e0682efe4e25808249d8fcb55927f6a9f446b8dc1d0a2c3b8cb133a5673b59a6d55ce754ec0c9a555401");
      const auto clamped = Botan::hex_decode(
         "24a4354608f3bdd38f1f5af305f3e0682efe4e25808249d8fcb55927f6a9f446b8dc1d0a2c3b8cb133a5673b59a6d55ce754ec0c9a555481");
      const auto pk = Botan::hex_decode(
         "145d083ea7a6379dbb32dcbd8aff4c206ea5d069b75e96c6dd2a3e38f441471ac97adca641fdad66685a96f32b7c3e064635fab3cc89234e");
      const auto ikm = Botan::hex_decode(
         "d45d1652df74920abf94a2883c83050f502ff512ffb56f07b6d833ec8dda74b6a1c1cc4d42a22641c0963d3c21ed8261f344dc9e0501a81c");

      const auto from_unclamped = Private_Key::deserialize(x448, unclamped);
      result.test_bin_eq("X448 deserialize clamps its input", from_unclamped.serialize(), clamped);
      result.test_bin_eq("X448 public key of unclamped input", from_unclamped.public_key().serialize(), pk);

      const auto from_clamped = Private_Key::deserialize(x448, clamped);
      result.test_bin_eq("X448 clamped input is unchanged", from_clamped.serialize(), clamped);
      result.test_bin_eq("X448 public key of clamped input", from_clamped.public_key().serialize(), pk);

      result.test_bin_eq("X448 derived key serializes clamped", Private_Key::derive(x448, ikm).serialize(), clamped);

      const auto adopted = Private_Key::from_key(x448, std::make_unique<Botan::X448_PrivateKey>(unclamped));
      result.test_bin_eq("X448 serialize clamps an adopted key", adopted.serialize(), clamped);
      result.test_bin_eq("X448 public key of adopted key", adopted.public_key().serialize(), pk);
   }
   #endif

   return result;
}

Test::Result test_hpke_low_order_points() {
   Test::Result result("HPKE low order X25519/X448 points");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_low_order_points");

   for(auto kem_code : {KEM_Code::DHKEM_X25519, KEM_Code::DHKEM_X448}) {
      const Suite suite(kem_code, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      if(!suite.is_available()) {
         continue;
      }

      const auto sk = Private_Key::generate(suite.kem(), *rng);

      // u = 0 and u = 1 are low order points on both curves, for which the
      // all-zero shared secret must be rejected (RFC 9180 Section 7.1.4)
      for(const uint8_t u : {uint8_t(0), uint8_t(1)}) {
         std::vector<uint8_t> point(suite.kem().public_key_length());
         point[0] = u;

         // The encoding is not malformed, so deserialization succeeds ...
         const auto pk = Public_Key::deserialize(suite.kem(), point);

         // ... but every use of the point is rejected
         result.test_throws<Botan::Invalid_Argument>("sender rejects low order recipient key",
                                                     [&] { Sender_Context::setup_base(suite, pk, *rng); });

         result.test_throws<Botan::Invalid_Argument>("recipient rejects low order enc",
                                                     [&] { Recipient_Context::setup_base(suite, sk, point, *rng); });

         auto sender = Sender_Context::setup_auth(suite, sk.public_key(), sk, *rng);
         result.test_throws<Botan::Invalid_Argument>("recipient rejects low order sender key", [&] {
            Recipient_Context::setup_auth(suite, sk, sender.encapsulated_key(), pk, *rng);
         });
      }
   }

   return result;
}

BOTAN_REGISTER_TEST_FN("pubkey",
                       "hpke",
                       test_hpke_psk_checks,
                       test_hpke_suite_ids,
                       test_hpke_key_type_checks,
                       test_hpke_derive_ikm_bounds,
                       test_hpke_context_behavior,
                       test_hpke_failed_open,
                       test_hpke_ec_key_encoding,
                       test_hpke_ec_key_adoption,
                       test_hpke_ecx_private_key_clamping,
                       test_hpke_low_order_points);

}  // namespace

#endif

}  // namespace Botan_Tests
