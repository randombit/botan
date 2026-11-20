/*
 * (C) 2026 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#if defined(BOTAN_HAS_HPKE_PQ)
   #include "test_rng.h"

   #include <botan/data_src.h>
   #include <botan/ec_apoint.h>
   #include <botan/ec_group.h>
   #include <botan/exceptn.h>
   #include <botan/hex.h>
   #include <botan/hpke.h>
   #include <botan/ml_kem.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs8.h>
   #include <botan/rng.h>
   #include <botan/x509_key.h>
   #include <botan/internal/hpke_kem.h>

   #if defined(BOTAN_HAS_X25519)
      #include <botan/x25519.h>
   #endif
   #include <algorithm>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HPKE_PQ)

namespace {

std::vector<uint8_t> pq_to_bytes(std::string_view s) {
   return std::vector<uint8_t>(s.begin(), s.end());
}

std::string pq_kem_name(Botan::HPKE::KEM_Id kem) {
   return kem.to_string().value_or("unknown");
}

/*
* An RNG which first produces the given bytes, and then falls back to the test
* RNG. The KEMs of draft-ietf-hpke-pq take their randomness in the order that
* the EncapsDerand function of the specification does, so this allows checking
* the encapsulations of the test vectors.
*/
Fixed_Output_RNG derand_rng(std::span<const uint8_t> randomness, Botan::RandomNumberGenerator& fallback) {
   Fixed_Output_RNG rng(fallback);
   rng.add_entropy(randomness);
   return rng;
}

const std::vector<Botan::HPKE::KEM_Code>& all_pq_kems() {
   using Botan::HPKE::KEM_Code;
   static const std::vector<KEM_Code> kems = {KEM_Code::ML_KEM_512,
                                              KEM_Code::ML_KEM_768,
                                              KEM_Code::ML_KEM_1024,
                                              KEM_Code::MLKEM768_P256,
                                              KEM_Code::MLKEM1024_P384,
                                              KEM_Code::MLKEM768_X25519};
   return kems;
}

/// The length of the serialized group element at the end of the public
/// key and encapsulation of a hybrid KEM
size_t hybrid_group_element_bytes(Botan::HPKE::KEM_Id kem) {
   using Botan::HPKE::KEM_Code;
   switch(kem.code()) {
      case KEM_Code::MLKEM768_P256:
         return 65;
      case KEM_Code::MLKEM1024_P384:
         return 97;
      case KEM_Code::MLKEM768_X25519:
         return 32;
      default:
         throw Test_Error("Not a hybrid KEM");
   }
}

class HPKE_PQ_KAT_Tests final : public Text_Based_Test {
   public:
      HPKE_PQ_KAT_Tests() :
            Text_Based_Test("pubkey/hpke_pq.vec",
                            "Kem,IkmR,SkRm,PkRm,IkmE,Enc,SharedSecret",
                            "Kdf,Aead,Info,Aad,Pt,Ct,ExportCtx,ExportVal") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         using namespace Botan::HPKE;

         Test::Result result("HPKE PQ KAT " + header);

         const KEM_Id kem(static_cast<uint16_t>(vars.get_req_sz("Kem")));

         if(!kem.is_available()) {
            result.note_missing("HPKE KEM " + pq_kem_name(kem));
            return result;
         }

         auto rng = Test::new_rng("hpke_pq_kat");

         const auto sk_rm = vars.get_req_bin("SkRm");
         const auto pk_rm = vars.get_req_bin("PkRm");
         const auto ikm_e = vars.get_req_bin("IkmE");
         const auto enc = vars.get_req_bin("Enc");
         const auto shared_secret = vars.get_req_bin("SharedSecret");

         // DeriveKeyPair and key serialization
         const auto skR = Private_Key::derive(kem, vars.get_req_bin("IkmR"));
         result.test_bin_eq("DeriveKeyPair skR", skR.serialize(), sk_rm);
         result.test_bin_eq("DeriveKeyPair pkR", skR.public_key().serialize(), pk_rm);

         const auto skR2 = Private_Key::deserialize(kem, sk_rm);
         result.test_bin_eq("DeserializePrivateKey", skR2.public_key().serialize(), pk_rm);
         result.test_bin_eq("SerializePrivateKey", skR2.serialize(), sk_rm);

         const auto pkR = Public_Key::deserialize(kem, pk_rm);
         result.test_bin_eq("SerializePublicKey", pkR.serialize(), pk_rm);
         result.test_is_true("public key equality", pkR == skR.public_key());

         // Encap, using the randomness of the test vector, and Decap
         const auto ops = KEM_Ops::create(kem);

         auto kem_rng = derand_rng(ikm_e, *rng);
         const auto kat_encap = ops->encap(pkR.underlying(), kem_rng);
         result.test_is_true("Encap used all of the randomness", kem_rng.empty());
         result.test_bin_eq("Encap enc", kat_encap.enc, enc);
         result.test_bin_eq("Encap shared_secret", kat_encap.shared_secret, shared_secret);

         result.test_bin_eq("Decap shared_secret", ops->decap(enc, skR.underlying(), *rng), shared_secret);

         if(!vars.has_key("Kdf")) {
            // The suite uses a KDF which is not implemented
            return result;
         }

         const Suite suite(
            kem, static_cast<uint16_t>(vars.get_req_sz("Kdf")), static_cast<uint16_t>(vars.get_req_sz("Aead")));

         if(!suite.is_available()) {
            result.note_missing("HPKE suite " + suite.to_string().value_or("unknown"));
            return result;
         }

         const auto info = vars.get_req_bin("Info");
         const auto aads = vars.get_req_bin_list("Aad");
         const auto pts = vars.get_req_bin_list("Pt");
         const auto cts = vars.get_req_bin_list("Ct");
         const auto export_contexts = vars.get_req_bin_list("ExportCtx");
         const auto export_values = vars.get_req_bin_list("ExportVal");

         if(!result.test_sz_eq("consistent Aad list", aads.size(), cts.size()) ||
            !result.test_sz_eq("consistent Pt list", pts.size(), cts.size()) ||
            !result.test_sz_eq("consistent export lists", export_contexts.size(), export_values.size())) {
            return result;
         }

         // The recipient
         auto recipient = Recipient_Context::setup_base(suite, skR, enc, *rng, info);

         for(size_t i = 0; i != cts.size(); ++i) {
            result.test_bin_eq("open", recipient.open(aads[i], cts[i]), pts[i]);
         }
         result.test_sz_eq("recipient sequence advanced", static_cast<size_t>(recipient.next_sequence()), cts.size());

         for(size_t i = 0; i != export_values.size(); ++i) {
            result.test_bin_eq("recipient export_secret",
                               recipient.export_secret(export_contexts[i], export_values[i].size()),
                               export_values[i]);
         }

         // The sender, which with the randomness of the test vector must
         // produce exactly the encapsulation and ciphertexts of the vector
         auto sender_rng = derand_rng(ikm_e, *rng);
         auto sender = Sender_Context::setup_base(suite, pkR, sender_rng, info);
         result.test_bin_eq("sender enc", sender.encapsulated_key(), enc);

         for(size_t i = 0; i != cts.size(); ++i) {
            result.test_bin_eq("seal", sender.seal(aads[i], pts[i]), cts[i]);
         }

         for(size_t i = 0; i != export_values.size(); ++i) {
            result.test_bin_eq("sender export_secret",
                               sender.export_secret(export_contexts[i], export_values[i].size()),
                               export_values[i]);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "hpke_pq_kat", HPKE_PQ_KAT_Tests);

class HPKE_Hybrid_KEM_KAT_Tests final : public Text_Based_Test {
   public:
      HPKE_Hybrid_KEM_KAT_Tests() :
            Text_Based_Test("pubkey/hpke_hybrid_kem.vec",
                            "Kem,Seed,Randomness,EncapsulationKey,Ciphertext,SharedSecret") {}

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         using namespace Botan::HPKE;

         Test::Result result("HPKE hybrid KEM KAT " + header);

         const KEM_Id kem(static_cast<uint16_t>(vars.get_req_sz("Kem")));

         if(!kem.is_available()) {
            result.note_missing("HPKE KEM " + pq_kem_name(kem));
            return result;
         }

         auto rng = Test::new_rng("hpke_hybrid_kem_kat");

         const auto seed = vars.get_req_bin("Seed");
         const auto ek = vars.get_req_bin("EncapsulationKey");
         const auto ct = vars.get_req_bin("Ciphertext");
         const auto shared_secret = vars.get_req_bin("SharedSecret");

         // The decapsulation key is the seed
         const auto sk = Private_Key::deserialize(kem, seed);
         result.test_bin_eq("decapsulation key", sk.serialize(), seed);
         result.test_bin_eq("encapsulation key", sk.public_key().serialize(), ek);

         const auto pk = Public_Key::deserialize(kem, ek);
         result.test_bin_eq("encapsulation key round trip", pk.serialize(), ek);

         const auto ops = KEM_Ops::create(kem);

         auto kem_rng = derand_rng(vars.get_req_bin("Randomness"), *rng);
         const auto encap = ops->encap(pk.underlying(), kem_rng);
         result.test_is_true("Encaps used all of the randomness", kem_rng.empty());
         result.test_bin_eq("Encaps ciphertext", encap.enc, ct);
         result.test_bin_eq("Encaps shared secret", encap.shared_secret, shared_secret);

         result.test_bin_eq("Decaps shared secret", ops->decap(ct, sk.underlying(), *rng), shared_secret);

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "hpke_hybrid_kem_kat", HPKE_Hybrid_KEM_KAT_Tests);

Test::Result test_hpke_pq_kem_ids() {
   Test::Result result("HPKE PQ KEM identifiers");

   using namespace Botan::HPKE;

   struct Expected {
         KEM_Code code;
         uint16_t wire_code;
         std::string name;
         size_t nenc;
         size_t npk;
         size_t nsk;
         bool is_ml_kem;
   };

   // See draft-ietf-hpke-pq-05 Sections 8.1 and 8.2
   const std::vector<Expected> expected = {
      {KEM_Code::ML_KEM_512, 0x0040, "ML-KEM-512", 768, 800, 64, true},
      {KEM_Code::ML_KEM_768, 0x0041, "ML-KEM-768", 1088, 1184, 64, true},
      {KEM_Code::ML_KEM_1024, 0x0042, "ML-KEM-1024", 1568, 1568, 64, true},
      {KEM_Code::MLKEM768_P256, 0x0050, "MLKEM768-P256", 1153, 1249, 32, false},
      {KEM_Code::MLKEM1024_P384, 0x0051, "MLKEM1024-P384", 1665, 1665, 32, false},
      {KEM_Code::MLKEM768_X25519, 0x647A, "MLKEM768-X25519", 1120, 1216, 32, false},
   };

   result.test_sz_eq("all PQ KEMs are covered", expected.size(), all_pq_kems().size());

   for(const auto& e : expected) {
      const KEM_Id kem(e.code);
      result.test_u16_eq("wire code", kem.wire_code(), e.wire_code);
      result.test_is_true("known from the wire", KEM_Id(e.wire_code).is_known());
      result.test_is_true("same KEM from the wire", KEM_Id(e.wire_code) == kem);
      result.test_str_eq("name", kem.to_string().value_or("?"), e.name);
      result.test_sz_eq("Nsecret", kem.shared_secret_length(), 32);
      result.test_sz_eq("Nenc", kem.encapsulation_length(), e.nenc);
      result.test_sz_eq("Npk", kem.public_key_length(), e.npk);
      result.test_sz_eq("Nsk", kem.private_key_length(), e.nsk);
      result.test_bool_eq("is_ml_kem", kem.is_ml_kem(), e.is_ml_kem);
      result.test_bool_eq("is_pq_hybrid", kem.is_pq_hybrid(), !e.is_ml_kem);
      result.test_is_false("not a DHKEM", kem.is_dhkem());
      result.test_is_false("no auth modes", kem.supports_auth_modes());
   }

   const KEM_Id x25519(KEM_Code::DHKEM_X25519);
   result.test_is_false("DHKEM is not ML-KEM", x25519.is_ml_kem());
   result.test_is_false("DHKEM is not a PQ hybrid", x25519.is_pq_hybrid());

   return result;
}

Test::Result test_hpke_pq_round_trip() {
   Test::Result result("HPKE PQ round trip");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_pq_round_trip");

   const auto info = pq_to_bytes("hpke pq info");
   const auto aad = pq_to_bytes("hpke pq aad");
   const auto msg = pq_to_bytes("a message for the post-quantum era");
   const auto export_ctx = pq_to_bytes("hpke pq export");
   const PSK psk(std::vector<uint8_t>(32, 0x5A), pq_to_bytes("psk identity"));

   for(const auto kem_code : all_pq_kems()) {
      const Suite suite(kem_code, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      if(!suite.is_available()) {
         result.test_note("Skipping unavailable KEM " + pq_kem_name(suite.kem()));
         continue;
      }

      const auto kem = suite.kem();
      const auto skR = Private_Key::generate(kem, *rng);
      const auto pkR = skR.public_key();

      // Base mode
      {
         auto sender = Sender_Context::setup_base(suite, pkR, *rng, info);
         const auto& enc = sender.encapsulated_key();
         result.test_sz_eq("Nenc", enc.size(), kem.encapsulation_length());

         auto recipient = Recipient_Context::setup_base(suite, skR, enc, *rng, info);

         const auto ct1 = sender.seal(aad, msg);
         const auto ct2 = sender.seal({}, msg);
         result.test_bin_eq("base round trip 1", recipient.open(aad, ct1), msg);
         result.test_bin_eq("base round trip 2", recipient.open({}, ct2), msg);
         result.test_bin_eq(
            "base exporter secrets", sender.export_secret(export_ctx, 48), recipient.export_secret(export_ctx, 48));

         // Each encapsulation is distinct
         const auto sender2 = Sender_Context::setup_base(suite, pkR, *rng, info);
         result.test_bin_ne("fresh encapsulation", sender2.encapsulated_key(), enc);

         /*
         * A modified ML-KEM ciphertext is rejected implicitly: decapsulation
         * succeeds, resulting in an unrelated shared secret. The same is so
         * for an encapsulation to some other key.
         */
         auto modified_enc = enc;
         modified_enc[0] ^= 0x01;
         auto modified_recipient = Recipient_Context::setup_base(suite, skR, modified_enc, *rng, info);
         result.test_throws<Botan::Invalid_Authentication_Tag>("modified encapsulation fails to open",
                                                               [&] { modified_recipient.open(aad, ct1); });
         result.test_bin_ne("modified encapsulation changes the exporter secret",
                            modified_recipient.export_secret(export_ctx, 32),
                            sender.export_secret(export_ctx, 32));

         const auto other_sk = Private_Key::generate(kem, *rng);
         auto other_recipient = Recipient_Context::setup_base(suite, other_sk, enc, *rng, info);
         result.test_throws<Botan::Invalid_Authentication_Tag>("wrong recipient key fails to open",
                                                               [&] { other_recipient.open(aad, ct1); });

         auto wrong_info_recipient = Recipient_Context::setup_base(suite, skR, enc, *rng, aad);
         result.test_throws<Botan::Invalid_Authentication_Tag>("wrong info fails to open",
                                                               [&] { wrong_info_recipient.open(aad, ct1); });
      }

      // PSK mode, which is the one authenticated mode available with these KEMs
      {
         auto sender = Sender_Context::setup_psk(suite, pkR, *rng, psk, info);
         result.test_is_true("PSK mode", sender.mode() == Mode::PSK);
         const auto& enc = sender.encapsulated_key();

         auto recipient = Recipient_Context::setup_psk(suite, skR, enc, *rng, psk, info);
         const auto ct = sender.seal(aad, msg);
         result.test_bin_eq("PSK round trip", recipient.open(aad, ct), msg);
         result.test_bin_eq(
            "PSK exporter secrets", sender.export_secret(export_ctx, 32), recipient.export_secret(export_ctx, 32));

         const PSK other_psk(std::vector<uint8_t>(32, 0xA5), pq_to_bytes("psk identity"));
         auto wrong_psk_recipient = Recipient_Context::setup_psk(suite, skR, enc, *rng, other_psk, info);
         result.test_throws<Botan::Invalid_Authentication_Tag>("wrong PSK fails to open",
                                                               [&] { wrong_psk_recipient.open(aad, ct); });

         auto base_recipient = Recipient_Context::setup_base(suite, skR, enc, *rng, info);
         result.test_throws<Botan::Invalid_Authentication_Tag>("wrong mode fails to open",
                                                               [&] { base_recipient.open(aad, ct); });
      }

      // An export-only suite
      {
         const Suite export_only(kem_code, KDF_Code::HKDF_SHA256, AEAD_Code::ExportOnly);
         auto sender = Sender_Context::setup_base(export_only, pkR, *rng, info);
         const auto recipient = Recipient_Context::setup_base(export_only, skR, sender.encapsulated_key(), *rng, info);
         result.test_bin_eq("export-only exporter secrets",
                            sender.export_secret(export_ctx, 32),
                            recipient.export_secret(export_ctx, 32));
         result.test_throws<Botan::Invalid_State>("export-only suite cannot seal", [&] { sender.seal(aad, msg); });
      }

      // See draft-ietf-hpke-pq-05 Section 7.2
      {
         const auto skS = Private_Key::generate(kem, *rng);
         const auto pkS = skS.public_key();

         const auto sender = Sender_Context::setup_base(suite, pkR, *rng, info);
         const auto& enc = sender.encapsulated_key();

         result.test_throws<Botan::Invalid_Argument>("sender Auth mode rejected",
                                                     [&] { Sender_Context::setup_auth(suite, pkR, skS, *rng, info); });
         result.test_throws<Botan::Invalid_Argument>(
            "sender AuthPSK mode rejected", [&] { Sender_Context::setup_auth_psk(suite, pkR, skS, *rng, psk, info); });
         result.test_throws<Botan::Invalid_Argument>(
            "recipient Auth mode rejected", [&] { Recipient_Context::setup_auth(suite, skR, enc, pkS, *rng, info); });
         result.test_throws<Botan::Invalid_Argument>("recipient AuthPSK mode rejected", [&] {
            Recipient_Context::setup_auth_psk(suite, skR, enc, pkS, *rng, psk, info);
         });
      }
   }

   return result;
}

Test::Result test_hpke_pq_key_encoding() {
   Test::Result result("HPKE PQ key encoding");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_pq_key_encoding");

   std::vector<Botan::secure_vector<uint8_t>> derived_keys;

   for(const auto kem_code : all_pq_kems()) {
      const Suite suite(kem_code, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      if(!suite.is_available()) {
         result.test_note("Skipping unavailable KEM " + pq_kem_name(suite.kem()));
         continue;
      }

      const auto kem = suite.kem();
      const size_t nsk = kem.private_key_length();
      const size_t npk = kem.public_key_length();
      const size_t nenc = kem.encapsulation_length();

      const auto sk = Private_Key::generate(kem, *rng);
      const auto sk_bytes = sk.serialize();
      const auto pk_bytes = sk.public_key().serialize();
      result.test_sz_eq("Nsk", sk_bytes.size(), nsk);
      result.test_sz_eq("Npk", pk_bytes.size(), npk);

      const auto sk2 = Private_Key::deserialize(kem, sk_bytes);
      result.test_bin_eq("private key round trip", sk2.serialize(), sk_bytes);
      result.test_bin_eq("public key of deserialized private key", sk2.public_key().serialize(), pk_bytes);
      result.test_bin_eq("public key round trip", Public_Key::deserialize(kem, pk_bytes).serialize(), pk_bytes);

      // DeriveKeyPair
      const std::vector<uint8_t> ikm(32, 0x2A);
      const auto derived = Private_Key::derive(kem, ikm);
      result.test_bin_eq(
         "DeriveKeyPair is deterministic", Private_Key::derive(kem, ikm).serialize(), derived.serialize());
      result.test_sz_eq("derived Nsk", derived.serialize().size(), nsk);
      result.test_throws<Botan::Invalid_Argument>("short ikm rejected",
                                                  [&] { Private_Key::derive(kem, std::span(ikm).first(31)); });
      result.test_no_throw("long ikm accepted", [&] { Private_Key::derive(kem, std::vector<uint8_t>(200, 0x2A)); });

      // The derived key depends on the KEM, even where Nsk is the same
      for(const auto& other : derived_keys) {
         if(other.size() == nsk) {
            result.test_bin_ne("derived key is bound to the KEM", derived.serialize(), other);
         }
      }
      derived_keys.push_back(derived.serialize());

      // Encodings of the wrong length
      for(const size_t bad_len : {size_t(0), nsk - 1, nsk + 1, size_t(32), size_t(64)}) {
         if(bad_len != nsk) {
            result.test_throws<Botan::Decoding_Error>("private key of the wrong length rejected", [&] {
               Private_Key::deserialize(kem, std::vector<uint8_t>(bad_len, 0x01));
            });
         }
      }

      for(const size_t bad_len : {size_t(0), npk - 1, npk + 1}) {
         std::vector<uint8_t> bad(pk_bytes.begin(), pk_bytes.begin() + std::min(bad_len, npk));
         bad.resize(bad_len);
         result.test_throws<Botan::Decoding_Error>("public key of the wrong length rejected",
                                                   [&] { Public_Key::deserialize(kem, bad); });
      }

      const auto sender = Sender_Context::setup_base(suite, sk.public_key(), *rng);
      const auto& enc = sender.encapsulated_key();
      for(const size_t bad_len : {size_t(0), nenc - 1, nenc + 1}) {
         std::vector<uint8_t> bad(enc.begin(), enc.begin() + std::min(bad_len, nenc));
         bad.resize(bad_len);
         result.test_throws<Botan::Decoding_Error>("encapsulation of the wrong length rejected",
                                                   [&] { Recipient_Context::setup_base(suite, sk, bad, *rng); });
      }

      /*
      * The encapsulation key check of FIPS 203 Section 7.2: each 12 bit
      * coefficient of the encoded key must be less than q = 3329. The first
      * coefficient is the first byte, plus the low 4 bits of the second.
      */
      auto bad_ml_kem_ek = pk_bytes;
      bad_ml_kem_ek[0] = 0xFF;
      bad_ml_kem_ek[1] |= 0x0F;
      result.test_throws<Botan::Decoding_Error>("ML-KEM encapsulation key check",
                                                [&] { Public_Key::deserialize(kem, bad_ml_kem_ek); });
   }

   return result;
}

Test::Result test_hpke_ml_kem_key_adoption() {
   Test::Result result("HPKE ML-KEM key adoption");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_ml_kem_key_adoption");

   const Suite suite(KEM_Code::ML_KEM_768, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
   if(!suite.is_available()) {
      result.test_note("Skipping, ML-KEM-768 suite not available");
      return result;
   }

   const auto kem = suite.kem();
   const Botan::ML_KEM_Mode mode(Botan::ML_KEM_Mode::ML_KEM_768);
   const auto msg = pq_to_bytes("message");

   const Botan::ML_KEM_PrivateKey ml_kem_sk(*rng, mode);
   const auto seed = ml_kem_sk.formatted_raw_private_key_bits(Botan::MlPrivateKeyFormat::Seed);
   const auto expanded = ml_kem_sk.formatted_raw_private_key_bits(Botan::MlPrivateKeyFormat::Expanded);
   const auto ek = ml_kem_sk.raw_public_key_bits();

   // The HPKE encodings are the seed, and the encapsulation key
   const auto sk = Private_Key::from_key(kem, std::make_unique<Botan::ML_KEM_PrivateKey>(seed, mode));
   result.test_bin_eq("adopted private key serializes as the seed", sk.serialize(), seed);
   result.test_bin_eq("adopted private key has the expected public key", sk.public_key().serialize(), ek);

   const auto pk = Public_Key::from_key(kem, std::make_unique<Botan::ML_KEM_PublicKey>(ek, mode));
   result.test_bin_eq("adopted public key serializes as the encapsulation key", pk.serialize(), ek);
   result.test_is_true("adopted keys match", pk == sk.public_key());

   result.test_is_true("underlying private key is ML-KEM",
                       dynamic_cast<const Botan::ML_KEM_PrivateKey*>(&sk.underlying()) != nullptr);
   result.test_is_true("underlying public key is ML-KEM",
                       dynamic_cast<const Botan::ML_KEM_PublicKey*>(&pk.underlying()) != nullptr);

   // Keys can go via PKCS #8 and X.509
   const auto pkcs8 = Botan::PKCS8::BER_encode(sk.underlying());
   Botan::DataSource_Memory pkcs8_src(pkcs8);
   const auto sk_from_pkcs8 = Private_Key::from_key(kem, Botan::PKCS8::load_key(pkcs8_src));
   result.test_bin_eq("PKCS #8 round trip", sk_from_pkcs8.serialize(), seed);

   const auto spki = Botan::X509::BER_encode(pk.underlying());
   const auto pk_from_spki = Public_Key::from_key(kem, Botan::X509::load_key(spki));
   result.test_bin_eq("X.509 round trip", pk_from_spki.serialize(), ek);

   // A key of another parameter set, or another algorithm, is rejected
   const Botan::ML_KEM_Mode other_mode(Botan::ML_KEM_Mode::ML_KEM_1024);
   if(other_mode.is_available()) {
      result.test_throws<Botan::Invalid_Argument>("private key of another parameter set rejected", [&] {
         Private_Key::from_key(kem, std::make_unique<Botan::ML_KEM_PrivateKey>(*rng, other_mode));
      });

      const Botan::ML_KEM_PrivateKey other_sk(*rng, other_mode);
      result.test_throws<Botan::Invalid_Argument>("public key of another parameter set rejected",
                                                  [&] { Public_Key::from_key(kem, other_sk.public_key()); });
   }

   #if defined(BOTAN_HAS_X25519)
   result.test_throws<Botan::Invalid_Argument>("X25519 private key rejected", [&] {
      Private_Key::from_key(kem, std::make_unique<Botan::X25519_PrivateKey>(*rng));
   });
   #endif

   #if defined(BOTAN_HAS_KYBER)
   const Botan::KyberMode kyber_r3(Botan::KyberMode::Kyber768_R3);
   if(kyber_r3.is_available()) {
      result.test_throws<Botan::Invalid_Argument>("Kyber round 3 key rejected", [&] {
         Private_Key::from_key(kem, std::make_unique<Botan::Kyber_PrivateKey>(*rng, kyber_r3));
      });
   }
   #endif

   /*
   * An ML-KEM key which was stored in the expanded format has no seed. It
   * can be used with HPKE, but cannot be serialized in the HPKE format.
   */
   const auto expanded_sk = Private_Key::from_key(kem, std::make_unique<Botan::ML_KEM_PrivateKey>(expanded, mode));
   result.test_bin_eq("expanded key has the expected public key", expanded_sk.public_key().serialize(), ek);

   auto sender = Sender_Context::setup_base(suite, pk, *rng);
   auto recipient = Recipient_Context::setup_base(suite, expanded_sk, sender.encapsulated_key(), *rng);
   result.test_bin_eq("expanded key can decapsulate", recipient.open({}, sender.seal({}, msg)), msg);
   result.test_throws<Botan::Invalid_State>("expanded key cannot be serialized", [&] { expanded_sk.serialize(); });

   // The expanded encoding is not accepted by DeserializePrivateKey
   result.test_throws<Botan::Decoding_Error>("expanded key is not the HPKE encoding",
                                             [&] { Private_Key::deserialize(kem, expanded); });

   return result;
}

Test::Result test_hpke_hybrid_keys() {
   Test::Result result("HPKE hybrid KEM keys");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_hybrid_keys");

   const std::vector<KEM_Code> hybrids = {KEM_Code::MLKEM768_P256, KEM_Code::MLKEM1024_P384, KEM_Code::MLKEM768_X25519};

   for(const auto kem_code : hybrids) {
      const Suite suite(kem_code, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      if(!suite.is_available()) {
         result.test_note("Skipping unavailable KEM " + pq_kem_name(suite.kem()));
         continue;
      }

      const auto kem = suite.kem();
      const auto sk = Private_Key::generate(kem, *rng);
      const auto pk = sk.public_key();

      // The underlying keys are of a type internal to HPKE, with only raw encodings
      const auto& raw_sk = sk.underlying();
      const auto& raw_pk = pk.underlying();

      result.test_str_eq("private key algorithm name", raw_sk.algo_name(), pq_kem_name(kem));
      result.test_str_eq("public key algorithm name", raw_pk.algo_name(), pq_kem_name(kem));
      result.test_bin_eq("raw public key", raw_pk.raw_public_key_bits(), pk.serialize());
      result.test_bin_eq("raw public key of private key", raw_sk.raw_public_key_bits(), pk.serialize());
      result.test_bin_eq("raw private key", raw_sk.raw_private_key_bits(), sk.serialize());
      result.test_bin_eq("public key of private key", raw_sk.public_key()->raw_public_key_bits(), pk.serialize());
      result.test_is_true("public key check", raw_pk.check_key(*rng, true));
      result.test_is_true("private key check", raw_sk.check_key(*rng, true));
      result.test_sz_gte("estimated strength", raw_pk.estimated_strength(), 128);
      result.test_is_false("no operations are offered",
                           raw_pk.supports_operation(Botan::PublicKeyOperation::KeyEncapsulation));
      result.test_throws<Botan::Not_Implemented>("no algorithm identifier", [&] { raw_pk.algorithm_identifier(); });
      result.test_throws<Botan::Not_Implemented>("no PKCS #8 encoding", [&] { raw_sk.private_key_bits(); });
      result.test_throws("no X.509 encoding", [&] { Botan::X509::BER_encode(raw_pk); });

      // from_key accepts only a key of this KEM
      auto another = raw_pk.generate_another(*rng);
      const auto another_pk_bytes = another->raw_public_key_bits();
      result.test_bin_ne("generate_another creates a new key", another_pk_bytes, pk.serialize());
      const auto adopted = Private_Key::from_key(kem, std::move(another));
      result.test_bin_eq("adopted key", adopted.public_key().serialize(), another_pk_bytes);

      for(const auto other_code : hybrids) {
         if(other_code != kem_code && KEM_Id(other_code).is_available()) {
            result.test_throws<Botan::Invalid_Argument>("private key of another hybrid KEM rejected", [&] {
               Private_Key::from_key(other_code, raw_pk.generate_another(*rng));
            });
            result.test_throws<Botan::Invalid_Argument>("public key of another hybrid KEM rejected",
                                                        [&] { Public_Key::from_key(other_code, raw_sk.public_key()); });
         }
      }

      const Botan::ML_KEM_Mode ml_kem_768(Botan::ML_KEM_Mode::ML_KEM_768);
      result.test_throws<Botan::Invalid_Argument>("ML-KEM private key rejected", [&] {
         Private_Key::from_key(kem, std::make_unique<Botan::ML_KEM_PrivateKey>(*rng, ml_kem_768));
      });

      // The key of a hybrid KEM cannot be used with its ML-KEM component alone
      const Suite ml_kem_suite(KEM_Code::ML_KEM_768, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      result.test_throws<Botan::Invalid_Argument>("setup rejects key for another KEM",
                                                  [&] { Sender_Context::setup_base(ml_kem_suite, pk, *rng); });
   }

   return result;
}

Test::Result test_hpke_hybrid_group_elements() {
   Test::Result result("HPKE hybrid KEM group element validation");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_hybrid_group_elements");

   for(const auto kem_code : {KEM_Code::MLKEM768_P256, KEM_Code::MLKEM1024_P384, KEM_Code::MLKEM768_X25519}) {
      const Suite suite(kem_code, KDF_Code::HKDF_SHA256, AEAD_Code::AES_128_GCM);
      if(!suite.is_available()) {
         result.test_note("Skipping unavailable KEM " + pq_kem_name(suite.kem()));
         continue;
      }

      const auto kem = suite.kem();
      const size_t elem_bytes = hybrid_group_element_bytes(kem);

      const auto skR = Private_Key::generate(kem, *rng);
      const auto valid_pk = skR.public_key().serialize();
      const auto valid_enc = Sender_Context::setup_base(suite, skR.public_key(), *rng).encapsulated_key();

      result.test_no_throw("valid encapsulation accepted",
                           [&] { Recipient_Context::setup_base(suite, skR, valid_enc, *rng); });

      // Replace the group element at the end of a public key or encapsulation
      const auto with_element = [&](const std::vector<uint8_t>& encoding, std::span<const uint8_t> element) {
         auto out = encoding;
         std::copy(element.begin(), element.end(), out.end() - elem_bytes);
         return out;
      };

      const std::vector<uint8_t> valid_element(valid_pk.end() - elem_bytes, valid_pk.end());

      if(kem_code == KEM_Code::MLKEM768_X25519) {
         /*
         * Every 32 byte string is accepted as a public key. One that encodes
         * a point of low order is rejected when the key agreement results in
         * an all zero output; here the identity, and a point of order 8.
         */
         const std::vector<uint8_t> zero(32, 0);
         const auto order_8 = Botan::hex_decode("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");

         for(const auto& low_order : {zero, order_8}) {
            const auto bad_pk = Public_Key::deserialize(kem, with_element(valid_pk, low_order));
            result.test_throws<Botan::Invalid_Argument>("low order public key rejected",
                                                        [&] { Sender_Context::setup_base(suite, bad_pk, *rng); });
            result.test_throws<Botan::Invalid_Argument>("low order encapsulation rejected", [&] {
               Recipient_Context::setup_base(suite, skR, with_element(valid_enc, low_order), *rng);
            });
         }
         continue;
      }

      // An invalid point must be rejected by DeserializePublicKey, and when
      // presented to a recipient as part of the encapsulation
      const auto rejected = [&](const std::string& what, const std::vector<uint8_t>& bad_element) {
         result.test_throws<Botan::Decoding_Error>(what + " rejected by deserialize", [&] {
            Public_Key::deserialize(kem, with_element(valid_pk, bad_element));
         });
         result.test_throws<Botan::Decoding_Error>(what + " rejected in enc", [&] {
            Recipient_Context::setup_base(suite, skR, with_element(valid_enc, bad_element), *rng);
         });
      };

      const size_t fe_bytes = (elem_bytes - 1) / 2;

      // Only the uncompressed SEC1 encoding is allowed
      for(const uint8_t prefix :
          {uint8_t(0x00), uint8_t(0x02), uint8_t(0x03), uint8_t(0x05), uint8_t(0x06), uint8_t(0x07)}) {
         auto bad = valid_element;
         bad[0] = prefix;
         rejected("prefix " + std::to_string(prefix), bad);
      }

      rejected("all zero element", std::vector<uint8_t>(elem_bytes, 0));

      auto origin = std::vector<uint8_t>(elem_bytes, 0);
      origin[0] = 0x04;
      rejected("point (0,0)", origin);

      auto off_curve = valid_element;
      off_curve.back() ^= 0x01;
      rejected("point not on the curve", off_curve);

      auto x_out_of_range = valid_element;
      std::fill(x_out_of_range.begin() + 1, x_out_of_range.begin() + 1 + fe_bytes, 0xFF);
      rejected("x coordinate out of range", x_out_of_range);

      auto y_out_of_range = valid_element;
      std::fill(y_out_of_range.begin() + 1 + fe_bytes, y_out_of_range.end(), 0xFF);
      rejected("y coordinate out of range", y_out_of_range);
   }

   return result;
}

Test::Result test_hpke_hybrid_scalar_sampling() {
   Test::Result result("HPKE hybrid KEM scalar sampling");

   using namespace Botan::HPKE;

   auto rng = Test::new_rng("hpke_hybrid_scalar_sampling");

   struct Params {
         KEM_Code kem;
         std::string curve;
         size_t candidates;
   };

   // RandomScalar of draft-irtf-cfrg-concrete-hybrid-kems-03 Section 3.1.1
   // takes a seed of 128 bytes for P-256, and of 48 bytes for P-384
   const std::vector<Params> params = {
      {KEM_Code::MLKEM768_P256, "secp256r1", 4},
      {KEM_Code::MLKEM1024_P384, "secp384r1", 1},
   };

   for(const auto& p : params) {
      const KEM_Id kem(p.kem);
      if(!kem.is_available()) {
         result.test_note("Skipping unavailable KEM " + pq_kem_name(kem));
         continue;
      }

      const auto group = Botan::EC_Group::from_name(p.curve);
      const size_t scalar_bytes = group.get_order_bytes();
      const size_t elem_bytes = hybrid_group_element_bytes(kem);

      const auto generator = Botan::EC_AffinePoint::generator(group);
      const auto g_bytes = generator.serialize_uncompressed<std::vector<uint8_t>>();
      const auto neg_g_bytes = generator.negate().serialize_uncompressed<std::vector<uint8_t>>();

      // Candidate scalars: 1 and n-1 are the extremes of the valid range,
      // while 0, n and 2^b - 1 are all outside of it
      std::vector<uint8_t> one(scalar_bytes, 0);
      one.back() = 1;
      const auto order_minus_one = (group.get_order() - 1).serialize(scalar_bytes);
      const std::vector<uint8_t> zero(scalar_bytes, 0);
      const auto order = group.get_order().serialize(scalar_bytes);
      const std::vector<uint8_t> all_ones(scalar_bytes, 0xFF);
      const std::vector<std::vector<uint8_t>> invalid = {zero, order, all_ones};

      const auto sk = Private_Key::generate(kem, *rng);
      const auto pk = sk.public_key();
      const auto ops = KEM_Ops::create(kem);

      const std::vector<uint8_t> ml_kem_randomness(32, 0x4D);

      // The randomness is 32 bytes for ML-KEM, followed by the seed for
      // RandomScalar, here given as a list of candidates
      const auto encap_with = [&](const std::vector<std::vector<uint8_t>>& candidates) {
         std::vector<uint8_t> randomness = ml_kem_randomness;
         for(size_t i = 0; i != p.candidates; ++i) {
            const auto& candidate = (i < candidates.size()) ? candidates[i] : all_ones;
            randomness.insert(randomness.end(), candidate.begin(), candidate.end());
         }
         auto kem_rng = derand_rng(randomness, *rng);
         return ops->encap(pk.underlying(), kem_rng);
      };

      const auto group_element_of = [&](const KEM_Ops::Encapsulation& encap) {
         return std::vector<uint8_t>(encap.enc.end() - elem_bytes, encap.enc.end());
      };

      const auto reference = encap_with({one});
      result.test_bin_eq("scalar 1 results in the generator", group_element_of(reference), g_bytes);
      result.test_bin_eq("decapsulation", ops->decap(reference.enc, sk.underlying(), *rng), reference.shared_secret);

      const auto max_scalar = encap_with({order_minus_one});
      result.test_bin_eq("scalar n-1 is accepted", group_element_of(max_scalar), neg_g_bytes);
      result.test_bin_eq(
         "decapsulation with scalar n-1", ops->decap(max_scalar.enc, sk.underlying(), *rng), max_scalar.shared_secret);

      // Every invalid candidate is skipped, in favor of the next one
      for(size_t skipped = 1; skipped < p.candidates; ++skipped) {
         for(const auto& bad : invalid) {
            std::vector<std::vector<uint8_t>> candidates(skipped, bad);
            candidates.push_back(one);
            const auto encap = encap_with(candidates);
            result.test_bin_eq("invalid candidates skipped", encap.enc, reference.enc);
            result.test_bin_eq("same shared secret", encap.shared_secret, reference.shared_secret);
         }
      }

      // It is an error if no candidate is valid
      for(const auto& bad : invalid) {
         result.test_throws("rejection sampling failure",
                            [&] { encap_with(std::vector<std::vector<uint8_t>>(p.candidates, bad)); });
      }
   }

   return result;
}

BOTAN_REGISTER_TEST_FN("pubkey",
                       "hpke_pq",
                       test_hpke_pq_kem_ids,
                       test_hpke_pq_round_trip,
                       test_hpke_pq_key_encoding,
                       test_hpke_ml_kem_key_adoption,
                       test_hpke_hybrid_keys,
                       test_hpke_hybrid_group_elements,
                       test_hpke_hybrid_scalar_sampling);

}  // namespace

#endif

}  // namespace Botan_Tests
