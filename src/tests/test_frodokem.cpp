/*
 * Tests for FrodoKEM ("You SHALL Pass")
 * - KAT tests using the KAT vectors from
 *   https://github.com/microsoft/PQCrypto-LWEKE/tree/master/KAT
 *
 * (C) 2023 Jack Lloyd
 * (C) 2023 René Meusel and Amos Treiber, Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_rng.h"
#include "tests.h"

#include <iostream>
#include <iterator>
#include <memory>

#if defined(BOTAN_HAS_FRODOKEM)
   #include "test_pubkey.h"

   #include <botan/frodokem.h>
   #include <botan/pubkey.h>
   #include <botan/xof.h>
   #include <botan/internal/fmt.h>
   #include <botan/internal/frodo_constants.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_FRODOKEM)

namespace {

   #if defined(BOTAN_HAS_AES)

Botan::FrodoKEMMode get_mode(std::string_view header) {
   if(header == "FrodoKEM-640-SHAKE") {
      return Botan::FrodoKEMMode::FrodoKEM640_SHAKE;
   } else if(header == "FrodoKEM-976-SHAKE") {
      return Botan::FrodoKEMMode::FrodoKEM976_SHAKE;
   } else if(header == "FrodoKEM-1344-SHAKE") {
      return Botan::FrodoKEMMode::FrodoKEM1344_SHAKE;
   } else if(header == "eFrodoKEM-640-SHAKE") {
      return Botan::FrodoKEMMode::eFrodoKEM640_SHAKE;
   } else if(header == "eFrodoKEM-976-SHAKE") {
      return Botan::FrodoKEMMode::eFrodoKEM976_SHAKE;
   } else if(header == "eFrodoKEM-1344-SHAKE") {
      return Botan::FrodoKEMMode::eFrodoKEM1344_SHAKE;
   } else if(header == "FrodoKEM-640-AES") {
      return Botan::FrodoKEMMode::FrodoKEM640_AES;
   } else if(header == "FrodoKEM-976-AES") {
      return Botan::FrodoKEMMode::FrodoKEM976_AES;
   } else if(header == "FrodoKEM-1344-AES") {
      return Botan::FrodoKEMMode::FrodoKEM1344_AES;
   } else if(header == "eFrodoKEM-640-AES") {
      return Botan::FrodoKEMMode::eFrodoKEM640_AES;
   } else if(header == "eFrodoKEM-976-AES") {
      return Botan::FrodoKEMMode::eFrodoKEM976_AES;
   } else if(header == "eFrodoKEM-1344-AES") {
      return Botan::FrodoKEMMode::eFrodoKEM1344_AES;
   }

   throw Test_Error(Botan::fmt("Unexpected FrodoKEM mode: {}", header));
}

decltype(auto) shake256_16(std::span<const uint8_t> data) {
   // Hash function to compare to the hashed values in the KAT file
   // We're using SHAKE-256 as a XOF because this is a hard and direct
   // dependency of the FrodoKEM module and will always be available
   // when FrodoKEM is enabled in the Botan module configuration.
   auto xof = Botan::XOF::create_or_throw("SHAKE-256");
   xof->update(data);
   return xof->output<std::vector<uint8_t>>(16);
}

class Frodo_KAT_Tests final : public Text_Based_Test {
   public:
      Frodo_KAT_Tests() : Text_Based_Test("pubkey/frodokem_kat.vec", "Seed,SS,PK,SK,CT") {}

      bool skip_this_test(const std::string& header, const VarMap&) override {
         return !get_mode(header).is_available();
      }

      Test::Result run_one_test(const std::string& header, const VarMap& vars) override {
         Test::Result result(Botan::fmt("FrodoKEM KAT {}", header));

         const auto mode = get_mode(header);
         const Botan::FrodoKEMConstants consts(mode);

         // Our implementation performs three independent RNG invocations to get
         // the seeds (s, seed_sk and z). The reference implementation assumes one
         // concatenated RNG invocation and slices the seeds from a single buffer.
         // We have to emulate this behaviour with the Fixed_Output_RNG below.
         CTR_DRBG_AES256 ctr_drbg(vars.get_req_bin("Seed"));
         Fixed_Output_RNG fixed_generation_rng(ctr_drbg.random_vec<std::vector<uint8_t>>(
            consts.len_sec_bytes() + consts.len_se_bytes() + consts.len_a_bytes()));

         // Key generation
         Botan::FrodoKEM_PrivateKey sk(fixed_generation_rng, mode);
         result.test_is_eq("Generated private key", shake256_16(sk.raw_private_key_bits()), vars.get_req_bin("SK"));

         auto pk = sk.public_key();
         result.test_is_eq("Generated public key", shake256_16(pk->public_key_bits()), vars.get_req_bin("PK"));

         // Encapsulation
         Botan::FrodoKEM_PublicKey pk2(pk->public_key_bits(), mode);
         Fixed_Output_RNG fixed_encapsulation_rng(
            ctr_drbg.random_vec<std::vector<uint8_t>>(consts.len_sec_bytes() + consts.len_salt_bytes()));
         auto enc = Botan::PK_KEM_Encryptor(pk2, "Raw");
         const auto encaped = enc.encrypt(fixed_encapsulation_rng, 0 /* no KDF */);
         result.test_is_eq("Shared Secret", encaped.shared_key(), Botan::lock(vars.get_req_bin("SS")));
         result.test_is_eq("Ciphertext", shake256_16(encaped.encapsulated_shared_key()), vars.get_req_bin("CT"));

         // Decapsulation
         Botan::FrodoKEM_PrivateKey sk2(sk.private_key_bits(), mode);
         Botan::Null_RNG null_rng;
         auto dec = Botan::PK_KEM_Decryptor(sk2, null_rng, "Raw");
         const auto shared_key = dec.decrypt(encaped.encapsulated_shared_key(), 0 /* no KDF */);
         result.test_is_eq("Decaps. Shared Secret", shared_key, Botan::lock(vars.get_req_bin("SS")));

         return result;
      }
};

   #endif

std::vector<Test::Result> test_frodo_roundtrips() {
   auto& rng = Test::rng();

   auto modes = std::vector{Botan::FrodoKEMMode::eFrodoKEM1344_SHAKE,
                            Botan::FrodoKEMMode::eFrodoKEM976_SHAKE,
                            Botan::FrodoKEMMode::eFrodoKEM640_SHAKE,
                            Botan::FrodoKEMMode::FrodoKEM1344_SHAKE,
                            Botan::FrodoKEMMode::FrodoKEM976_SHAKE,
                            Botan::FrodoKEMMode::FrodoKEM640_SHAKE,
                            Botan::FrodoKEMMode::eFrodoKEM1344_AES,
                            Botan::FrodoKEMMode::eFrodoKEM976_AES,
                            Botan::FrodoKEMMode::eFrodoKEM640_AES,
                            Botan::FrodoKEMMode::FrodoKEM1344_AES,
                            Botan::FrodoKEMMode::FrodoKEM976_AES,
                            Botan::FrodoKEMMode::FrodoKEM640_AES};

   auto get_decryption_error_value = [](Botan::FrodoKEMConstants& consts,
                                        std::span<const uint8_t> encaps_value,
                                        const Botan::FrodoKEM_PrivateKey& sk) {
      // Extracts the `S` value from the encoded private key
      auto& shake = consts.SHAKE_XOF();
      const auto sk_bytes = sk.raw_private_key_bits();
      auto sk_s = std::span<const uint8_t>(sk_bytes.data(), consts.len_sec_bytes());
      shake.update(encaps_value);
      shake.update(sk_s);
      return shake.output(consts.len_sec_bytes());
   };

   std::vector<Test::Result> results;
   for(auto mode : modes) {
      Botan::FrodoKEMMode m(mode);
      if(!m.is_available()) {
         continue;
      }
      Botan::FrodoKEMConstants consts(mode);
      Test::Result& result = results.emplace_back("FrodoKEM roundtrip: " + m.to_string());

      Botan::FrodoKEM_PrivateKey sk1(rng, mode);
      Botan::FrodoKEM_PublicKey pk1(sk1.public_key_bits(), mode);

      // Happy case
      Botan::PK_KEM_Encryptor enc1(pk1, "Raw");
      const auto enc_res = enc1.encrypt(rng, 0 /* no KDF */);

      result.test_eq("length of shared secret", enc_res.shared_key().size(), enc1.shared_key_length(0));
      result.test_eq("length of ciphertext", enc_res.encapsulated_shared_key().size(), enc1.encapsulated_key_length());

      Botan::PK_KEM_Decryptor dec1(sk1, rng, "Raw");
      auto ss = dec1.decrypt(enc_res.encapsulated_shared_key(), 0 /* no KDF */);

      result.test_eq("shared secrets match", ss, enc_res.shared_key());
      result.test_eq("length of shared secret (decaps)", ss.size(), dec1.shared_key_length(0));

      // Decryption failures ("All right then, keep your secrets.")
      Botan::FrodoKEM_PrivateKey sk2(rng, mode);

      // Decryption failure: mismatching private key
      Botan::PK_KEM_Decryptor dec2(sk2, rng, "Raw");
      auto ss_mismatch = dec2.decrypt(enc_res.encapsulated_shared_key(), 0 /* no KDF */);
      result.test_eq("decryption failure sk",
                     ss_mismatch,
                     get_decryption_error_value(consts, enc_res.encapsulated_shared_key(), sk2));

      // Decryption failure: bitflip in encapsulated shared value
      const auto mutated_encaps_value = Test::mutate_vec(enc_res.encapsulated_shared_key());
      ss_mismatch = dec2.decrypt(mutated_encaps_value, 0 /* no KDF */);
      result.test_eq(
         "decryption failure bitflip", ss_mismatch, get_decryption_error_value(consts, mutated_encaps_value, sk2));

      // Decryption failure: malformed encapsulation value
      result.test_throws(
         "malformed encapsulation value", "FrodoKEM ciphertext does not have the correct byte count", [&] {
            auto short_encaps_value = enc_res.encapsulated_shared_key();
            short_encaps_value.pop_back();
            dec1.decrypt(short_encaps_value, 0);
         });
   }

   return results;
}

class Frodo_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         return {
   #if defined(BOTAN_HAS_FRODOKEM_SHAKE)
            "FrodoKEM-640-SHAKE", "FrodoKEM-976-SHAKE", "eFrodoKEM-640-SHAKE", "eFrodoKEM-976-SHAKE",
   #endif
   #if defined(BOTAN_HAS_FRODOKEM_AES)
               "FrodoKEM-640-AES", "FrodoKEM-976-AES", "eFrodoKEM-640-AES", "eFrodoKEM-976-AES",
   #endif
         };
      }

      std::string algo_name() const override { return "FrodoKEM"; }
};

}  // namespace

   #if defined(BOTAN_HAS_AES)
BOTAN_REGISTER_TEST("frodokem", "frodo_kat_tests", Frodo_KAT_Tests);
   #endif

BOTAN_REGISTER_TEST_FN("frodokem", "frodo_roundtrips", test_frodo_roundtrips);
BOTAN_REGISTER_TEST("frodokem", "frodo_keygen", Frodo_Keygen_Tests);

#endif

}  // namespace Botan_Tests
