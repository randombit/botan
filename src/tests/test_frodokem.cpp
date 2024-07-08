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

#include "test_pubkey_pqc.h"
#include "test_rng.h"
#include "tests.h"

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
class Frodo_KAT_Tests final : public PK_PQC_KEM_KAT_Test {
   public:
      Frodo_KAT_Tests() : PK_PQC_KEM_KAT_Test("FrodoKEM", "pubkey/frodokem_kat.vec") {}

   private:
      Botan::FrodoKEMMode get_mode(const std::string& mode) const { return Botan::FrodoKEMMode(mode); }

      bool is_available(const std::string& mode) const final { return get_mode(mode).is_available(); }

      std::vector<uint8_t> map_value(const std::string&, std::span<const uint8_t> value, VarType var_type) const final {
         if(var_type == VarType::SharedSecret) {
            return {value.begin(), value.end()};
         }
         auto xof = Botan::XOF::create_or_throw("SHAKE-256");
         xof->update(value);
         return xof->output<std::vector<uint8_t>>(16);
      }

      Fixed_Output_RNG rng_for_keygen(const std::string& mode, Botan::RandomNumberGenerator& rng) const final {
         Botan::FrodoKEMConstants consts(get_mode(mode));
         return Fixed_Output_RNG(rng, consts.len_sec_bytes() + consts.len_se_bytes() + consts.len_a_bytes());
      }

      Fixed_Output_RNG rng_for_encapsulation(const std::string& mode, Botan::RandomNumberGenerator& rng) const final {
         Botan::FrodoKEMConstants consts(get_mode(mode));
         return Fixed_Output_RNG(rng, consts.len_sec_bytes() + consts.len_salt_bytes());
      }
};

std::vector<Test::Result> test_frodo_roundtrips() {
   auto rng = Test::new_rng("frodokem_roundtrip");

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

      Botan::FrodoKEM_PrivateKey sk1(*rng, mode);
      Botan::FrodoKEM_PublicKey pk1(sk1.public_key_bits(), mode);

      // Happy case
      Botan::PK_KEM_Encryptor enc1(pk1, "Raw");
      const auto enc_res = enc1.encrypt(*rng, 0 /* no KDF */);

      result.test_eq("length of shared secret", enc_res.shared_key().size(), enc1.shared_key_length(0));
      result.test_eq("length of ciphertext", enc_res.encapsulated_shared_key().size(), enc1.encapsulated_key_length());

      Botan::PK_KEM_Decryptor dec1(sk1, *rng, "Raw");
      auto ss = dec1.decrypt(enc_res.encapsulated_shared_key(), 0 /* no KDF */);

      result.test_eq("shared secrets match", ss, enc_res.shared_key());
      result.test_eq("length of shared secret (decaps)", ss.size(), dec1.shared_key_length(0));

      // Decryption failures ("All right then, keep your secrets.")
      Botan::FrodoKEM_PrivateKey sk2(*rng, mode);

      // Decryption failure: mismatching private key
      Botan::PK_KEM_Decryptor dec2(sk2, *rng, "Raw");
      auto ss_mismatch = dec2.decrypt(enc_res.encapsulated_shared_key(), 0 /* no KDF */);
      result.test_eq("decryption failure sk",
                     ss_mismatch,
                     get_decryption_error_value(consts, enc_res.encapsulated_shared_key(), sk2));

      // Decryption failure: bitflip in encapsulated shared value
      const auto mutated_encaps_value = Test::mutate_vec(enc_res.encapsulated_shared_key(), *rng);
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

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::FrodoKEM_PublicKey>(raw_pk, Botan::FrodoKEMMode(keygen_params));
      }
};

}  // namespace

BOTAN_REGISTER_TEST("frodokem", "frodo_kat_tests", Frodo_KAT_Tests);
BOTAN_REGISTER_TEST_FN("frodokem", "frodo_roundtrips", test_frodo_roundtrips);
BOTAN_REGISTER_TEST("frodokem", "frodo_keygen", Frodo_Keygen_Tests);

#endif

}  // namespace Botan_Tests
