/*
 * Tests for HQC
 * - KAT tests using the vectors of the reference implementation as vendored
 *   in the Rust crate rust-hqc
 *
 * (C) 2026 Falko Strenzke
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "test_pubkey_pqc.h"
#include "tests.h"

#include <memory>

#if defined(BOTAN_HAS_HQC)
   #include "test_pubkey.h"
   #include "test_rng.h"

   #include <botan/hqc.h>
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
   #include <botan/internal/fmt.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HQC)

namespace {

/**
 * Key generation is verified against all vectors of the reference KATs. The
 * encapsulation of the reference KATs continues the PRNG stream of the key
 * generation and cannot be reproduced through the stateless C API of the
 * crate; the decapsulation is verified separately by HQC_KAT_Decap_Tests.
 */
class HQC_KAT_KeyGen_Tests final : public PK_PQC_KEM_ACVP_KAT_KeyGen_Test {
   public:
      HQC_KAT_KeyGen_Tests() : PK_PQC_KEM_ACVP_KAT_KeyGen_Test("HQC", "pubkey/hqc_kat_keygen.vec", "Seed") {}

   private:
      bool is_available(const std::string& /*params*/) const final { return true; }

      Fixed_Output_RNG rng_for_keygen(const VarMap& vars) const final {
         return Fixed_Output_RNG(vars.get_req_bin("Seed"));
      }
};

/**
 * Decapsulation of the reference ciphertexts with the key generated from the
 * reference seed must yield the reference shared secret.
 */
class HQC_KAT_Decap_Tests final : public PK_Test {
   public:
      HQC_KAT_Decap_Tests() : PK_Test("HQC", "pubkey/hqc_kat_decap.vec", "Seed,CT,SS") {}

   private:
      Test::Result run_one_test(const std::string& params, const VarMap& vars) final {
         Test::Result result(Botan::fmt("HQC decapsulation KAT with parameters {}", params));

         Fixed_Output_RNG rng_keygen(vars.get_req_bin("Seed"));
         const Botan::HQC_PrivateKey sk(rng_keygen, Botan::HQC_Mode(params));
         result.test_is_true("All prepared random bits used for key generation", rng_keygen.empty());

         Botan::Null_RNG null_rng;
         Botan::PK_KEM_Decryptor dec(sk, null_rng, "Raw");
         const auto shared_key = dec.decrypt(vars.get_req_bin("CT"), 0 /* no KDF */);
         result.test_bin_eq("Decaps. Shared Secret", shared_key, vars.get_req_bin("SS"));

         return result;
      }
};

std::vector<Test::Result> test_hqc_roundtrips() {
   auto rng = Test::new_rng("hqc_roundtrip");

   const auto modes = std::vector{Botan::HQC_Mode::HQC_1, Botan::HQC_Mode::HQC_3, Botan::HQC_Mode::HQC_5};

   std::vector<Test::Result> results;
   for(const auto mode : modes) {
      const Botan::HQC_Mode m(mode);
      Test::Result& result = results.emplace_back("HQC roundtrip: " + m.to_string());

      const Botan::HQC_PrivateKey sk1(*rng, mode);
      const Botan::HQC_PublicKey pk1(sk1.public_key_bits(), mode);

      // Happy case
      Botan::PK_KEM_Encryptor enc1(pk1, "Raw");
      const auto enc_res = enc1.encrypt(*rng, 0 /* no KDF */);

      result.test_sz_eq("length of shared secret", enc_res.shared_key().size(), enc1.shared_key_length(0));
      result.test_sz_eq(
         "length of ciphertext", enc_res.encapsulated_shared_key().size(), enc1.encapsulated_key_length());

      Botan::PK_KEM_Decryptor dec1(sk1, *rng, "Raw");
      auto ss = dec1.decrypt(enc_res.encapsulated_shared_key(), 0 /* no KDF */);

      result.test_bin_eq("shared secrets match", ss, enc_res.shared_key());
      result.test_sz_eq("length of shared secret (decaps)", ss.size(), dec1.shared_key_length(0));

      // Decryption failures are hidden by implicit rejection: the result is a
      // pseudo-random shared secret that differs from the encapsulated one.
      const Botan::HQC_PrivateKey sk2(*rng, mode);

      // Decryption failure: mismatching private key
      Botan::PK_KEM_Decryptor dec2(sk2, *rng, "Raw");
      auto ss_mismatch = dec2.decrypt(enc_res.encapsulated_shared_key(), 0 /* no KDF */);
      result.test_bin_ne("decryption failure sk", ss_mismatch, enc_res.shared_key());

      // Decryption failure: bitflip in encapsulated shared value
      const auto mutated_encaps_value = Test::mutate_vec(enc_res.encapsulated_shared_key(), *rng);
      ss_mismatch = dec1.decrypt(mutated_encaps_value, 0 /* no KDF */);
      result.test_bin_ne("decryption failure bitflip", ss_mismatch, enc_res.shared_key());

      // Decryption failure: malformed encapsulation value
      result.test_throws("short encapsulation value", "HQC ciphertext does not have the correct byte count", [&] {
         auto short_encaps_value = enc_res.encapsulated_shared_key();
         short_encaps_value.pop_back();
         dec1.decrypt(short_encaps_value, 0);
      });
      result.test_throws("long encapsulation value", "HQC ciphertext does not have the correct byte count", [&] {
         auto long_encaps_value = enc_res.encapsulated_shared_key();
         long_encaps_value.push_back(0);
         dec1.decrypt(long_encaps_value, 0);
      });

      // Key encodings
      const auto pk_loaded = Botan::load_public_key(pk1.algorithm_identifier(), pk1.public_key_bits());
      result.test_not_null("public key loaded from encoding", pk_loaded);
      result.test_bin_eq("public key encoding roundtrip", pk_loaded->public_key_bits(), pk1.public_key_bits());
      result.test_str_eq("loaded public key algorithm name", pk_loaded->algo_name(), "HQC");

      const auto sk_loaded = Botan::load_private_key(sk1.algorithm_identifier(), sk1.private_key_bits());
      result.test_not_null("private key loaded from encoding", sk_loaded);
      result.test_bin_eq("private key encoding roundtrip", sk_loaded->private_key_bits(), sk1.private_key_bits());
      result.test_bin_eq(
         "public key of loaded private key", sk_loaded->public_key()->public_key_bits(), pk1.public_key_bits());

      result.test_throws("short public key", "HQC public key does not have the correct byte count", [&] {
         auto short_pk = pk1.public_key_bits();
         short_pk.pop_back();
         const Botan::HQC_PublicKey pk(short_pk, mode);
      });
      result.test_throws("public key with non-zero padding bits", "HQC public key has non-zero padding bits", [&] {
         // For all parameter sets n mod 8 != 0, so the most significant bit
         // of the last byte is a padding bit
         auto padded_pk = pk1.public_key_bits();
         padded_pk.back() |= 0x80;
         const Botan::HQC_PublicKey pk(padded_pk, mode);
      });
      result.test_throws("short private key", "HQC private key does not have the correct byte count", [&] {
         auto short_sk = sk1.private_key_bits();
         short_sk.pop_back();
         const Botan::HQC_PrivateKey sk(short_sk, mode);
      });
      result.test_throws("public key with parameters in algorithm identifier", [&] {
         const Botan::AlgorithmIdentifier alg_id(m.object_identifier(), Botan::AlgorithmIdentifier::USE_NULL_PARAM);
         const Botan::HQC_PublicKey pk(alg_id, pk1.public_key_bits());
      });
   }

   return results;
}

class HQC_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"HQC-1", "HQC-3", "HQC-5"}; }

      std::string algo_name() const override { return "HQC"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::HQC_PublicKey>(raw_pk, Botan::HQC_Mode(keygen_params));
      }
};

}  // namespace

BOTAN_REGISTER_TEST("hqc", "hqc_kat_keygen", HQC_KAT_KeyGen_Tests);
BOTAN_REGISTER_TEST("hqc", "hqc_kat_decap", HQC_KAT_Decap_Tests);
BOTAN_REGISTER_TEST_FN("hqc", "hqc_roundtrips", test_hqc_roundtrips);
BOTAN_REGISTER_TEST("hqc", "hqc_keygen", HQC_Keygen_Tests);

#endif

}  // namespace Botan_Tests
