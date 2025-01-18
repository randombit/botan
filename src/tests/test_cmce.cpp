/*
* Tests for Classic McEliece
*
* (C) 2023 Jack Lloyd
*     2023,2024 Fabian Albert, Amos Treiber - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "test_pubkey.h"
#include "test_pubkey_pqc.h"
#include "test_rng.h"
#include "tests.h"

#if defined(BOTAN_HAS_CLASSICMCELIECE)

   #include <botan/cmce.h>
   #include <botan/hash.h>
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
   #include <botan/internal/cmce_decaps.h>
   #include <botan/internal/cmce_encaps.h>
   #include <botan/internal/cmce_field_ordering.h>
   #include <botan/internal/cmce_gf.h>
   #include <botan/internal/cmce_keys_internal.h>
   #include <botan/internal/cmce_parameters.h>
   #include <botan/internal/cmce_poly.h>

namespace Botan_Tests {

namespace {

Botan::Classic_McEliece_Polynomial create_element_from_bytes(std::span<const uint8_t> bytes,
                                                             const Botan::Classic_McEliece_Polynomial_Ring& ring) {
   BOTAN_ARG_CHECK(bytes.size() == ring.degree() * 2, "Correct input size");
   std::vector<uint16_t> coef(ring.degree());
   Botan::load_le<uint16_t>(coef.data(), bytes.data(), ring.degree());

   std::vector<Botan::Classic_McEliece_GF> coeff_vec_gf;
   std::transform(coef.begin(), coef.end(), std::back_inserter(coeff_vec_gf), [&](auto& coeff) {
      return Botan::Classic_McEliece_GF(Botan::CmceGfElem(coeff), ring.poly_f());
   });
   return Botan::Classic_McEliece_Polynomial(coeff_vec_gf);
}

std::vector<Botan::Classic_McEliece_Parameter_Set> get_test_instances_all() {
   return {// All instances
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864f,

           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_460896,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_460896f,

           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128f,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pc,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6688128pcf,

           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119f,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pc,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf,

           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128f,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pc,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_8192128pcf};
}

std::vector<Botan::Classic_McEliece_Parameter_Set> get_test_instances_min() {
   return {// Testing with and without pc and f. Also testing 6960119 with m*t mod 8 != 0.
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864,
           Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_6960119pcf};
}

std::vector<Botan::Classic_McEliece_Parameter_Set> instances_to_test() {
   if(Test::run_long_tests()) {
      return get_test_instances_all();
   } else {
      return get_test_instances_min();
   }
}

bool skip_cmce_test(const std::string& params_str) {
   auto params = Botan::Classic_McEliece_Parameters::create(params_str);
   auto to_test = instances_to_test();
   return std::find(to_test.begin(), to_test.end(), params.parameter_set()) == to_test.end();
}
}  // namespace

class CMCE_Utility_Tests final : public Test {
   public:
      Test::Result expand_seed_test() {
         Test::Result result("Seed expansion");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864);

         // Created using the reference implementation
         auto seed = Botan::hex_decode_locked("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");

         auto exp_first_and_last_bytes = Botan::hex_decode(
            "543e2791fd98dbc1"    // first 8 bytes
            "d332a7c40776ca01");  // last 8 bytes

         size_t byte_length =
            (params.n() + params.sigma2() * params.q() + params.sigma1() * params.t() + params.ell()) / 8;

         auto rand = params.prg(seed)->output_stdvec(byte_length);
         rand.erase(rand.begin() + 8, rand.end() - 8);

         result.test_is_eq("Seed expansion", rand, exp_first_and_last_bytes);

         return result;
      }

      Test::Result irreducible_poly_gen_test() {
         Test::Result result("Irreducible Polynomial Generation");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864);

         // Created using the reference implementation
         auto random_bits = Botan::CmceIrreducibleBits(Botan::hex_decode(
            "d9b8bb962a3f9dac0f832d243def581e7d26f4028de1ff9cd168460e5050ab095a32a372b40d720bd5d75389a6b3f08fa1d13cec60a4b716d4d6c240f2f80cd3"
            "cbc76ae0dddca164c1130da185bd04e890f2256fb9f4754864811e14ea5a43b8b3612d59cecde1b2fdb6362659a0193d2b7d4b9d79aa1801dde3ca90dc300773"));

         auto exp_g = Botan::Classic_McEliece_Minimal_Polynomial::from_bytes(
            Botan::hex_decode(
               "8d00a50f520a0307b8007c06cb04b9073b0f4a0f800fb706a60f2a05910a670b460375091209fc060a09ab036c09e5085a0df90d3506b404a30fda041d09970f"
               "1206d000e00aac01c00dc80f490cd80b4108330c0208cf00d602450ec00a21079806eb093f00de015f052905560917081b09270c820af002000c34094504cd03"),
            params.poly_f());

         auto g = params.poly_ring().compute_minimal_polynomial(random_bits);
         result.confirm("Minimize polynomial successful", g.has_value());
         result.test_is_eq("Minimize polynomial", g.value().coef(), exp_g.coef());

         return result;
      }

      Test::Result gf_inv_test() {
         Test::Result result("GF inv test");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864);

         auto v = params.gf(Botan::CmceGfElem(42));
         auto v_inv = v.inv();
         result.test_is_eq("Control bits creation", (v * v_inv).elem(), Botan::CmceGfElem(1));

         return result;
      }

      Test::Result gf_poly_mul_test() {
         Test::Result result("GF Poly Mul");

         auto params =
            Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::ClassicMcEliece_348864);

         const auto& field = params.poly_ring();

         auto val1 = create_element_from_bytes(
            Botan::hex_decode(
               "bb02d40437094c0ae4034c00b10fed090a04850f660c3b0e110eb409810a86015b0f5804ca0e78089806e20b5b03aa0bc2020b05ea03710da902340c390f630b"
               "bc07a70db20b9e0ee4038905a00a09090a0521045e0a0706370b5a00050a4100480c4d0e8f00730692093701fe04650dbe0fd00702011a04910360023f04fb0a"),
            field);

         auto val2 = create_element_from_bytes(
            Botan::hex_decode(
               "060c630b170abb00020fef03e501020e89098108bf01f30dd30900000e0d3d0ca404ec01190760021f088c09b90b0a06a702d104500f0f02f00a580287010a09"
               "4e01490d270c73051800bc0af303b901b202b50321002802b903ce0ab40806083f0a2d06d002df0f260811005c02a10b300e5c0ba20d14045003c50f2f02de02"),
            field);

         auto exp_mul = create_element_from_bytes(
            Botan::hex_decode(
               "370d090b19008f0efb01f5011b04f9054b0d1f071d0457011e09cd0dfa093c004f08500e670abb0567090000f603770a3905bf044408b8025805930b25012201"
               "8d0a560e840d960d9d0a280d1d06fc08d5078c06fe0cb406d0061e02c6090507d20eb10cb90146085c042e030c0e1a07910fcd0c5f0fda066c0cee061d01f40f"),
            field);

         auto mul = field.multiply(val1, val2);  // val1 * val2;
         result.test_is_eq("GF multiplication", mul.coef(), exp_mul.coef());

         return result;
      }

      Test::Result rigged_rng_encryption_test() {
         // RNG that always returns zero bytes
         class All_Zero_RNG : public Botan::RandomNumberGenerator {
            public:
               void fill_bytes_with_input(std::span<uint8_t> output, std::span<const uint8_t> /* ignored */) override {
                  std::fill(output.begin(), output.end(), static_cast<uint8_t>(0));
               }

               std::string name() const override { return "All_Zero_RNG"; }

               bool accepts_input() const override { return false; }

               void clear() override {}

               bool is_seeded() const override { return true; }
         } rigged_rng;

         Test::Result result("No endless loop with rigged RNG");
         // Key creation should work even with a rigged RNG (PRNG is not used for key creation)
         auto private_key = Botan::create_private_key("ClassicMcEliece", rigged_rng, "348864f");
         if(!private_key) {
            result.test_failure("Key generation failed");
            return result;
         }
         auto enc = Botan::PK_KEM_Encryptor(*private_key, "Raw");
         result.test_throws("Many failed encryption attempts throws exception", [&] { enc.encrypt(rigged_rng); });

         return result;
      }

      std::vector<Test::Result> run() override {
         return {expand_seed_test(),
                 irreducible_poly_gen_test(),
                 gf_inv_test(),
                 gf_poly_mul_test(),
                 rigged_rng_encryption_test()};
      }
};

   #if defined(BOTAN_HAS_AES)
class CMCE_Invalid_Test : public Text_Based_Test {
   public:
      CMCE_Invalid_Test() :
            Text_Based_Test("pubkey/cmce_negative.vec", "seed,ct_invalid,ss_invalid", "ct_invalid_c1,ss_invalid_c1") {}

      Test::Result run_one_test(const std::string& params_str, const VarMap& vars) override {
         Test::Result result("CMCE Invalid Ciphertext Test");

         auto params = Botan::Classic_McEliece_Parameters::create(params_str);

         const auto kat_seed = Botan::lock(vars.get_req_bin("seed"));
         const auto ct_invalid = vars.get_req_bin("ct_invalid");
         const auto ref_ss_invalid = Botan::lock(vars.get_req_bin("ss_invalid"));

         const auto test_rng = std::make_unique<CTR_DRBG_AES256>(kat_seed);

         auto private_key = Botan::create_private_key("ClassicMcEliece", *test_rng, params_str);

         // Decaps an invalid ciphertext
         auto dec = Botan::PK_KEM_Decryptor(*private_key, *test_rng, "Raw");
         auto decaps_ct_invalid = dec.decrypt(ct_invalid);

         result.test_is_eq("Decaps an invalid encapsulated key", decaps_ct_invalid, ref_ss_invalid);

         if(params.is_pc()) {
            // For pc variants, additionally check the plaintext confirmation (pc) logic by
            // flipping a bit in the second part of the ciphertext (C_1 in pc). In this case
            // C_0 is decoded correctly, but pc will change the shared secret, since C_1' != C_1.
            const auto ct_invalid_c1 = vars.get_opt_bin("ct_invalid_c1");
            const auto ref_ss_invalid_c1 = Botan::lock(vars.get_opt_bin("ss_invalid_c1"));
            auto decaps_ct_invalid_c1 = dec.decrypt(ct_invalid_c1);

            result.test_is_eq("Decaps with invalid C_1 in pc", decaps_ct_invalid_c1, ref_ss_invalid_c1);
         }

         return result;
      }
};
   #endif  // BOTAN_HAS_AES

class CMCE_Generic_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         auto to_test = get_test_instances_min();

         std::vector<std::string> res;
         std::transform(to_test.begin(), to_test.end(), std::back_inserter(res), [](auto& param_set) {
            return param_set.to_string();
         });

         return res;
      }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /*provider*/,
                                                             std::span<const uint8_t> raw_key_bits) const override {
         return std::make_unique<Botan::Classic_McEliece_PublicKey>(
            raw_key_bits, Botan::Classic_McEliece_Parameter_Set::from_string(keygen_params));
      }

      std::string algo_name() const override { return "ClassicMcEliece"; }
};

class Classic_McEliece_KAT_Tests final : public Botan_Tests::PK_PQC_KEM_KAT_Test {
   public:
      Classic_McEliece_KAT_Tests() : PK_PQC_KEM_KAT_Test("ClassicMcEliece", "pubkey/cmce_kat_hashed.vec") {}

   private:
      Botan::Classic_McEliece_Parameters get_params(const std::string& header) const {
         return Botan::Classic_McEliece_Parameters::create(Botan::Classic_McEliece_Parameter_Set::from_string(header));
      }

      bool is_available(const std::string& alg_name) const final { return !skip_cmce_test(alg_name); }

      std::vector<uint8_t> map_value(const std::string&, std::span<const uint8_t> value, VarType var_type) const final {
         if(var_type == VarType::Ciphertext || var_type == VarType::SharedSecret) {
            return {value.begin(), value.end()};
         }
         auto hash = Botan::HashFunction::create_or_throw("SHAKE-256(512)");
         return hash->process<std::vector<uint8_t>>(value);
      }

      Fixed_Output_RNG rng_for_keygen(const std::string&, Botan::RandomNumberGenerator& rng) const final {
         const auto seed = rng.random_vec(Botan::Classic_McEliece_Parameters::seed_len());
         return Fixed_Output_RNG(seed);
      }

      Fixed_Output_RNG rng_for_encapsulation(const std::string& alg_name,
                                             Botan::RandomNumberGenerator& rng) const final {
         // There is no way to tell exacly how much randomness is
         // needed for encapsulation (rejection sampling)
         // For testing we use a number that fits for all test cases
         auto params = get_params(alg_name);
         const size_t max_attempts = 100;
         const size_t bits_per_attempt = (params.sigma1() / 8) * params.tau();

         std::vector<uint8_t> rand_buffer;
         for(size_t attempt = 0; attempt < max_attempts; ++attempt) {
            auto random_bytes = rng.random_vec(bits_per_attempt);
            rand_buffer.insert(rand_buffer.end(), random_bytes.begin(), random_bytes.end());
         }

         return Fixed_Output_RNG(rand_buffer);
      }

      void inspect_rng_after_encaps(const std::string&, const Fixed_Output_RNG&, Test::Result&) const final {
         // Encaps uses any number of random bytes, so we cannot check the RNG
      }
};

BOTAN_REGISTER_TEST("cmce", "cmce_utility", CMCE_Utility_Tests);
BOTAN_REGISTER_TEST("cmce", "cmce_generic_keygen", CMCE_Generic_Keygen_Tests);
BOTAN_REGISTER_TEST("cmce", "cmce_generic_kat", Classic_McEliece_KAT_Tests);
   #if defined(BOTAN_HAS_AES)
BOTAN_REGISTER_TEST("cmce", "cmce_invalid", CMCE_Invalid_Test);
   #endif

}  // namespace Botan_Tests

#endif  // BOTAN_HAS_CLASSICMCELIECE
