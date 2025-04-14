/*
* (C) 2024 Jack Lloyd
*     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/
#include "tests.h"
#if defined(BOTAN_HAS_OUNSWORTH)
   #include "test_pubkey.h"
   #include "test_rng.h"
   #include <botan/ounsworth.h>
   #include <botan/internal/fmt.h>

namespace Botan_Tests {

namespace {

std::vector<Botan::Ounsworth::Sub_Algo_Type> get_all_sub_algo_types() {
   return {
   #ifdef BOTAN_HAS_KYBER
      Botan::Ounsworth::Sub_Algo_Type::Kyber512_R3,
      Botan::Ounsworth::Sub_Algo_Type::Kyber768_R3,
      Botan::Ounsworth::Sub_Algo_Type::Kyber1024_R3,
   #endif
   #ifdef BOTAN_HAS_FRODOKEM_SHAKE
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM640_SHAKE,
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM976_SHAKE,
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM1344_SHAKE,
   #endif
   #ifdef BOTAN_HAS_FRODOKEM_AES
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM640_AES,
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM976_AES,
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM1344_AES,
   #endif
   #ifdef BOTAN_HAS_X25519
      Botan::Ounsworth::Sub_Algo_Type::X25519,
   #endif
   #ifdef BOTAN_HAS_X448
      Botan::Ounsworth::Sub_Algo_Type::X448,
   #endif
   #ifdef BOTAN_HAS_ECDH
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Secp192R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Secp224R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Secp256R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Secp384R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Secp521R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Brainpool256R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Brainpool384R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Brainpool512R1
   #endif
   };
}

std::vector<Botan::Ounsworth::Sub_Algo_Type> get_sub_algo_types_subset() {
   return {
   #ifdef BOTAN_HAS_KYBER
      Botan::Ounsworth::Sub_Algo_Type::Kyber512_R3,
   #endif
   #ifdef BOTAN_HAS_FRODOKEM_SHAKE
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM640_SHAKE,
   #endif
   #ifdef BOTAN_HAS_FRODOKEM_AES
      Botan::Ounsworth::Sub_Algo_Type::FrodoKEM640_AES,
   #endif
   #ifdef BOTAN_HAS_X25519
      Botan::Ounsworth::Sub_Algo_Type::X25519,
   #endif
   #ifdef BOTAN_HAS_X448
      Botan::Ounsworth::Sub_Algo_Type::X448,
   #endif
   #ifdef BOTAN_HAS_ECDH
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Secp192R1,
      Botan::Ounsworth::Sub_Algo_Type::ECDH_Brainpool256R1,
   #endif
   };
}

std::vector<Botan::Ounsworth::Sub_Algo_Type> get_tested_sub_algos() {
   if(Test::run_long_tests()) {
      return get_all_sub_algo_types();
   }
   return get_sub_algo_types_subset();
}

class Ounsworth_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         return {
   #if defined(BOTAN_HAS_KYBER) && defined(BOTAN_HAS_X25519)
            "OunsworthKEMCombiner/Kyber-768-r3/X25519/KMAC-256",
   #endif
   #if defined(BOTAN_HAS_KYBER) && defined(BOTAN_HAS_X448)
               "OunsworthKEMCombiner/Kyber-1024-r3/X448/KMAC-256",
   #endif
   #if defined(BOTAN_HAS_KYBER) && defined(BOTAN_HAS_ECDH)
               "OunsworthKEMCombiner/Kyber-512-r3/ECDH-secp256r1/KMAC-128",
               "OunsworthKEMCombiner/Kyber-768-r3/ECDH-secp384r1/KMAC-256",
               "OunsworthKEMCombiner/Kyber-1024-r3/ECDH-secp521r1/KMAC-256",
   #endif
   #if defined(BOTAN_HAS_FRODOKEM_SHAKE) && defined(BOTAN_HAS_ECDH)
               "OunsworthKEMCombiner/FrodoKEM-640-SHAKE/ECDH-brainpool256r1/KMAC-128",
               "OunsworthKEMCombiner/FrodoKEM-976-SHAKE/ECDH-brainpool384r1/KMAC-256",
               "OunsworthKEMCombiner/FrodoKEM-1344-SHAKE/ECDH-brainpool512r1/KMAC-256"
   #endif
         };
      }

      std::string algo_name() const override { return "OunsworthKEMCombiner"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /*provider*/,
                                                             std::span<const uint8_t> raw_key_bits) const override {
         Botan::AlgorithmIdentifier alg_id(Botan::OID::from_string(keygen_params),
                                           Botan::AlgorithmIdentifier::USE_EMPTY_PARAM);
         return std::make_unique<Botan::Ounsworth_PublicKey>(alg_id, raw_key_bits);
      }
};

BOTAN_REGISTER_TEST("ounsworth", "ounsworth_keygen", Ounsworth_Keygen_Tests);

class Ounsworth_Roundtrip_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("Ounsworth");

         // Test to combine all supported algorithms
         auto sub_algos = get_tested_sub_algos();
         if(sub_algos.size() < 2) {
            result.test_note("Skipping Ounsworth test as there are not enough sub algorithms");
            return {result};
         }

         for(Botan::Ounsworth::Kdf kdf : {Botan::Ounsworth::Kdf::Option::SHA3_256,
                                          Botan::Ounsworth::Kdf::Option::SHA3_512,
                                          Botan::Ounsworth::Kdf::Option::KMAC128,
                                          Botan::Ounsworth::Kdf::Option::KMAC256}) {
            std::vector<Botan::Ounsworth::PrivateKeyGenerationInfo> gen_infos;
            gen_infos.reserve(sub_algos.size());
            for(auto sub_algo : sub_algos) {
               gen_infos.push_back(Botan::Ounsworth::PrivateKeyGenerationInfo(sub_algo));
            }
            auto sk = std::make_unique<Botan::Ounsworth_PrivateKey>(Test::rng(), gen_infos, kdf);
            auto pk = sk->public_key();

            // Test keys
            result.test_eq("Public key bits", pk->public_key_bits(), sk->public_key_bits());

            auto enc = Botan::PK_KEM_Encryptor(*pk);
            auto dec = Botan::PK_KEM_Decryptor(*sk, rng());

            // Encapsulate and decapsulate
            auto [ct, ss] = Botan::KEM_Encapsulation::destructure(enc.encrypt(rng(), 32));
            auto ss_dec = dec.decrypt(ct, 32);

            result.test_eq("Encaps/Decaps roundtrip", ss, ss_dec);

            // Encapsulate with secret key
            {
               auto enc_sk = Botan::PK_KEM_Encryptor(*sk);
               auto [ct2, ss2] = Botan::KEM_Encapsulation::destructure(enc_sk.encrypt(rng(), 32));
               auto ss2_dec = dec.decrypt(ct2, 32);
               result.test_eq("Encaps with secret key (shared secret)", ss2_dec, ss2);
            }
            {
               // Encapsulate with fixedInfo (salt)
               auto salt = rng().random_vec(32);
               auto [ct2, ss2] = Botan::KEM_Encapsulation::destructure(enc.encrypt(rng(), 32, salt));
               auto ss2_dec = dec.decrypt(ct2, 32, salt);
               result.test_eq("Encaps with salt (shared secret)", ss2_dec, ss2);
            }
            // General tests
            {
               // Serialize and deserialize custom public key
               std::vector<Botan::Ounsworth::PublicKeyImportInfo> import_info;
               import_info.reserve(sub_algos.size());
               for(auto sub_algo : sub_algos) {
                  import_info.push_back(Botan::Ounsworth::PublicKeyImportInfo(sub_algo));
               }
               auto pk2 = Botan::Ounsworth_PublicKey(pk->public_key_bits(), import_info, kdf);
               result.test_eq("Public key bits (imported)", pk2.public_key_bits(), pk->public_key_bits());
            }
            {
               // Create a private and public key by passing the key objects
               std::vector<std::unique_ptr<Botan::Private_Key>> sks;
               std::vector<std::unique_ptr<Botan::Public_Key>> pks;

               for(const auto& gen_info : gen_infos) {
                  sks.push_back(gen_info.create_private_key(rng()));
                  pks.push_back(sks.back()->public_key());
               }
               Botan::Ounsworth_PublicKey pk2(std::move(pks), kdf);
               Botan::Ounsworth_PrivateKey sk2(std::move(sks), kdf);

               // Roundtrip
               auto enc2 = Botan::PK_KEM_Encryptor(pk2);
               auto dec2 = Botan::PK_KEM_Decryptor(sk2, rng());

               auto [ct2, ss2] = Botan::KEM_Encapsulation::destructure(enc2.encrypt(rng(), 32));
               auto ss2_dec = dec2.decrypt(ct2, 32);
               result.test_eq("Encaps/Decaps roundtrip (from key objects)", ss2, ss2_dec);
            }
            if(kdf.is_mac_based()) {
               // Encapsulate with context specific MAC key K
               std::string big_k = "My-Ounsworth-Domain-Separator";
               auto enc_with_k = Botan::PK_KEM_Encryptor(*pk, big_k);
               auto dec_with_k = Botan::PK_KEM_Decryptor(*sk, rng(), big_k);

               auto [ct2, ss2] = Botan::KEM_Encapsulation::destructure(enc_with_k.encrypt(rng(), 32));
               auto ss2_dec = dec_with_k.decrypt(ct2, 32);
               result.test_eq("Encaps with K (shared secret)", ss2_dec, ss2);
            }
         }
         return {result};
      }
};

BOTAN_REGISTER_TEST("ounsworth", "ounsworth_roundtrip", Ounsworth_Roundtrip_Test);

   #if defined(BOTAN_HAS_X25519) && defined(BOTAN_HAS_X448)
class Ounsworth_Kat_Test final : public Text_Based_Test {
   public:
      Ounsworth_Kat_Test() : Text_Based_Test("pubkey/ounsworth.vec", "sk,pk,rng_output,ct,fixed_info,K,kdf_input") {}

      Test::Result run_one_test(const std::string& /*params*/, const VarMap& vars) override {
         Test::Result result("Ounsworth KEM Combiner KAT");

         auto sk = vars.get_req_bin("sk");
         auto pk = vars.get_req_bin("pk");
         auto rng_output = vars.get_req_bin("rng_output");
         auto ct = vars.get_req_bin("ct");
         auto fixed_info = vars.get_req_bin("fixed_info");
         auto big_k = vars.get_req_str("K");
         auto kdf_input = vars.get_req_bin("kdf_input");

         Botan::Ounsworth::Kdf kdf(Botan::Ounsworth::Kdf::Option::KMAC128);

         const size_t desired_len = 32;

         Botan::Ounsworth_PrivateKey private_key(
            sk,
            {Botan::Ounsworth::Sub_Algo_Type::X25519, Botan::Ounsworth::Sub_Algo_Type::X448},
            Botan::Ounsworth::Kdf::Option::KMAC128);
         Fixed_Output_RNG fixed_rng(rng_output);

         Botan::PK_KEM_Encryptor enc(private_key, big_k);
         auto [enc_ct, enc_ss] = Botan::KEM_Encapsulation::destructure(enc.encrypt(fixed_rng, desired_len, fixed_info));

         result.test_eq("Encapsulated ciphertext", enc_ct, ct);

         Botan::PK_KEM_Decryptor dec(private_key, rng(), big_k);
         auto dec_ss = dec.decrypt(ct, desired_len, fixed_info);

         result.test_eq("Decapsulated shared secret", dec_ss, enc_ss);

         Botan::secure_vector<uint8_t> kdm_output(desired_len);
         auto mac = Botan::MessageAuthenticationCode::create(Botan::fmt("KMAC-128({})", desired_len * 8));
         std::vector<uint8_t> big_k_bytes(big_k.begin(), big_k.end());

         kdf.create_kdf_instance()->derive_key(kdm_output, kdf_input, big_k_bytes, fixed_info);
         result.test_eq("Compare ss to KDM output for known input", kdm_output, enc_ss);

         return result;
      }
};

BOTAN_REGISTER_TEST("ounsworth", "ounsworth_kat", Ounsworth_Kat_Test);
   #endif
}  // namespace
}  // namespace Botan_Tests
#endif  // BOTAN_HAS_OUNSWORTH
