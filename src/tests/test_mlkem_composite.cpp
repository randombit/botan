
/*
 * ML-KEM Composite KEM tests
 * (C) 2026 Falko Strenzke, MTG AG
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include "test_pubkey.h"
#include "tests.h"

#if defined(BOTAN_HAS_MLKEM_COMPOSITE)
   #include <botan/base64.h>
   #include <botan/ber_dec.h>
   #include <botan/exceptn.h>
   #include <botan/hash.h>
   #include <botan/hex.h>
   #include <botan/mlkem_comp.h>
   #include <botan/mlkem_comp_parameters.h>
   #include <botan/pk_algs.h>
   #include <botan/pk_keys.h>
   #include <botan/pkcs8.h>
   #include <botan/pubkey.h>
   #include <botan/rng.h>
   #include <botan/secmem.h>

   #if defined(BOTAN_HAS_X509_CERTIFICATES)
      #include <botan/pkix_enums.h>
      #include <botan/x509cert.h>
   #endif

#endif

#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#if defined(BOTAN_HAS_MLKEM_COMPOSITE)
namespace Botan_Tests {

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
namespace {
std::vector<uint8_t> decode_var_base64(const VarMap& vars, std::string_view var) {
   const auto var_b64 = vars.get_req_str(var);
   const auto var_sv = Botan::base64_decode(var_b64);
   return std::vector<uint8_t>(var_sv.begin(), var_sv.end());
}

enum mlkem_comp_artifact_e : uint8_t { Publickey, Privatekey, Ciphertext };

enum artifact_modification_e : uint8_t {
   truncate_before_boundary,
   truncate_on_boundary,
   truncate_after_boundary,
   manipulate_mlkem,
   manipulate_traditional
};

std::vector<uint8_t> manipulate_mlkem_comp_artifact(std::span<const uint8_t> in,
                                                    mlkem_comp_artifact_e artifact_type,
                                                    const Botan::MLKEM_Composite_Param& param,
                                                    artifact_modification_e mod_type,
                                                    size_t index_offset_for_manipulation,
                                                    uint8_t xor_for_manipulation) {
   const std::string id_str = param.id_str();
   size_t index = 0;
   xor_for_manipulation = (xor_for_manipulation == 0) ? 1 : xor_for_manipulation;
   if(artifact_type == mlkem_comp_artifact_e::Privatekey) {
      index = 64;
   } else if(id_str.find("MLKEM768") != std::string::npos) {
      switch(artifact_type) {
         case Publickey:
            index = 1184;
            break;
         case Ciphertext:
            index = 1088;
            break;
         default:
            throw Test_Error("error in test code");
      }
   } else if(id_str.find("MLKEM1024") != std::string::npos) {
      index = 1568;  // for both Publickey and Ciphertext
   }
   const size_t truncation_offset = index_offset_for_manipulation;
   std::vector<uint8_t> result(in.begin(), in.end());
   switch(mod_type) {
      case truncate_before_boundary:
         return std::vector<uint8_t>(in.begin(), in.begin() + index - truncation_offset);
      case truncate_on_boundary:
         return std::vector<uint8_t>(in.begin(), in.begin() + index);
      case truncate_after_boundary:
         return std::vector<uint8_t>(in.begin(), in.begin() + index + truncation_offset);
      case manipulate_mlkem:
         result[10] ^= xor_for_manipulation;
         return result;
      case manipulate_traditional:
         result[index + 10] ^= xor_for_manipulation;
         return result;
   }
   throw Test_Error("unreachable code");
}

std::vector<std::vector<uint8_t>> some_manipulations(std::span<const uint8_t> in,
                                                     mlkem_comp_artifact_e artifact_type,
                                                     const Botan::MLKEM_Composite_Param& param,
                                                     bool run_long_tests) {
   static const artifact_modification_e list_of_mods[] = {truncate_before_boundary,
                                                          truncate_on_boundary,
                                                          truncate_after_boundary,
                                                          manipulate_mlkem,
                                                          manipulate_traditional};
   std::vector<std::vector<uint8_t>> result;
   for(auto mod : list_of_mods) {
      result.push_back(manipulate_mlkem_comp_artifact(in, artifact_type, param, mod, 10, 2));
      if(run_long_tests) {
         result.push_back(manipulate_mlkem_comp_artifact(in, artifact_type, param, mod, 1, 4));
         result.push_back(manipulate_mlkem_comp_artifact(in, artifact_type, param, mod, 2, 8));
         result.push_back(manipulate_mlkem_comp_artifact(in, artifact_type, param, mod, 3, 8));
         result.push_back(manipulate_mlkem_comp_artifact(in, artifact_type, param, mod, 8, 0x0F));
         result.push_back(manipulate_mlkem_comp_artifact(in, artifact_type, param, mod, 20, 0xFE));
      }
   }
   return result;
}

void encrypt_and_decrypt(const Botan::Private_Key& privkey,
                         const Botan::Public_Key& pubkey,
                         Botan::RandomNumberGenerator& rng,
                         Test::Result& test_result,
                         std::string_view test_context) {
   Botan::PK_KEM_Decryptor decryptor(privkey, rng, "", "");
   const Botan::secure_vector<uint8_t> shared_key(32);

   Botan::PK_KEM_Encryptor encryptor(pubkey, "", "");
   Botan::secure_vector<uint8_t> ss_rt(32);
   Botan::secure_vector<uint8_t> ct_rt(encryptor.encapsulated_key_length());
   encryptor.encrypt(ct_rt, ss_rt, rng, 32);
   Botan::secure_vector<uint8_t> ss_rt_2(32);
   decryptor.decrypt(ss_rt_2, ct_rt, 32);
   test_result.test_bin_eq(test_context, ss_rt, ss_rt_2);
}
}  // namespace

class MLKEM_Composite_KAT_Tests : public Text_Based_Test {
   public:
      MLKEM_Composite_KAT_Tests() : Text_Based_Test("pubkey/mlkem_composite.vec", "tcId,ek,x5c,dk,dk_pkcs8,c,k") {}

      Test::Result run_one_test(const std::string& name, const VarMap& vars) override {
         bool pubkey_valid = true;
         bool privkey_valid = true;
         bool exc_during_pubkey_decoding = false;
         bool exc_during_privkey_decoding = false;
         if(name.ends_with("pubkey-invalid")) {
            pubkey_valid = false;
         }
         if(name.ends_with("privkey-invalid")) {
            privkey_valid = false;
         }
         Test::Result result(name);
         auto tcId = vars.get_req_str("tcId");
         if(tcId.starts_with("id-")) {
            tcId = tcId.substr(3);
         }

         auto rng = Test::new_rng(name);
         const auto pk = decode_var_base64(vars, "ek");
         const auto sk = decode_var_base64(vars, "dk");

         const auto ct_vec = decode_var_base64(vars, "c");
         const auto ss_vec = decode_var_base64(vars, "k");

         const auto comp_parm_opt = Botan::MLKEM_Composite_Param::from_id_str(tcId);
         // support of composite algorithms also depends on whether Botan's build configuration supports the individual  traditional component algorithm.
         if(!comp_parm_opt.has_value() or !comp_parm_opt.value().is_supported()) {
            return result;
         }

         auto comp_parm = comp_parm_opt.value();

         std::unique_ptr<Botan::Public_Key> pubkey;
         std::unique_ptr<Botan::Private_Key> privkey;

         try {
            privkey = std::make_unique<Botan::MLKEM_Composite_PrivateKey>(comp_parm.id(), sk);
         } catch(const Botan::Exception&) {
            exc_during_privkey_decoding = true;
         }
         result.test_bool_eq("privkey decoding OK", !exc_during_privkey_decoding, privkey_valid);
         if(exc_during_privkey_decoding) {
            return result;
         }

         try {
            pubkey = std::make_unique<Botan::MLKEM_Composite_PublicKey>(comp_parm.id(), pk);
         } catch(const Botan::Exception&) {
            exc_during_pubkey_decoding = true;
         }
         result.test_bool_eq("pubkey decoding OK", !exc_during_pubkey_decoding, pubkey_valid);
         if(exc_during_pubkey_decoding) {
            return result;
         }
         const size_t limit = ((options().run_long_tests() == true) ? 100 : 1);
         for(size_t i = 0; i < limit; i++) {
            Botan::PK_KEM_Decryptor decryptor(*privkey, *rng, "", "");
            {
               Botan::secure_vector<uint8_t> shared_key(32);
               decryptor.decrypt(shared_key, ct_vec, shared_key.size());
               result.test_bin_eq("decryption of valid KAT ciphertext", shared_key, ss_vec);

               Botan::PK_KEM_Encryptor encryptor(*pubkey, "", "");
               Botan::secure_vector<uint8_t> ss_rt(32);
               Botan::secure_vector<uint8_t> ct_rt(ct_vec.size());
               encryptor.encrypt(ct_rt, ss_rt, *rng, 32);
               Botan::secure_vector<uint8_t> ss_rt_2(32);
               decryptor.decrypt(ss_rt_2, ct_rt, 32);
               result.test_bin_eq(
                  std::string("decryption of valid roundtrip ciphertext (#") + std::to_string(i) + ")", ss_rt, ss_rt_2);
            }

      #if defined(BOTAN_HAS_X509_CERTIFICATES)
            const std::vector<uint8_t> x5c = decode_var_base64(vars, "x5c");
            std::unique_ptr<Botan::Public_Key> pub_key_from_cert;
            if(comp_parm_opt.has_value() and comp_parm_opt.value().is_supported()) {
               const Botan::X509_Certificate cert(x5c);
               pub_key_from_cert = cert.subject_public_key();
               Botan::PK_KEM_Encryptor encryptor_cert(*pub_key_from_cert, "", "");
               Botan::secure_vector<uint8_t> ss_rt_crt(32);
               Botan::secure_vector<uint8_t> ct_rt_crt(ct_vec.size());
               encryptor_cert.encrypt(ct_rt_crt, ss_rt_crt, *rng, 32);
               Botan::secure_vector<uint8_t> ss_rt_2_crt(32);
               decryptor.decrypt(ss_rt_2_crt, ct_rt_crt, 32);
               result.test_bin_eq(
                  std::string(
                     "decryption of valid roundtrip ciphertext encrypted with public key from certificate (#") +
                     std::to_string(i) + ")",
                  ss_rt_crt,
                  ss_rt_2_crt);
            }

      #endif
         }

         return result;
      }

   private:
};

BOTAN_REGISTER_TEST("pubkey", "mlkem_composite_kat", MLKEM_Composite_KAT_Tests);

class MLKEM_Composite_RT_Tests : public Test {
   public:
      static Test::Result run_detail_test(Botan::MLKEM_Composite_Param::id_t id) {
         auto param = Botan::MLKEM_Composite_Param::from_id_supported_or_throw(id);
         const std::string test_name = std::string("MLKEM_Composite_round_trip_") + param.id_str();
         Test::Result result(test_name);

         auto rng = Test::new_rng(test_name);
         if(!param.is_supported()) {
            result.test_throws<Botan::Not_Implemented>("create MLKEM-composite private key for non-supported parameter",
                                                       [&]() { Botan::create_private_key(param.id_str(), *rng); });
            return result;
         }

         const uint64_t rep_cnt = options().run_long_tests() ? 20 : 1;
         for(uint64_t i = 0; i < rep_cnt; i++) {
            auto priv_key_generated =
               Botan::create_private_key(Botan::MLKEM_Composite_Param::generic_algo_name, *rng, param.id_str());
            if(nullptr == priv_key_generated) {
               result.test_bool_eq("generated private key non-null", false, true);
            } else {
               auto pub_key_generated = priv_key_generated->public_key();
               if(nullptr == pub_key_generated) {
                  result.test_bool_eq("generated pub key key non-null", false, true);
               } else {
                  encrypt_and_decrypt(
                     *priv_key_generated, *pub_key_generated, *rng, result, "produced with generated key");
               }
            }
            Botan::secure_vector<uint8_t> private_enc = priv_key_generated->private_key_bits();
            if(test_name.find("ECDH") != std::string::npos) {
               check_encoded_ecdh_private_key(private_enc, result);
            }
            std::vector<uint8_t> public_enc = priv_key_generated->public_key_bits();
            const Botan::MLKEM_Composite_PrivateKey priv_key_redec(priv_key_generated->algorithm_identifier(),
                                                                   private_enc);
            const Botan::MLKEM_Composite_PublicKey pub_key_redec(priv_key_generated->algorithm_identifier(),
                                                                 public_enc);
            encrypt_and_decrypt(priv_key_redec, pub_key_redec, *rng, result, "produced with re-decoded key");
         }
         return result;
      }

      std::vector<Test::Result> run() override {
         auto all_params = Botan::MLKEM_Composite_Param::all_supported_param_sets();
         std::vector<Test::Result> result;
         result.reserve(all_params.size());
         for(const auto& param : all_params) {
            result.push_back(run_detail_test(param.id()));
         }
         return result;
      }

   private:
      // possibly merge with same routine for MLDSA-composite:
      static void check_encoded_ecdh_private_key(std::span<uint8_t> composite_private_key, Test::Result& result) {
         const size_t mlkem_private_key_size = 64;
         Botan::OID key_parameters;
         Botan::secure_vector<uint8_t> private_key_bits;
         const Botan::secure_vector<uint8_t> public_key_bits;
         if(composite_private_key.size() < 33) {
            result.test_failure("encoded ECDH component private key is too short");
         }
         const std::vector<uint8_t> ecc_private_enc(composite_private_key.begin() + mlkem_private_key_size,
                                                    composite_private_key.end());
         try {
            Botan::BER_Decoder(ecc_private_enc)
               .start_sequence()
               .decode_and_check<size_t>(1, "Unknown version code for ECC key")
               .decode(private_key_bits, Botan::ASN1_Type::OctetString)
               .decode_optional(key_parameters, Botan::ASN1_Type(0), Botan::ASN1_Class::ExplicitContextSpecific)
               .end_cons()
               .verify_end();
         } catch(const Botan::Exception& e) {
            result.test_failure(std::string("verify ECC private format decoding: ") + e.what());
         }
      }
};

BOTAN_REGISTER_TEST("pubkey", "mlkem_composite_roundtrips", MLKEM_Composite_RT_Tests);

class MLKEM_Composite_KAT_Invalid_Tests : public Text_Based_Test {
   public:
      MLKEM_Composite_KAT_Invalid_Tests() :
            Text_Based_Test("pubkey/mlkem_composite.vec", "tcId,ek,x5c,dk,dk_pkcs8,c,k") {}

      Test::Result run_one_test(const std::string& name, const VarMap& vars) override {
         const auto pk = decode_var_base64(vars, "ek");
         const auto sk = decode_var_base64(vars, "dk");

         const auto ct_vec = decode_var_base64(vars, "c");
         const auto ss_vec = decode_var_base64(vars, "k");

         Test::Result result(name);
         auto tcId = vars.get_req_str("tcId");
         if(tcId.starts_with("id-")) {
            tcId = tcId.substr(3);
         }

         auto rng = Test::new_rng(name);
         const auto comp_parm_opt = Botan::MLKEM_Composite_Param::from_id_str(tcId);
         // support of composite algorithms also depends on whether Botan's build configuration supports the individual  traditional component algorithm.
         if(!comp_parm_opt.has_value() or !comp_parm_opt.value().is_supported()) {
            return result;
         }

         auto comp_parm = comp_parm_opt.value();

         const std::vector<std::vector<uint8_t>> invalid_private_keys =
            some_manipulations(sk, mlkem_comp_artifact_e::Privatekey, comp_parm, options().run_long_tests());
         const std::vector<std::vector<uint8_t>> invalid_public_keys =
            some_manipulations(pk, mlkem_comp_artifact_e::Publickey, comp_parm, options().run_long_tests());
         const std::vector<std::vector<uint8_t>> invalid_ciphertexts =
            some_manipulations(ct_vec, mlkem_comp_artifact_e::Ciphertext, comp_parm, options().run_long_tests());
         for(const auto& invalid_dk : invalid_private_keys) {
            execute_invalid_test(comp_parm, *rng, invalid_dk, pk, ct_vec, ss_vec, false, true, true, result);
         }
         for(const auto& invalid_ek : invalid_public_keys) {
            execute_invalid_test(comp_parm, *rng, sk, invalid_ek, ct_vec, ss_vec, true, false, true, result);
         }
         for(const auto& invalid_ct : invalid_ciphertexts) {
            execute_invalid_test(comp_parm, *rng, sk, pk, invalid_ct, ss_vec, true, true, false, result);
         }
         return result;
      }

   private:
      void execute_invalid_test(const Botan::MLKEM_Composite_Param& comp_param,
                                Botan::RandomNumberGenerator& rng,
                                std::span<const uint8_t> private_key,
                                std::span<const uint8_t> public_key,
                                std::span<const uint8_t> ciphertext,
                                std::span<const uint8_t> expected_ss,
                                bool privkey_valid,
                                bool pubkey_valid,
                                bool ciphertext_valid,
                                Test::Result& result) {
         std::unique_ptr<Botan::Public_Key> pubkey;
         std::unique_ptr<Botan::Private_Key> privkey;

         try {
            privkey = std::make_unique<Botan::MLKEM_Composite_PrivateKey>(comp_param.id(), private_key);
         } catch(const Botan::Exception&) {
            // No need to check if the private key was invalid, since this case is covered by the normal (positive) KAT tests
            result.test_success("exception during private key decoding");
            return;
         }

         try {
            pubkey = std::make_unique<Botan::MLKEM_Composite_PublicKey>(comp_param.id(), public_key);
         } catch(const Botan::Exception&) {
            // No need to check if the public key was invalid, since this case is covered by the normal (positive) KAT tests
            result.test_success("exception during public key decoding");
            return;
         }
         // It can happen that the invalid keys only take effect during the operations.
         bool exc_during_decryption = false;
         Botan::PK_KEM_Decryptor decryptor(*privkey, rng, "", "");
         Botan::secure_vector<uint8_t> shared_key(32);
         try {
            decryptor.decrypt(shared_key, ciphertext, shared_key.size());
         } catch(const Botan::Exception&) {
            exc_during_decryption = true;
         }
         if(exc_during_decryption or
            !std::equal(shared_key.begin(), shared_key.end(), expected_ss.begin(), expected_ss.end())) {
            result.test_is_true(
               "decryption failure due to exception or implicit rejection during decapsulation as expected for invalid private key or ciphertext",
               !privkey_valid or !ciphertext_valid);
            return;
         } else {
            // successful decryption. the manipulated public key was not involved in this test.
            result.test_is_true("decryption went OK expectedly for valid private key and valid ciphertext",
                                privkey_valid and ciphertext_valid);
            // we continue in this case to test the encapsulation.
         }

         //result.test_bin_eq("decryption of valid KAT ciphertext", shared_key, ss_vec);

         Botan::PK_KEM_Encryptor encryptor(*pubkey, "", "");
         Botan::secure_vector<uint8_t> ss_rt(32);
         Botan::secure_vector<uint8_t> ct_rt(encryptor.encapsulated_key_length());
         try {
            encryptor.encrypt(ct_rt, ss_rt, rng, 32);
         } catch(Botan::Exception&) {
            result.test_is_true("error during encryption for invalid public key", !pubkey_valid);
            return;
         }
         Botan::secure_vector<uint8_t> ss_rt_2(32);
         try {
            decryptor.decrypt(ss_rt_2, ct_rt, 32);
         } catch(Botan::Exception&) {
            result.test_is_true("error during decryption for invalid public key", !pubkey_valid);
            return;
         }
         result.test_bin_ne("decryption of roundtrip ciphertext for invalid public key", ss_rt, ss_rt_2);
      }
};

BOTAN_REGISTER_TEST("pubkey", "mlkem_composite_kat_invalid", MLKEM_Composite_KAT_Invalid_Tests);

   #endif
}  // namespace Botan_Tests
#endif
