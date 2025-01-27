/*
* (C) 2016 Philipp Weber
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECIES)
   #include <botan/ecdh.h>
   #include <botan/ecies.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECIES) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_MODE_CBC)

using Flags = Botan::ECIES_Flags;

Botan::EC_Point_Format get_compression_type(const std::string& format) {
   if(format == "uncompressed") {
      return Botan::EC_Point_Format::Uncompressed;
   } else if(format == "compressed") {
      return Botan::EC_Point_Format::Compressed;
   } else if(format == "hybrid") {
      return Botan::EC_Point_Format::Hybrid;
   }
   throw Botan::Invalid_Argument("invalid compression format");
}

Flags ecies_flags(bool cofactor_mode, bool old_cofactor_mode, bool check_mode, bool single_hash_mode) {
   return (cofactor_mode ? Flags::CofactorMode : Flags::None) |
          (single_hash_mode ? Flags::SingleHashMode : Flags::None) |
          (old_cofactor_mode ? Flags::OldCofactorMode : Flags::None) | (check_mode ? Flags::CheckMode : Flags::None);
}

void check_encrypt_decrypt(Test::Result& result,
                           const Botan::ECDH_PrivateKey& private_key,
                           const Botan::ECDH_PrivateKey& other_private_key,
                           const Botan::ECIES_System_Params& ecies_params,
                           const Botan::InitializationVector& iv,
                           const std::string& label,
                           const std::vector<uint8_t>& plaintext,
                           const std::vector<uint8_t>& ciphertext,
                           Botan::RandomNumberGenerator& rng) {
   try {
      Botan::ECIES_Encryptor ecies_enc(private_key, ecies_params, rng);
      ecies_enc.set_other_key(
         Botan::EC_AffinePoint(other_private_key.domain(), other_private_key.raw_public_key_bits()));
      Botan::ECIES_Decryptor ecies_dec(other_private_key, ecies_params, rng);
      if(!iv.bits_of().empty()) {
         ecies_enc.set_initialization_vector(iv);
         ecies_dec.set_initialization_vector(iv);
      }
      if(!label.empty()) {
         ecies_enc.set_label(label);
         ecies_dec.set_label(label);
      }

      const std::vector<uint8_t> encrypted = ecies_enc.encrypt(plaintext, rng);
      if(!ciphertext.empty()) {
         result.test_eq("encrypted data", encrypted, ciphertext);
      }
      const Botan::secure_vector<uint8_t> decrypted = ecies_dec.decrypt(encrypted);
      result.test_eq("decrypted data equals plaintext", decrypted, plaintext);

      std::vector<uint8_t> invalid_encrypted = encrypted;
      uint8_t& last_byte = invalid_encrypted[invalid_encrypted.size() - 1];
      last_byte = ~last_byte;
      result.test_throws("throw on invalid ciphertext",
                         [&ecies_dec, &invalid_encrypted] { ecies_dec.decrypt(invalid_encrypted); });
   } catch(Botan::Lookup_Error& e) {
      result.test_note(std::string("Test not executed: ") + e.what());
   }
}

void check_encrypt_decrypt(Test::Result& result,
                           const Botan::ECDH_PrivateKey& private_key,
                           const Botan::ECDH_PrivateKey& other_private_key,
                           const Botan::ECIES_System_Params& ecies_params,
                           size_t iv_length,
                           Botan::RandomNumberGenerator& rng) {
   const std::vector<uint8_t> plaintext{1, 2, 3};
   check_encrypt_decrypt(result,
                         private_key,
                         other_private_key,
                         ecies_params,
                         Botan::InitializationVector(std::vector<uint8_t>(iv_length, 0)),
                         "",
                         plaintext,
                         std::vector<uint8_t>(),
                         rng);
}

   #if defined(BOTAN_HAS_KDF1_18033) && defined(BOTAN_HAS_SHA1)

class ECIES_ISO_Tests final : public Text_Based_Test {
   public:
      ECIES_ISO_Tests() : Text_Based_Test("pubkey/ecies-18033.vec", "format,p,a,b,Order,Gx,Gy,Oid,hx,hy,x,r,C0,K") {}

      bool clear_between_callbacks() const override { return false; }

      bool skip_this_test(const std::string&, const VarMap&) override {
         return !Botan::EC_Group::supports_application_specific_group();
      }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("ECIES-ISO");

         // get test vectors defined by ISO 18033
         const Botan::EC_Point_Format compression_type = get_compression_type(vars.get_req_str("format"));
         const Botan::BigInt p = vars.get_req_bn("p");
         const Botan::BigInt a = vars.get_req_bn("a");
         const Botan::BigInt b = vars.get_req_bn("b");
         const Botan::BigInt order = vars.get_req_bn("Order");  // order
         const Botan::BigInt gx = vars.get_req_bn("Gx");        // base point x
         const Botan::BigInt gy = vars.get_req_bn("Gy");        // base point y
         const Botan::OID oid(vars.get_req_str("Oid"));
         const Botan::BigInt hx = vars.get_req_bn("hx");          // x of public point of bob
         const Botan::BigInt hy = vars.get_req_bn("hy");          // y of public point of bob
         const Botan::BigInt x = vars.get_req_bn("x");            // private key of bob
         const Botan::BigInt r = vars.get_req_bn("r");            // (ephemeral) private key of alice
         const std::vector<uint8_t> c0 = vars.get_req_bin("C0");  // expected encoded (ephemeral) public key
         const std::vector<uint8_t> k = vars.get_req_bin("K");    // expected derived secret

         const Botan::EC_Group domain(oid, p, a, b, gx, gy, order);

         // keys of bob
         const Botan::ECDH_PrivateKey other_private_key(this->rng(), domain, x);
         const auto other_public_key_point = Botan::EC_AffinePoint::from_bigint_xy(domain, hx, hy).value();
         const Botan::ECDH_PublicKey other_public_key(domain, other_public_key_point);

         // (ephemeral) keys of alice
         const Botan::ECDH_PrivateKey eph_private_key(this->rng(), domain, r);
         const auto eph_public_key_bin = eph_private_key.public_value(compression_type);
         result.test_eq("encoded (ephemeral) public key", eph_public_key_bin, c0);

         // test secret derivation: ISO 18033 test vectors use KDF1 from ISO 18033
         // no cofactor-/oldcofactor-/singlehash-/check-mode and 128 byte secret length
         Botan::ECIES_KA_Params ka_params(
            eph_private_key.domain(), "KDF1-18033(SHA-1)", 128, compression_type, Flags::None);
         const Botan::ECIES_KA_Operation ka(eph_private_key, ka_params, true, this->rng());
         const Botan::SymmetricKey secret_key = ka.derive_secret(eph_public_key_bin, other_public_key_point);
         result.test_eq("derived secret key", secret_key.bits_of(), k);

         // test encryption / decryption

         for(auto comp_type : {Botan::EC_Point_Format::Uncompressed,
                               Botan::EC_Point_Format::Compressed,
                               Botan::EC_Point_Format::Hybrid}) {
            for(bool cofactor_mode : {true, false}) {
               for(bool single_hash_mode : {true, false}) {
                  for(bool old_cofactor_mode : {true, false}) {
                     for(bool check_mode : {true, false}) {
                        Flags flags = ecies_flags(cofactor_mode, old_cofactor_mode, check_mode, single_hash_mode);

                        if(size_t(cofactor_mode) + size_t(check_mode) + size_t(old_cofactor_mode) > 1) {
                           auto onThrow = [&]() {
                              Botan::ECIES_System_Params(eph_private_key.domain(),
                                                         "KDF2(SHA-1)",
                                                         "AES-256/CBC",
                                                         32,
                                                         "HMAC(SHA-1)",
                                                         20,
                                                         comp_type,
                                                         flags);
                           };
                           result.test_throws("throw on invalid ECIES_Flags", onThrow);
                           continue;
                        }

                        Botan::ECIES_System_Params ecies_params(eph_private_key.domain(),
                                                                "KDF2(SHA-1)",
                                                                "AES-256/CBC",
                                                                32,
                                                                "HMAC(SHA-1)",
                                                                20,
                                                                comp_type,
                                                                flags);
                        check_encrypt_decrypt(
                           result, eph_private_key, other_private_key, ecies_params, 16, this->rng());
                     }
                  }
               }
            }
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecies_iso", ECIES_ISO_Tests);

   #endif

class ECIES_Tests final : public Text_Based_Test {
   public:
      ECIES_Tests() :
            Text_Based_Test("pubkey/ecies.vec",
                            "Curve,PrivateKey,OtherPrivateKey,Kdf,Dem,DemKeyLen,Mac,MacKeyLen,Format,"
                            "CofactorMode,OldCofactorMode,CheckMode,SingleHashMode,Label,Plaintext,Ciphertext",
                            "Iv") {}

      bool skip_this_test(const std::string&, const VarMap& vars) override {
         const auto curve = vars.get_req_str("Curve");

         if(curve.starts_with("-----BEGIN EC PARAMETERS")) {
            return !Botan::EC_Group::supports_application_specific_group();
         } else {
            return !Botan::EC_Group::supports_named_group(curve);
         }
      }

      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) override {
         Test::Result result("ECIES");

         const std::string curve = vars.get_req_str("Curve");
         const Botan::BigInt private_key_value = vars.get_req_bn("PrivateKey");
         const Botan::BigInt other_private_key_value = vars.get_req_bn("OtherPrivateKey");
         const std::string kdf = vars.get_req_str("Kdf");
         const std::string dem = vars.get_req_str("Dem");
         const size_t dem_key_len = vars.get_req_sz("DemKeyLen");
         const Botan::InitializationVector iv = Botan::InitializationVector(vars.get_opt_bin("Iv"));
         const std::string mac = vars.get_req_str("Mac");
         const size_t mac_key_len = vars.get_req_sz("MacKeyLen");
         const Botan::EC_Point_Format compression_type = get_compression_type(vars.get_req_str("Format"));
         const bool cofactor_mode = vars.get_req_sz("CofactorMode") != 0;
         const bool old_cofactor_mode = vars.get_req_sz("OldCofactorMode") != 0;
         const bool check_mode = vars.get_req_sz("CheckMode") != 0;
         const bool single_hash_mode = vars.get_req_sz("SingleHashMode") != 0;
         const std::string label = vars.get_req_str("Label");
         const std::vector<uint8_t> plaintext = vars.get_req_bin("Plaintext");
         const std::vector<uint8_t> ciphertext = vars.get_req_bin("Ciphertext");

         const Flags flags = ecies_flags(cofactor_mode, old_cofactor_mode, check_mode, single_hash_mode);

         // This test uses a mix of named curves plus PEM, so we use the deprecated constructor atm
         const Botan::EC_Group domain(curve);
         const Botan::ECDH_PrivateKey private_key(this->rng(), domain, private_key_value);
         const Botan::ECDH_PrivateKey other_private_key(this->rng(), domain, other_private_key_value);

         const Botan::ECIES_System_Params ecies_params(
            private_key.domain(), kdf, dem, dem_key_len, mac, mac_key_len, compression_type, flags);
         check_encrypt_decrypt(
            result, private_key, other_private_key, ecies_params, iv, label, plaintext, ciphertext, this->rng());

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecies", ECIES_Tests);

   #if defined(BOTAN_HAS_KDF1_18033) && defined(BOTAN_HAS_HMAC) && defined(BOTAN_HAS_AES) && defined(BOTAN_HAS_SHA2_64)

Test::Result test_other_key_not_set() {
   Test::Result result("ECIES other key not set");

   auto rng = Test::new_rng("ecies_other_key_not_set");

   const Flags flags = ecies_flags(false, false, false, true);
   const auto domain = Botan::EC_Group::from_name("secp521r1");

   const Botan::BigInt private_key_value(
      "405029866705438137604064977397053031159826489755682166267763407"
      "5002761777100287880684822948852132235484464537021197213998300006"
      "547176718172344447619746779823");

   const Botan::ECDH_PrivateKey private_key(*rng, domain, private_key_value);
   const Botan::ECIES_System_Params ecies_params(private_key.domain(),
                                                 "KDF1-18033(SHA-512)",
                                                 "AES-256/CBC",
                                                 32,
                                                 "HMAC(SHA-512)",
                                                 20,
                                                 Botan::EC_Point_Format::Compressed,
                                                 flags);

   Botan::ECIES_Encryptor ecies_enc(private_key, ecies_params, *rng);

   result.test_throws("encrypt not possible without setting other public key",
                      [&ecies_enc, &rng]() { ecies_enc.encrypt(std::vector<uint8_t>(8), *rng); });

   return result;
}

Test::Result test_kdf_not_found() {
   Test::Result result("ECIES kdf not found");

   auto rng = Test::new_rng("ecies_kdf_not_found");

   const Flags flags = ecies_flags(false, false, false, true);
   const auto domain = Botan::EC_Group::from_name("secp521r1");

   const Botan::BigInt private_key_value(
      "405029866705438137604064977397053031159826489755682166267763407"
      "5002761777100287880684822948852132235484464537021197213998300006"
      "547176718172344447619746779823");

   const Botan::ECDH_PrivateKey private_key(*rng, domain, private_key_value);
   const Botan::ECIES_System_Params ecies_params(private_key.domain(),
                                                 "KDF-XYZ(SHA-512)",
                                                 "AES-256/CBC",
                                                 32,
                                                 "HMAC(SHA-512)",
                                                 20,
                                                 Botan::EC_Point_Format::Compressed,
                                                 flags);

   result.test_throws("kdf not found", [&]() {
      Botan::ECIES_Encryptor ecies_enc(private_key, ecies_params, *rng);
      ecies_enc.encrypt(std::vector<uint8_t>(8), *rng);
   });

   return result;
}

Test::Result test_mac_not_found() {
   Test::Result result("ECIES mac not found");

   auto rng = Test::new_rng("ecies_mac_not_found");

   const Flags flags = ecies_flags(false, false, false, true);
   const auto domain = Botan::EC_Group::from_name("secp521r1");

   const Botan::BigInt private_key_value(
      "405029866705438137604064977397053031159826489755682166267763407"
      "5002761777100287880684822948852132235484464537021197213998300006"
      "547176718172344447619746779823");

   const Botan::ECDH_PrivateKey private_key(*rng, domain, private_key_value);
   const Botan::ECIES_System_Params ecies_params(private_key.domain(),
                                                 "KDF1-18033(SHA-512)",
                                                 "AES-256/CBC",
                                                 32,
                                                 "XYZMAC(SHA-512)",
                                                 20,
                                                 Botan::EC_Point_Format::Compressed,
                                                 flags);

   result.test_throws("mac not found", [&]() {
      Botan::ECIES_Encryptor ecies_enc(private_key, ecies_params, *rng);
      ecies_enc.encrypt(std::vector<uint8_t>(8), *rng);
   });

   return result;
}

Test::Result test_cipher_not_found() {
   Test::Result result("ECIES cipher not found");

   auto rng = Test::new_rng("ecies_cipher_not_found");

   const Flags flags = ecies_flags(false, false, false, true);
   const auto domain = Botan::EC_Group::from_name("secp521r1");

   const Botan::BigInt private_key_value(
      "405029866705438137604064977397053031159826489755682166267763407"
      "5002761777100287880684822948852132235484464537021197213998300006"
      "547176718172344447619746779823");

   const Botan::ECDH_PrivateKey private_key(*rng, domain, private_key_value);
   const Botan::ECIES_System_Params ecies_params(private_key.domain(),
                                                 "KDF1-18033(SHA-512)",
                                                 "AES-XYZ-256/CBC",
                                                 32,
                                                 "HMAC(SHA-512)",
                                                 20,
                                                 Botan::EC_Point_Format::Compressed,
                                                 flags);

   result.test_throws("cipher not found", [&]() {
      Botan::ECIES_Encryptor ecies_enc(private_key, ecies_params, *rng);
      ecies_enc.encrypt(std::vector<uint8_t>(8), *rng);
   });

   return result;
}

Test::Result test_system_params_short_ctor() {
   Test::Result result("ECIES short system params ctor");

   auto rng = Test::new_rng("ecies_params_short_ctor");

   const auto domain = Botan::EC_Group::from_name("secp521r1");
   const Botan::BigInt private_key_value(
      "405029866705438137604064977397053031159826489755682166267763407"
      "5002761777100287880684822948852132235484464537021197213998300006"
      "547176718172344447619746779823");

   const Botan::BigInt other_private_key_value(
      "2294226772740614508941417891614236736606752960073669253551166842"
      "5866095315090327914760325168219669828915074071456176066304457448"
      "25404691681749451640151380153");

   const Botan::ECDH_PrivateKey private_key(*rng, domain, private_key_value);
   const Botan::ECDH_PrivateKey other_private_key(*rng, domain, other_private_key_value);

   const Botan::ECIES_System_Params ecies_params(
      private_key.domain(), "KDF1-18033(SHA-512)", "AES-256/CBC", 32, "HMAC(SHA-512)", 16);

   const Botan::InitializationVector iv("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
   const std::string label = "Test";

   const std::vector<uint8_t> plaintext = Botan::hex_decode("000102030405060708090A0B0C0D0E0F");

   // generated with botan
   const std::vector<uint8_t> ciphertext = Botan::hex_decode(
      "0401519EAA0489FF9D51E98E4C22349463E2001CD06F8CE47D81D4007A"
      "79ACF98E92C814686477CEA666EFC277DC84E15FC95E38AFF8E16D478A"
      "44CD5C5F1517F8B1F300000591317F261C3D04A7207F01EAE3EC70F2360"
      "0F82C53CC0B85BE7AC9F6CE79EF2AB416E5934D61BA9D346385D7545C57F"
      "77C7EA7C58E18C70CBFB0A24AE1B9943EC5A8D0657522CCDF30BA95674D81"
      "B397635D215178CD13BD9504AE957A9888F4128FFC0F0D3F1CEC646AEC8CE"
      "3F2463D233B22A7A12B679F4C06501F584D4DEFF6D26592A8D873398BD892"
      "B477B3468813C053DA43C4F3D49009F7A12D6EF7");

   check_encrypt_decrypt(result, private_key, other_private_key, ecies_params, iv, label, plaintext, ciphertext, *rng);

   return result;
}

Test::Result test_ciphertext_too_short() {
   Test::Result result("ECIES ciphertext too short");

   const auto domain = Botan::EC_Group::from_name("secp521r1");
   const Botan::BigInt private_key_value(
      "405029866705438137604064977397053031159826489755682166267763407"
      "5002761777100287880684822948852132235484464537021197213998300006"
      "547176718172344447619746779823");

   const Botan::BigInt other_private_key_value(
      "2294226772740614508941417891614236736606752960073669253551166842"
      "5866095315090327914760325168219669828915074071456176066304457448"
      "25404691681749451640151380153");

   auto rng = Test::new_rng("ecies_ciphertext_too_short");

   const Botan::ECDH_PrivateKey private_key(*rng, domain, private_key_value);
   const Botan::ECDH_PrivateKey other_private_key(*rng, domain, other_private_key_value);

   const Botan::ECIES_System_Params ecies_params(
      private_key.domain(), "KDF1-18033(SHA-512)", "AES-256/CBC", 32, "HMAC(SHA-512)", 16);

   Botan::ECIES_Decryptor ecies_dec(other_private_key, ecies_params, *rng);

   result.test_throws("ciphertext too short",
                      [&ecies_dec]() { ecies_dec.decrypt(Botan::hex_decode("0401519EAA0489FF9D51E98E4C22349A")); });

   return result;
}

class ECIES_Unit_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         std::vector<std::function<Test::Result()>> fns = {test_other_key_not_set,
                                                           test_kdf_not_found,
                                                           test_mac_not_found,
                                                           test_cipher_not_found,
                                                           test_system_params_short_ctor,
                                                           test_ciphertext_too_short};

         for(size_t i = 0; i != fns.size(); ++i) {
            try {
               results.emplace_back(fns[i]());
            } catch(std::exception& e) {
               results.emplace_back(Test::Result::Failure("ECIES unit tests " + std::to_string(i), e.what()));
            }
         }

         return results;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecies_unit", ECIES_Unit_Tests);

   #endif

#endif

}  // namespace

}  // namespace Botan_Tests
