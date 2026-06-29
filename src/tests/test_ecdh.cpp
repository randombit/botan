/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDH)
   #include "test_pubkey.h"
   #include <botan/asn1_obj.h>
   #include <botan/ec_group.h>
   #include <botan/ecdh.h>
   #include <botan/pubkey.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDH)

class ECDH_KAT_Tests final : public PK_Key_Agreement_Test {
   public:
      ECDH_KAT_Tests() : PK_Key_Agreement_Test("ECDH", "pubkey/ecdh.vec", "Secret,CounterKey,K", "KDF") {}

      std::string default_kdf(const VarMap& /*unused*/) const override { return "Raw"; }

      bool skip_this_test(const std::string& group_id, const VarMap& /*vars*/) override {
         return !Botan::EC_Group::supports_named_group(group_id);
      }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string& group_id, const VarMap& vars) override {
         const auto group = Botan::EC_Group::from_name(group_id);
         const Botan::BigInt secret = vars.get_req_bn("Secret");
         return std::make_unique<Botan::ECDH_PrivateKey>(this->rng(), group, secret);
      }

      std::vector<uint8_t> load_their_key(const std::string& /*header*/, const VarMap& vars) override {
         return vars.get_req_bin("CounterKey");
      }
};

class ECDH_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         return {
            "secp256r1", "secp384r1", "secp521r1", "brainpool256r1", "brainpool384r1", "brainpool512r1", "frp256v1"};
      }

      std::string algo_name() const override { return "ECDH"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view keygen_params,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         const auto group = Botan::EC_Group(keygen_params);
         const auto public_key = Botan::EC_AffinePoint(group, raw_pk);
         return std::make_unique<Botan::ECDH_PublicKey>(group, public_key);
      }
};

class ECDH_AllGroups_Tests : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         for(const std::string& group_name : Botan::EC_Group::known_named_groups()) {
            Test::Result result("ECDH " + group_name);

            result.start_timer();

            const std::string kdf = "Raw";

            try {
               const auto group = Botan::EC_Group::from_name(group_name);

               // Regression test: prohibit loading an all-zero private key
               result.test_throws<Botan::Invalid_Argument>("all-zero private key is unacceptable", [&] {
                  const auto one = Botan::EC_Scalar::one(group);
                  const auto zero = one - one;  // NOLINT(*-redundant-expression)
                  Botan::ECDH_PrivateKey(group, zero);
               });

               // Regression test: prohibit loading a public point that is the identity (point at infinity)
               result.test_throws<Botan::Invalid_Argument>("point at infinity isn't a valid public key", [&] {
                  const auto infinity = Botan::EC_AffinePoint::identity(group);
                  Botan::ECDH_PublicKey(group, infinity);
               });

               // Regression test: prohibit ECDH-agreement with all-zero public value
               result.test_throws<Botan::Decoding_Error>("ECDH public value is point-at-infinity", [&] {
                  const auto sk = Botan::ECDH_PrivateKey(rng(), group);
                  const Botan::PK_Key_Agreement ka(sk, rng(), kdf);
                  std::vector<uint8_t> sec1_infinity(1, 0x00);
                  const auto a_ss = ka.derive_key(0, sec1_infinity);
               });

               // Regression test: prohibit loading a point not on the curve
               result.test_throws<Botan::Decoding_Error>("point is not on curve", [&] {
                  const auto& base_point = Botan::EC_AffinePoint::generator(group);
                  auto encoded = base_point.serialize_uncompressed();
                  encoded[3] -= 1;

                  const Botan::ECDH_PrivateKey a_priv(rng(), group);
                  const auto a_pub = a_priv.public_value();
                  const Botan::PK_Key_Agreement a_ka(a_priv, rng(), kdf);
                  const auto a_ss = a_ka.derive_key(0, encoded);
               });

               for(size_t i = 0; i != 100; ++i) {
                  const Botan::ECDH_PrivateKey a_priv(rng(), group);
                  const auto a_pub = a_priv.public_value();

                  const Botan::ECDH_PrivateKey b_priv(rng(), group);
                  const auto b_pub = b_priv.public_value();

                  const Botan::PK_Key_Agreement a_ka(a_priv, rng(), kdf);
                  const auto a_ss = a_ka.derive_key(0, b_pub);

                  const Botan::PK_Key_Agreement b_ka(b_priv, rng(), kdf);
                  const auto b_ss = b_ka.derive_key(0, a_pub);

                  result.test_bin_eq("Same shared secret", a_ss.bits_of(), b_ss.bits_of());
               }
            } catch(std::exception& e) {
               result.test_failure("Exception", e.what());
            }

            result.end_timer();

            results.push_back(result);
         }

         return results;
      }
};

/**
 * @brief Testing PK key decoding
 */
class ECC_Private_Key_Param_Decoding_Test : public Text_Based_Test {
   public:
      ECC_Private_Key_Param_Decoding_Test() : Text_Based_Test("pubkey/ecc-key-and-param.vec", "key,param,valid") {}

   protected:
      Test::Result run_one_test(const std::string& /*header*/, const VarMap& vars) final {
         const auto key_bin = vars.get_req_bin("key");
         const auto param_str = vars.get_req_str("param");
         const auto valid_pair = vars.get_req_bool("valid");

         Test::Result result("ECC Private Key Decoding with external AlgorithmIdentifier parameter");
         try {
            const auto alg_id = [&]() {
               const auto oid_ecdh = Botan::OID("1.3.132.1.12");
               if(param_str.empty()) {
                  return Botan::AlgorithmIdentifier(oid_ecdh,
                                                    Botan::AlgorithmIdentifier::Encoding_Option::USE_EMPTY_PARAM);
               }
               const auto enc_param = Botan::OID(param_str).BER_encode();
               return Botan::AlgorithmIdentifier(oid_ecdh, enc_param);
            };
            const auto create_key = [&]() { const Botan::ECDH_PrivateKey priv_key(alg_id(), key_bin); };
            if(valid_pair) {
               create_key();
               result.test_success("deserialize valid combination of ECC private key and AlgorithmIdentifier");
            } else {
               result.test_throws(
                  "exception when decoding invalid pair of private key group parameters and AlgorithmIdentifier",
                  [&]() { create_key(); });
            }
         } catch(Botan::Exception& e) {
            result.test_failure("Failed to deserialize key", e.what());
         }
         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "ecdh_kat", ECDH_KAT_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdh_keygen", ECDH_Keygen_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecdh_all_groups", ECDH_AllGroups_Tests);
BOTAN_REGISTER_TEST("pubkey", "ecc_key_and_params", ECC_Private_Key_Param_Decoding_Test);

#endif

}  // namespace

}  // namespace Botan_Tests
