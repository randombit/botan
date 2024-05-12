/*
 * Ed448 Signature Algorithm Tests
 * (C) 2024 Jack Lloyd
 *     2024 Fabian Albert - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include "tests.h"

#if defined(BOTAN_HAS_ED448)
   #include "test_pubkey.h"
   #include <botan/bigint.h>
   #include <botan/ed448.h>
   #include <botan/internal/curve448_scalar.h>
   #include <botan/internal/ed448_internal.h>

namespace Botan_Tests {
namespace {

class Ed448_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override {
         // Test without prehash and Ed448ph with default (SHAKE256(64)) and
         // a custom hash function (SHAKE256(72))
         return {"", "Ed448ph", "SHAKE-256(72)"};
      }

      std::string algo_name() const override { return "Ed448"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         return std::make_unique<Botan::Ed448_PublicKey>(raw_pk);
      }
};

class Ed448_Signature_Tests final : public PK_Signature_Generation_Test {
   public:
      Ed448_Signature_Tests() :
            PK_Signature_Generation_Test("Ed448", "pubkey/ed448.vec", "Msg,PrivateKey,PublicKey,Valid,Signature") {}

      bool clear_between_callbacks() const override { return false; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const std::vector<uint8_t> privkey = vars.get_req_bin("PrivateKey");
         const std::vector<uint8_t> pubkey = vars.get_req_bin("PublicKey");

         const Botan::secure_vector<uint8_t> seed(privkey.begin(), privkey.end());

         auto sk = std::make_unique<Botan::Ed448_PrivateKey>(seed);

         if(sk->public_key_bits() != pubkey) {
            throw Test_Error("Invalid Ed448 key in test data");
         }

         return sk;
      }

      bool skip_this_test(const std::string&, const VarMap& vars) override { return vars.get_req_sz("Valid") != 1; }
};

class Ed448_Verification_Tests : public PK_Signature_Verification_Test {
   public:
      Ed448_Verification_Tests() :
            PK_Signature_Verification_Test("Ed448", "pubkey/ed448.vec", "Msg,PrivateKey,PublicKey,Valid,Signature") {}

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> pk = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::Ed448_PublicKey>(pk);
      }
};

class Ed448_General_Test final : public Text_Based_Test {
   private:
      template <size_t S>
      std::array<uint8_t, S> to_array(std::span<const uint8_t> sp) {
         BOTAN_ASSERT_NOMSG(sp.size() == S);
         std::array<uint8_t, S> arr;
         Botan::copy_mem(arr.data(), sp.data(), S);
         return arr;
      }

   public:
      Ed448_General_Test() : Text_Based_Test("pubkey/ed448.vec", "Msg,PrivateKey,PublicKey,Valid,Signature") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         Test::Result result("Ed448 general tests");

         const auto pub_key_ref = to_array<57>(vars.get_req_bin("PublicKey"));
         const auto sk = to_array<57>(vars.get_req_bin("PrivateKey"));

         // Test encoding and decoding
         const auto p = Botan::Ed448Point::decode(pub_key_ref);
         const auto reencoded_point_data = p.encode();

         result.test_is_eq("Enc- and decoding roundtrip", reencoded_point_data, pub_key_ref);

         // Test public key creation
         const auto pub_key = Botan::create_pk_from_sk(sk);

         result.test_is_eq("Public key from secret key", pub_key, pub_key_ref);

         return result;
      }

      bool skip_this_test(const std::string&, const VarMap& vars) override { return vars.get_req_sz("Valid") != 1; }
};

class Ed448_Utils_Test final : public Test {
   private:
      std::array<uint8_t, 56> reduce_mod_L_ref(std::span<const uint8_t> t) {
         const std::vector<uint8_t> t_bytes(t.rbegin(), t.rend());
         const Botan::BigInt t_int(t_bytes.data(), t_bytes.size());
         const BigInt L(
            "0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3");
         const auto res = t_int % L;
         std::array<uint8_t, 56> res_bytes = {0};
         res.serialize_to(res_bytes);
         std::reverse(res_bytes.begin(), res_bytes.end());
         return res_bytes;
      }

      Test::Result test_reduce_mod_L() {
         Test::Result result("Reduce mod L test");
         std::array<uint8_t, 114> full = {0};
         std::memset(full.data(), 0xff, full.size());

         const std::vector<std::array<uint8_t, 114>> test_vectors = {
            full, std::array<uint8_t, 114>{0x42}, std::array<uint8_t, 114>{0}};

         for(auto& t : test_vectors) {
            const auto ref = reduce_mod_L_ref(t);
            std::array<uint8_t, 56> res;
            result.test_no_throw("Reduce mod L does not throw", [&] { res = Botan::Scalar448(t).to_bytes<56>(); });
            result.test_is_eq("Reduce mod L result", res, ref);
         }

         return result;
      }

   public:
      std::vector<Test::Result> run() override { return {test_reduce_mod_L()}; }
};

}  // namespace

BOTAN_REGISTER_TEST("ed448", "ed448_keygen", Ed448_Keygen_Tests);
BOTAN_REGISTER_TEST("ed448", "ed448_sign", Ed448_Signature_Tests);
BOTAN_REGISTER_TEST("ed448", "ed448_verify", Ed448_Verification_Tests);
BOTAN_REGISTER_TEST("ed448", "ed448_general", Ed448_General_Test);
BOTAN_REGISTER_TEST("ed448", "ed448_utils", Ed448_Utils_Test);

}  // namespace Botan_Tests

#endif
