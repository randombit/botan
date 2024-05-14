#include "tests.h"
#if defined(BOTAN_HAS_X_WING)
   #include "test_pubkey.h"
   #include <botan/x_wing.h>

namespace Botan_Tests {

namespace {

class X_Wing_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {""}; }

      std::string algo_name() const override { return "X-Wing"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /*keygen_params*/,
                                                             std::string_view /*provider*/,
                                                             std::span<const uint8_t> raw_key_bits) const override {
         return std::make_unique<Botan::X_Wing_PublicKey>(raw_key_bits);
      }
};

class X_Wing_Roundtrip_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X-Wing roundtrip");

         auto sk = std::make_unique<Botan::X_Wing_PrivateKey>(Test::rng());
         auto pk = sk->public_key();

         // Test keys
         result.test_eq("Public key bits", pk->public_key_bits(), sk->public_key_bits());

         auto enc = Botan::PK_KEM_Encryptor(*pk, "Raw", "base");
         auto dec = Botan::PK_KEM_Decryptor(*sk, Test::rng(), "Raw", "base");

         // Encapsulate and decapsulate
         auto [ct, ss] = Botan::KEM_Encapsulation::destructure(enc.encrypt(Test::rng(), 32));
         auto ss_dec = dec.decrypt(ct, 32);

         result.test_eq("Encaps/Decaps roundtrip", ss, ss_dec);

         // Encapsulate with secret key
         {
            auto enc_sk = Botan::PK_KEM_Encryptor(*sk, "Raw", "base");
            auto [ct2, ss2] = Botan::KEM_Encapsulation::destructure(enc.encrypt(Test::rng(), 32));
            auto ss2_dec = dec.decrypt(ct2, 32);
            result.test_eq("Encaps with secret key (shared secret)", ss2_dec, ss2);
         }
         return {result};
      }
};

}  // namespace

BOTAN_REGISTER_TEST("x_wing", "x_wing_keygen", X_Wing_Keygen_Tests);
BOTAN_REGISTER_TEST("x_wing", "x_wing_roundtrip", X_Wing_Roundtrip_Test);

}  // namespace Botan_Tests
#endif  // BOTAN_HAS_X_WING