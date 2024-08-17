/*
* Extended Hash-Based Signatures Tests
*
* (C) 2014,2015 Jack Lloyd
* (C) 2016,2018 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
**/

#include "tests.h"

#if defined(BOTAN_HAS_XMSS_RFC8391)
   #include "test_pubkey.h"
   #include "test_rng.h"
   #include <botan/hash.h>
   #include <botan/xmss.h>
   #include <botan/internal/loadstor.h>
   #include <botan/internal/stl_util.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_XMSS_RFC8391)

class XMSS_Signature_Tests final : public PK_Signature_Generation_Test {
   public:
      XMSS_Signature_Tests() :
            PK_Signature_Generation_Test("XMSS", "pubkey/xmss_sig.vec", "Params,Msg,PrivateKey,Signature") {}

      bool skip_this_test(const std::string& /*header*/, const VarMap& vars) override {
         if(Test::run_long_tests() == false) {
            const std::string params = vars.get_req_str("Params");

            if(params == "SHAKE_10_256" || params == "SHA2_10_192") {
               return false;
            }

            return true;
         }

         return false;
      }

      std::string default_padding(const VarMap& /*vars*/) const override { return ""; }

      std::string printed_params(const VarMap& vars, const std::string& /*padding*/) const override {
         return vars.get_req_str("Params");
      }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PrivateKey");
         const Botan::secure_vector<uint8_t> sec_key(raw_key.begin(), raw_key.end());

         return std::make_unique<Botan::XMSS_PrivateKey>(sec_key);
      }
};

class XMSS_Signature_Verify_Tests final : public PK_Signature_Verification_Test {
   public:
      XMSS_Signature_Verify_Tests() :
            PK_Signature_Verification_Test("XMSS", "pubkey/xmss_verify.vec", "Params,Msg,PublicKey,Signature") {}

      std::string default_padding(const VarMap& /*vars*/) const override { return ""; }

      std::string printed_params(const VarMap& vars, const std::string& /*padding*/) const override {
         return vars.get_req_str("Params");
      }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::XMSS_PublicKey>(raw_key);
      }
};

class XMSS_Signature_Verify_Invalid_Tests final : public PK_Signature_NonVerification_Test {
   public:
      XMSS_Signature_Verify_Invalid_Tests() :
            PK_Signature_NonVerification_Test(
               "XMSS", "pubkey/xmss_invalid.vec", "Params,Msg,PublicKey,InvalidSignature") {}

      std::string default_padding(const VarMap& /*vars*/) const override { return ""; }

      std::string printed_params(const VarMap& vars, const std::string& /*padding*/) const override {
         return vars.get_req_str("Params");
      }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override {
         const std::vector<uint8_t> raw_key = vars.get_req_bin("PublicKey");
         return std::make_unique<Botan::XMSS_PublicKey>(raw_key);
      }
};

class XMSS_Keygen_Tests final : public PK_Key_Generation_Test {
   public:
      std::vector<std::string> keygen_params() const override { return {"XMSS-SHA2_10_256", "XMSS-SHA2_10_192"}; }

      std::string algo_name() const override { return "XMSS"; }

      std::unique_ptr<Botan::Public_Key> public_key_from_raw(std::string_view /* keygen_params */,
                                                             std::string_view /* provider */,
                                                             std::span<const uint8_t> raw_pk) const override {
         Botan::BufferSlicer s(raw_pk);
         const auto oid = Botan::XMSS_Parameters::xmss_algorithm_t(Botan::load_be(s.take<4>()));
         const auto p = Botan::XMSS_Parameters(oid);
         auto root = s.copy_as_secure_vector(p.element_size());
         auto public_seed = s.copy_as_secure_vector(p.element_size());

         return std::make_unique<Botan::XMSS_PublicKey>(oid, std::move(root), std::move(public_seed));
      }
};

/**
 * Tests that the key generation is compatible with the reference implementation
 *   based on: https://github.com/XMSS/xmss-reference/tree/171ccbd
 */
class XMSS_Keygen_Reference_Test final : public Text_Based_Test {
   public:
      XMSS_Keygen_Reference_Test() :
            Text_Based_Test("pubkey/xmss_keygen_reference.vec",
                            "Params,SecretSeed,PublicSeed,SecretPrf,PublicKey,PrivateKey") {}

      Test::Result run_one_test(const std::string&, const VarMap& vars) final {
         Test::Result result(vars.get_req_str("Params"));

         Fixed_Output_RNG fixed_rng;
         auto add_entropy = [&](auto v) { fixed_rng.add_entropy(v.data(), v.size()); };

         // The order of the RNG values is dependent on the order they are pulled
         // from the RNG in the production implementation.
         add_entropy(vars.get_req_bin("PublicSeed"));  // XMSS_PublicKey constructor's initializer list
         add_entropy(vars.get_req_bin("SecretPrf"));   // XMSS_PrivateKey constructor's call to ..._Internal constructor
         add_entropy(vars.get_req_bin("SecretSeed"));  // XMSS_PrivateKey constructor's call to ..._Internal constructor

         const auto xmss_algo = Botan::XMSS_Parameters::xmss_id_from_string(vars.get_req_str("Params"));
         Botan::XMSS_PrivateKey keypair(xmss_algo, fixed_rng);

         result.test_eq("Generated private key matches", keypair.raw_private_key(), vars.get_req_bin("PrivateKey"));
         result.test_eq("Generated public key matches", keypair.raw_public_key(), vars.get_req_bin("PublicKey"));

         return result;
      }

      bool skip_this_test(const std::string& /*header*/, const VarMap& vars) override {
         // skip if this build does not provide the requested hash function
         const auto params = Botan::XMSS_Parameters(vars.get_req_str("Params"));
         if(Botan::HashFunction::create(params.hash_function_name()) == nullptr) {
            return true;
         }

         if(Test::run_long_tests()) {
            return false;
         }

         else if(vars.get_req_str("Params") == "XMSS-SHA2_10_256") {
            return false;
         }

         else {
            return true;
         }
      }
};

std::vector<Test::Result> xmss_statefulness() {
   auto rng = Test::new_rng(__func__);

   auto sign_something = [&rng](auto& sk) {
      auto msg = Botan::hex_decode("deadbeef");

      Botan::PK_Signer signer(sk, *rng);
      signer.sign_message(msg, *rng);
   };

   return {CHECK("signing alters state",
                 [&](auto& result) {
                    Botan::XMSS_PrivateKey sk(Botan::XMSS_Parameters::XMSS_SHA2_10_256, *rng);
                    result.require("allows 1024 signatures", sk.remaining_operations() == 1024);

                    sign_something(sk);

                    result.require("allows 1023 signatures", sk.remaining_operations() == 1023);
                 }),

           CHECK("state can become exhausted", [&](auto& result) {
              const auto skbytes = Botan::hex_decode(
                 "000000011BBB81273E8057724A2A894593A1A688B3271410B3BEAB9F5587337BCDCBBF5C4E43AB"
                 "0AB2F88258E5AC54BB252E39335AE9B0D4AF0C0347EA45B8AA0AA3804C000003FFAC0C29C1ACD3"
                 //                                                         ~~1023~~
                 "19DA96E9C8EE4E28C2078441A76B6BB8BAFD358F67FBCBFC559B55C37C01FFADBB118099759EEB"
                 "A3B07643F73BCB4AAC546E244B57782D6BEABC");
              Botan::XMSS_PrivateKey sk(skbytes);
              result.require("allow one last signature", sk.remaining_operations() == 1);

              sign_something(sk);

              result.require("allow no more signatures", sk.remaining_operations() == 0);
              result.test_throws("no more signing", [&] { sign_something(sk); });
           })};
}

std::vector<Test::Result> xmss_legacy_private_key() {
   const auto legacy_xmss_public_key = Botan::hex_decode(
      "00000001C49B128365E23D97C2D36A2AC26E0B448FCEF77A5ED68EFDC460E787D0EDB67"
      "68EAC3E82B04B84571C49684ED822F8179FDFF1C825DA9F9EA78F5D50A21E6341");

   // With Botan 3.0 we implemented a multi-target attack mitigation as
   // suggested by NIST's SP.800-208. This private key was generated before that.
   const auto legacy_xmss_private_key = Botan::hex_decode(
      "04818800000001C49B128365E23D97C2D36A2AC26E0B448FCEF77A5ED68EFDC460E787D"
      "0EDB6768EAC3E82B04B84571C49684ED822F8179FDFF1C825DA9F9EA78F5D50A21E6341"
      "0000000059FF2307F3D05577B1B259A64B5D8DB8FDF51A4EA898D23B3F4F574961ED7A6"
      "A7F42ADD11F527ED757E79183A2FABA0E37E1C3C8C6E6468B4AB44305D3920DAE");

   const auto legacy_signature = Botan::hex_decode(
      "0000000049BB2EDE36E46FD63C5DBA3F60A2F628E3116452DAB39A60A4E321110EC45D1"
      "CE7CD3F33F736B8ACABB9D2FA0764645F1FD708E84B82BED1D94B2FD4A4AF72DE4B68AE"
      "2B7E95A99B752C6CD74DF3180754A2B663F164616B07E0212224CA3A66887DDA3083090"
      "010310D9F16BB087DE1F346FD2C2693AC5DE11DE24181A21AF3F2CFF6535C11D2072078"
      "D291E939BC95C8F3CD4A59225774EB291B8CDE7A90AF03030BF05F71FCD2BD0C4462E6B"
      "9FAC751B5E896370966357B3032A2650895502566FFCD99C309548C5091785DC145A511"
      "E591F39495EF86B1CFBBA654BB289A3B61BCB4C5967773182396D384E76D6007FD9698C"
      "55F8F4DA4A21EA97FBDF7B40B4289917B51067307BAC0507DBB39E4B618B799AAD8D08D"
      "FB4C10B648AFC66BFB071472FC6ADEC311008FF1D4C4F32BE664DCEF829375E3A92A0F0"
      "C9D7C4613B778172ACF81F7EFEE1D76A4AF0C1195292BE694F655374B68C3DB9E4C82F2"
      "8FF2EEC3AE9B5D1EDC807608E1A08246408CECBE5816BCC6585A9558A8EAE57619EAEE3"
      "1DE879138FAE3EACBFF180F71ED4BD28497BDCDE4CF37D40FDDE92D3422A1DA99CEEDC4"
      "063656E81E3F9398E9333BB3BCE7A0FC594D12F9A9E82D3FE89E66C49F07144737D56B1"
      "B0DCE1B98AC3B3619C4D85C77416C286998652A0A08A9F0D5B51BBD4040C0A07373130C"
      "1E9C0194F649018D67AF050353BE08E3E5E750D7E9D85C9C7283F5293212C8D372BBFDA"
      "8D28A581B42C90BE0C5E68FC63A3E0812656EB0D57CE9758ADD8436F57B9FD402EE42E9"
      "25CA68A52BEEE972871C9559819C9BAED8FD3BA508DCC9945415B603330A82CAEAA8001"
      "9EB1332E191E06EC8FA325BCE49B903BFC4244608A42E673D3DFA8202F49AE5C150AB56"
      "D4C720E32719498835D35D7062FCF2A969F552B11672CB7061E7C565B960C2BA8EB0780"
      "49365202674D07617DD516D2C598C71669D43EE63852BC758ABFD042097FEC7E3F9B855"
      "9AF3043630F00AEB9DF8B549076FBB2F786D0BD16C889439F45D441AF3EBC16E70AF7B5"
      "98D36A9F3A5FA05D5D438D1A563C9AC11B73A6A9976AD3DC78190F3289F35D019D5DF59"
      "DD3262608643509C25FF4C6056C7528BB551680F6A5E637F60C5951593F7E701C297DA0"
      "FDB289D1D47E2CE1F5E3CD6703069F773860152C903962B0F8704E6B89201296C05D6DA"
      "81CC0E3848E8C07400A9B3962013642E25F2332FC820463890D97F3BD34DDC4318E2EA1"
      "E65BE4F5613854856497BE2C4B894731DCD45209038C80855EB4150EE5D4CC6BE6859A6"
      "D71A02AD693E2F43BD5736859B7F295BA068503510347637ABF19D67F984BAA9AFE577B"
      "BC4EFF50FD7F2F56305DF9F0393DDB02F20BA554DFF9ACF6748E8FFE433267CCBE0C434"
      "900672987D00197116F61FACE800C42FAA1957D95679F4CDCA392E5CAC26E84F523D23D"
      "C209C19E8E42FAF1269A6C07BDC3E89304E479D2F71A7BCDDBF485BA65662013DD4F35C"
      "1CB7CBB7FD9388DD048AA5CB5AF01A7DB63E20BCB43B2C7AB2CBC9C9232CE5099055915"
      "6D18B0BD44B46C813CC2E0C29361790B3EE61EF6946AE3197A8B0226B47E8931A9841DA"
      "6A976EB1A105F0487AFD294BE69B4021BF60EFDA826DC69C1A2BAE015CD0D13DD614E8A"
      "71B885FFB9CDBF8BCF157BAF08D1A4EE24573235617F70049511AFF40D9243D2398C8F0"
      "05790D86F0956473BDBC5DEF4DFB12597F6BE67E3265E062356D4122D30B3BCDC60D736"
      "0D82FB0943DF88DC761018C7E43F7653A899D517709DE33AB2866BD44748A32E96BDCA2"
      "84763EEEEFAEF347FD8D31AE7BF98C21498240C5BBACD9F16A7B4C8B98C9AB1F9F10E17"
      "8F45483CBB6DFE3CF47EEB87CB5A563105DC2AA6B3174B407A3C20FDF82B4E7A825FD4E"
      "80FCD3A63A9FDA6182A69A1289A0A8EECB5AC381BC53048ECBFCAF26E4BA46179081325"
      "DBD89ACF9EF115667368F6604E2856AD107B5CA6BFA8E9253146D9CFB32E4359A2E7A3D"
      "3F6DCDA5EDCD09558B904D13D3CFA5E02D409EC6C610FBF9D0E1F34C9D5AF4F18F43527"
      "AA0A2BB687A12AE426E3A73BD75493DCCAAABEA83E1DB0BF9CC7589EE169A8A8C5FAAA7"
      "7D69405D9347D9642202E50B27229AE0A8E7482F06AC4FB9F039CECE7F056EC01F83549"
      "6977D845641254ACF420B6766F8CD1CE13DD9041B2BE7369EFE20FC5359DFD31166FBFF"
      "5D1C6EBB1FFB0A6C29CC64DE9F30EE3C643A3168403911B7DDA3E7B23090C444960FCE5"
      "6F9F1077D0D54658DAD1C65D388448982ACE87D426595CD38F50BF88755036551976A00"
      "310E66E0CB8BCBF5A51AE0F6418079F29C5F56DA9F7FD787B821C6346205C520794079F"
      "11858E7530CF494377F998E33323030D82A44D84F5209CC608F38C950D88B6A169D297F"
      "101A0D3E7DA3152F7D698ED3F6F6EE79B4F87E6032B98907E2FEC3AD1F44FA7816B568A"
      "31AF329B19636788498BE3C21A5676BDEB987F1BA213C8E86F5D39CEC9571EB5198645C"
      "D39EA26BE5598D47F3324F3D763D4E892A13C579F964B72369B40800B30088DE6140E94"
      "5B5F03C67015EC4E03065EC9126C2417F827EC526C852020D73BB6F97DED24081399D7B"
      "F7EE644B16A7BC601F32A312CFB98FF0E954DF0FCD2C61154B3D8CCC32DCFCCB172033D"
      "5F5ACB03369E323429123FB9EAB658CB072EA9CD058CAD76D78A6F0BA01BB5D36172DE7"
      "4DE17704A055509B3BDBE7032F4A0E3E7329CC646D06DE7C7ECF5EF030362CE079D3C3B"
      "DDB605A04918C16FE79251B7705DAC88A0C84E7C692E1AFF59968DE28CBDF001BBEA509"
      "A8A270B6BFD7E653B2228418E73F40A14F491FAEBAC8C11F346FB51C8E10DB63ED5C287"
      "DA7DDC692B8FE6998AC85EA29D4F9B5FEB3E062FFEEA23DAD536DDE783AFE43606D9685"
      "09F4695E55FE935DF20B8E9EFEE01DD21E733C22830A6E6086EBB4AC7CFB5DC5C6F9FBE"
      "F131BF636A129723E5D663FDCCF181AB996D158146602D567B48CEF809E4D3E5B7A7B64"
      "3C48EFCA7621534397B623AF23AE6F2BE7F2D7A6FBB2D7B64B96526B73DBA66A29F4260"
      "2BD9FF72A165431C15A570A5731D9426210F946FC682F181944F40DFB68314ACA43E321"
      "4AFDF11EA825B79425F0C864E354CA7E6C447AE9E0796AAB2B6720516D3FC0B73CFE98E"
      "F0D8E8D80A59DB9ADA0F03CF0444E1BED9ED9A75FBB6FD6D5BAD4F5FF66C8987ADA6F9F"
      "CA06CBAD1C9E329B844CC5BBF6CCC52852DE44B72EECAF34802043107542F5BFEA73944"
      "611AB035D6D7A8EBD3101F321A54C1DADC600419F8DA6BF3967E5B9E708BC4C3E901623"
      "E8FB6E87825757498A24A921EC601CC15399237D9C4115B678E8968A2095818D9261C4E"
      "8F94B9DCE3F74EC7E0479F6F6AB13676954390EF3B45D2292BF664D618CFE5ECFFBD391"
      "872B4F9F306A09B1238E7561942C7065FD14208F4D4A42752A9A747A29B8BE3C1658EDC"
      "6B250DBD1599FBB09A7F148A7AEFEAB26ADB728A330DD3F616C8A736D1BF4EA17F2C3BF"
      "A5E22C249FA9D1E7DA08DB351709C4");

   Botan::XMSS_PrivateKey legacy_secret_key = Botan::XMSS_PrivateKey(legacy_xmss_private_key);
   Botan::XMSS_PublicKey public_key_from_secret_key(legacy_secret_key);
   Botan::XMSS_PublicKey legacy_public_key = Botan::XMSS_PublicKey(legacy_xmss_public_key);

   const auto message = Botan::hex_decode("deadcafe");

   auto rng = Test::new_rng(__func__);

   return {
      CHECK("Use a legacy private key to create a signature",
            [&](auto& result) {
               Botan::PK_Signer signer(legacy_secret_key, *rng);
               auto signature = signer.sign_message(message, *rng);

               Botan::PK_Verifier verifier(public_key_from_secret_key);
               result.confirm("legacy private key generates signatures that are still verifiable",
                              verifier.verify_message(message, signature));
            }),

      CHECK("Verify a legacy signature",
            [&](auto& result) {
               Botan::PK_Verifier verifier(public_key_from_secret_key);
               result.confirm("legacy private key generates signatures that are still verifiable",
                              verifier.verify_message(message, legacy_signature));
            }),

      CHECK("Verify a new signature by a legacy private key with a legacy public key",
            [&](auto& result) {
               Botan::PK_Signer signer(legacy_secret_key, *rng);
               auto signature = signer.sign_message(message, *rng);

               Botan::PK_Verifier verifier(legacy_public_key);
               result.confirm("legacy private key generates signatures that are still verifiable",
                              verifier.verify_message(message, legacy_signature));
            }),
   };
}

BOTAN_REGISTER_TEST("pubkey", "xmss_sign", XMSS_Signature_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_verify", XMSS_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_verify_invalid", XMSS_Signature_Verify_Invalid_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_keygen", XMSS_Keygen_Tests);
BOTAN_REGISTER_TEST("pubkey", "xmss_keygen_reference", XMSS_Keygen_Reference_Test);
BOTAN_REGISTER_TEST_FN("pubkey", "xmss_unit_tests", xmss_statefulness, xmss_legacy_private_key);

#endif

}  // namespace

}  // namespace Botan_Tests
