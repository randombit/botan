/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include "test_pubkey.h"
  #include <botan/pubkey.h>
  #include <botan/dh.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)

class Diffie_Hellman_KAT_Tests : public PK_Key_Agreement_Test
   {
   public:
      Diffie_Hellman_KAT_Tests() : PK_Key_Agreement_Test(
         "Diffie-Hellman",
         "pubkey/dh.vec",
         "P,G,X,Y,Msg,OutLen,K",
         "Q,KDF")
         {}

      std::string default_kdf(const VarMap&) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_our_key(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt x = get_req_bn(vars, "X");
         const Botan::BigInt q = get_opt_bn(vars, "Q", 0);

         Botan::DL_Group grp;
         if(q == 0)
            {
            grp = Botan::DL_Group(p, g);
            }
         else
            {
            grp = Botan::DL_Group(p, q, g);
            }

         std::unique_ptr<Botan::Private_Key> key(new Botan::DH_PrivateKey(Test::rng(), grp, x));
         return key;
         }

      std::vector<uint8_t> load_their_key(const std::string&, const VarMap& vars) override
         {
         const Botan::BigInt p = get_req_bn(vars, "P");
         const Botan::BigInt g = get_req_bn(vars, "G");
         const Botan::BigInt y = get_req_bn(vars, "Y");
         const Botan::BigInt q = get_opt_bn(vars, "Q", 0);

         Botan::DL_Group grp;
         if(q == 0)
            {
            grp = Botan::DL_Group(p, g);
            }
         else
            {
            grp = Botan::DL_Group(p, q, g);
            }

         Botan::DH_PublicKey key(grp, y);
         return key.public_value();
         }

      std::vector<Test::Result> run_final_tests() override
         {
         using namespace Botan;

         Test::Result result("DH negative tests");

         const BigInt g("2");
         const BigInt p("58458002095536094658683755258523362961421200751439456159756164191494576279467");
         const DL_Group grp(p, g);

         const Botan::BigInt x("46205663093589612668746163860870963912226379131190812163519349848291472898748");
         std::unique_ptr<Private_Key> privkey(new DH_PrivateKey(Test::rng(), grp, x));

         std::unique_ptr<PK_Key_Agreement> kas(new PK_Key_Agreement(*privkey, rng(), "Raw"));

         result.test_throws("agreement input too big", [&kas]()
            {
            const BigInt too_big("584580020955360946586837552585233629614212007514394561597561641914945762794672");
            kas->derive_key(16, BigInt::encode(too_big));
            });

         result.test_throws("agreement input too small", [&kas]()
            {
            const BigInt too_small("1");
            kas->derive_key(16, BigInt::encode(too_small));
            });

         // public keys failing checks from NIST CAVS file 20.1 (Generated on Mon Jun 20 09:02:25 2016)
         // http://csrc.nist.gov/groups/STM/cavp/documents/keymgmt/KASTestVectorsFFC2016.zip
         const Botan::BigInt g_nist("0x1e2b67448a1869df1ce57517dc5e797b62c5d2c832e23f954bef8bcca74489db6caed2ea496b52a52cb664a168374cb176ddc4bc0068c6eef3a746e561f8dc65195fdaf12b363e90cfffdac18ab3ffefa4b2ad1904b45dd9f6b76b477ef8816802c7bd7cb0c0ab25d378098f5625e7ff737341af63f67cbd00509efbc6470ec38c17b7878a463cebda80053f36558a308923e6b41f465385a4f24fdb303c37fb998fc1e49e3c09ce345ff7cea18e9cd1457eb93daa87dba8a31508fa5695c32ce485962eb1834144413b41ef936db71b79d6fe985c018ac396e3af25054dbbc95e56ab5d4d4b7b61a70670e789c336b46b9f7be43cf6eb0e68b40e33a55d55cc");
         const Botan::BigInt p_nist("0xa25cb1199622be09d9f473695114963cbb3b109f92df6da1b1dcab5e8511e9a117e2881f30a78f04d6a3472b8064eb6416cdfd7bb8b9891ae5b5a1f1ee1da0cace11dab3ac7a50236b22e105dbeef9e45b53e0384c45c3078acb6ee1ca983511795801da3d14fa9ed82142ec47ea25c0c0b7e86647d41e9f55955b8c469e7e298ea30d88feacf43ade05841008373605808a2f8f8910b195f174bd8af5770e7cd85380d198f4ed2a0c3a2f373436ae6ce9567846a79275765ef829abbc6171718f7746ebd167d406e2546acdea7299194a613660d5ef721cd77e7722095c4ca42b29db3d4436325b47f850af05d411c7a95ccc54555c193384a6eeebb47e6f0f");
         const Botan::BigInt q_nist("0xa944d488de8c89567b602bae44478632604f8bf7cb4deb851cf6e22d");

         const Botan::DL_Group grp_nist(p_nist, q_nist, g_nist);
         std::unique_ptr<Botan::Public_Key> key;

         // [FB - SHA512]
         // COUNT = 5
         key.reset(new Botan::DH_PublicKey(grp_nist, Botan::BigInt("0x4e2a136cf21a94b4c226fb5c6a4e9be1472acffe8dee6b20f987b1cdf90c6a581a69e2ab25e3615e9ee3681edb2c468af9142fb2d2f4b7333133e107c829e60d00e969c432a204105e75976eea05ee0988dfbbd01cc10d816908b0f616b620d4829ebee50ddd1733d025ebe5abf3d069a3424ec1300d582cd442cacae6f09760cb5f4195fff6fe0c85ac986e14a8b232b33c6f5e7729e0d38fd42fe07f646816e01c6784e029a03663199b2ea6135aee2949f9371045ce7c24a10acd193fb3ed5b53326bae54bf5928fff5548d0877555260ab4475bdade168211fa3a1df87510b08796ebce5ea742112ca7942a7a602d106007a5259624aebb74fe771755050")));
         result.test_eq("public key fails checks", key->check_key(Test::rng(), false), false);

         // COUNT = 7
         key.reset(new Botan::DH_PublicKey(grp_nist, Botan::BigInt("0x347852ff2455951a209b19bb1b8a121f5c77c7899ce540ecad4f740aa14bb6b44374a5d5f1427341817618c6d64c49895d77ceeeb04c3d84d0c360e125cc88ef0751dced4e795c6db1819b10f4d0260ff430e934751b1fef76bd0f1b76d884f56c9c8fb008e9a11f5bf52270845be85d792aa041c70a80d7d5f36dfc6a397b5386f01b09f3e50a896b71358b709ffee900e0edfa79bc03d3aa5a5aed148b92dd859c65bd0aebec19ccd1ec327894242999ea8623b9ae9ff1e71a9deb6c5876ecd9e9c4082299196cd90ff8ce87d697888651d1022e418f47305e685057f0437bebf1b5d77887d2bb3cbd936d7a4a4e948962f5e940bfbca7216ae8dce27df3f4")));
         result.test_eq("public key fails checks", key->check_key(Test::rng(), false), false);

         // COUNT = 13
         key.reset(new Botan::DH_PublicKey(grp_nist, Botan::BigInt("0x6ca0b830ecbd14bf83fa4c1953723c2ddad8fc49e43e10247fec75507258c17b8a48fccc246797369bb45aad921f76ba174a10d81966668f62dc9cd739a9f19839eb26503f4e7db63c14d706a5b44fe0c5a8f7a343941db5f15a7af008e8ea511ed7c002cf949482d50f35471bac48b1594178c9da13c3264bd86181f9ba9e3bd35aaf23c753413137f0a9eca8f52cdbd33d6a4e4bdc14b30405c5175a9f9b54d9f301a39321623d60133910d424f0985ae7478e1865241d096a07d5d37bdd845a85d7d2ae80f3b973827864a638be440c2e10c9ce3d062cd5a444f774cfb981d47baaca437d10756328980f43615245c3137be8bece09e25614f793f8c81c1e")));
         result.test_eq("public key fails checks", key->check_key(Test::rng(), false), false);

         // COUNT = 20
         key.reset(new Botan::DH_PublicKey(grp_nist, Botan::BigInt("0x14065ecaf934ad595e18264d51d79ac23b4b7e82f2f9be8ded8debedd99d59e43f295051ba53bfcfd9bcaf9488641d07e5fd9d1bd3e6ade4c5afe53521d085277d9739ebb70dbc75e531aa2df4ab9f5e9a5efb203c4d9eb2267ca1df7242d68f4fd95a3dac6908a6e3aab3153b27e09f244faebd665ae3196f3b119ff8d1ab30bf4b625a2f30c18c347fb413c02792be1e31fe5a13ade3fd6d068ae2d9e8740707267eb15d326ec0171b90153e2368690160c4073af09885bb215c7a73faf445e24071d5d502803986c6a54288aaf947b67a716d181e822807e82cab3c2bc56620db240a646da43c6091a7ed15c9fa14c7c3a4dde7299fbe908ef65a7d3b29d4")));
         result.test_eq("public key fails checks", key->check_key(Test::rng(), false), false);

         // [FC - SHA512]
         // COUNT = 6
         key.reset(new Botan::DH_PublicKey(grp_nist, Botan::BigInt("0x0596416ae996328fe5a617575711a34ba575a556d4db035ea6c815c8203b0d9f7ca6c7a94cf661196808053edea255540543b63c40ba87f69f418051c3f06394527f0a2741f0d16ee94db40888edd85d4f063cf4e1cfd327505f83a2f3fdf0e83ac4a3f07a57842b15b4cc8e4f14f56ebe01f8dff21609ed0625c99d3745c41219b3791a5a8b544f5f9a891095db63d8be4a0c5b3c9520da5f307524552557b908ad7a978e6bd54ca18f7d55dbc3d75f961cb46d344fcd88c98c56c44f028871e847a01ea8670f58e990fa402a5040d8c7fde63dd38edb5dea1850d193ec53077444517422464df2c463465c169675999e3b0968bf03baf013fcdb05ae484e16")));
         result.test_eq("public key fails checks", key->check_key(Test::rng(), false), false);

         // COUNT = 12
         key.reset(new Botan::DH_PublicKey(grp_nist, Botan::BigInt("0x71a6d5dafd1ef49d84c4cd15b47a9594d05199c3be2190a019ee52c6a844b4cf7a579b7e4d16d3591acd1a04e9298f3d3e65f66cc48629478baf16b51f223f8f13b5f6625ba1c013f078361b0fec44485fedc6a84841e744fd6fd73ad716f55bc9f1d18c45a3d7fbeeba754a3a56f215298ea037532341ffeec2a25a91d9a939ea8607a640ad7731612bc040aa98df944bcf0b37f31389deeae5766d6ff1fb21504689ec1681a71e77926f2602db5700415435eae90dd049c5091d941ae5ea3fd542442f2cccab30869f80b51b9002efb0cbcbbea1e45aeff9a92e3d896d722dc8cbd14211db99b40cbf4ba52473da790ea6531664d98d1cca5d49dbc55dc154")));
         result.test_eq("public key fails checks", key->check_key(Test::rng(), false), false);

         // COUNT = 13
         key.reset(new Botan::DH_PublicKey(grp_nist, Botan::BigInt("0x15d3595dd8a4bf905cc739c92895135467bcadd3ed96e10ec9a07fcf8a1c693653dcc6caa8ded43d63b856f4516e73353557ace6983be82f4c8ff627ed04f3a2d31f9a827b68e65339fdce5c209d801f2bf99ffed9a5965233aab227b5b11926fb1981660f2ec274768cfe9729e5b72d9b3073716885a69c647e3469f6267eaa77d24c9068bac761aa9c0fb0b25721637fa99f4c4c3b76b0a2a3db7507d66d1bdbf922b10ad4105c05ccb96f4874844103e5a1d84bc46a086fd6d981979f7662695d0c1fed108b942bb481bce19328c9e0834348fa251341088f40a004743958aa5b61ef3ab2ef9be7d264334c21a33b695348f169ee244ab5f2bb92c6ff71a7")));
         result.test_eq("public key fails checks", key->check_key(Test::rng(), false), false);

         return{result};
         }

   };

BOTAN_REGISTER_TEST("dh_kat", Diffie_Hellman_KAT_Tests);

class Diffie_Hellman_Keygen_Tests : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override { return { "modp/ietf/1024", "modp/ietf/2048" }; }
      std::string algo_name() const override { return "DH"; }
   };


BOTAN_REGISTER_TEST("dh_keygen", Diffie_Hellman_Keygen_Tests);

#endif

}

}
