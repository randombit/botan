/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bls12_381.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/bls12_381_fields.h>
#include <botan/internal/mp_core.h>
#include <botan/internal/xmd.h>

namespace Botan::BLS12_381 {

namespace {

// G1 SSWU (RFC 9380 8.8.1) and 11-isogeny (E.2) constants, pre-converted to Montgomery
constexpr auto G1_SSWU_A = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "155455c3e5071d8528376eda6bfc183527e11c91b5f24e7cb85ce591b7bd31e286464c2d1e8416c32f65aa0e9af5aa51"));
constexpr auto G1_SSWU_B = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "06824061418a386bca72b5e45a52d888873e27c3a221e5718c476013de99c5c49aa93eb35b742d6ffb996971fe22a1e0"));
constexpr auto G1_SSWU_Z = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "078c712fbe0ab6e850553f1b9c1315219dac23e943dc174077672417ed5828c30f70008d3090001d886c00000023ffdc"));

constexpr std::array<FieldElement, 12> G1_ISO_XNUM = {
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0913be200a20bef4d15b58d2ffc0005423dcea34f2ffb3043f2885f1467f19ae19fa219793fee28c4d18b6f3af00131c")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "07097bc5998784ad11b22deed20d827b8637ef1e4d6623ad1597e193f4cd233a3c79e43cc7d966aa898985385cdbbd8b")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0784151ed7605524df6e99707d2a00795b5491c05102f0e75ba2ef314ed8b5a6fc7169c026e568c6a542583a480b664b")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0e93d431ea011aeb65dadd7828505289049dfee82aefbd6026f5577994e34c3dab9be52fbda43021494e212870f72741")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "09f20ead8e532bf6169139d319ea7a8f104c24211be4805c0f1a8953b325f4647ada1c8a41bfb18590ee774bd6a74d45")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "18f4bfcbb4368929b0282d480e56489f2e0a94ccf77ec0db143245631883f4bda5482c9aa1ccd7bd6ddd93e2f43626b7")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "1277ffc72f25e8feffd89869a572b297d0df5c98e1f9d70f2c390d3d2da5df637a43ff6958ce4fe923c5f0c953402dfd")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "08b76279f621d028bba074f260e400f1e2a57f6505880d6512da3054b18b641085f894a88030fd8179f4f0490f06a8a6")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "09e699dd9adfa5ac05a69cdcef55feeee21585b9a30f86cb7888bff6e6b33bb48456ba9a1f186475e67245ba78d5b00b")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "098c4bf7de8b63750443915f50fd41798ad456574e9db24fe256bb67b3b3cd8d0a0db4ae6b1a10b20de5c357bff57107")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "054fdf4bbf1d821c4a51d8667f0fe1cfe4efd1ad3f767ceb1dafdeda137a489efe6e37d442537375e6b0617e7dd929c7")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "18ae6a856f40715db14f01aadb30be2f464170142a1009ebe969d6833764ab478abf91faa257b3d572db2a50658d767b")),
};
constexpr std::array<FieldElement, 11> G1_ISO_XDEN = {
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0165aa6c93ad115f9c0b3ac929599016b43fc37b908b133ec14d568c3ed6c544a6a9740fefda13a0b962a077fdb0f945")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "083383d6ed81f1ceed4530924cec2045116dda1c5070ae933b294ab13755f0ff92cfca0a9465176a23279a3ba506c1d9")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0f29c13c660523e2ff364f36e54b6812a0fba72732b3fafd17da9ffd8738c1424a2b54ccd37733f09885c2a6449fecfc")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "12025184f407440c1c2c7844bc417be443a92bd69c15c2dfc9d325849ade5150d487228f2f3204fbe349cc118278f041")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "13b93c63edf6c0157408904f0f186bb2ccda066072436a42fbf995e71270da491444ef325140201f587f65ae6acb057b")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "06cc402dd594bbebaeedd424d780f38830f94df6f83a3dc20beb232927f7fb264a4c64423ecaddb4fb918622cd141920")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0c6f7f7237b466066933a38d5b594c81df70a9a1f757c6e464f436e888c62cb932a92465435719b3d41f761151b23f8f")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "17916987aa14a122bc6be2d8dad57c2389bc62d61c7baf238e9071dab950c12422c9850bf9cf80f0693c08747876c8f7")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0c102cbac531bb34bbc2ee18e1c227f432c6aa9af394361cc7f7f62962f5cd819965243a7571dfa71be3ff439c1316fd")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "12a6dcd7f0f4e0e816178f5bbf698711ca2b066c2a87492f5b8c95fc14353fc361f86372b99192c0997614c97bacbf07")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd")),
};
constexpr std::array<FieldElement, 16> G1_ISO_YNUM = {
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0d300744d42a03107d7b18a682692693cc31a30a0b6cd3dfce028fea04bd73731d4d9e57b958a7672b567ff3e2837267")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0a8dadd9c2414555706326a6957dd5a414e03832052b49c85df0608b8f97608afe7f53cc4874f87899c2555fa542493f")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "13f70bf38bbf290583d0c7532f8c1fde0000bd1de7ba50f0cf05a27c8456088d357e33e36e261e7d13d942922a5cf63a")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0bb6cde49d8ba257b3468f4550192bf7afe19ff6f97e6d533983ceb4f6360b6d28a359a65e5417075c57fd95bfafbdbb")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0386213c651b888d64eace4cb09821916ddf84a095713d5f6bef32ce94b8a800314b4ce372cacefd590b62c7ff8a513f")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "01fddf5aed881793cf5b1f022e1c9107aa6ec095283ee4a7f9ad9cc95423d2e9a14ac0f5da148982a5310a31111bbcdd")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "07eb1b29c1dfde1fba12961be86e9efb05b2d36c769a89b0c2fcebe7cb877dbde25c2d8183473a1965a572b0d7a7d950")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0ad52ba3e6695a79f4fa918082e44d64a47da89439f5340f8569467e68af51b5364e92907679509193e09572f7c4cd24")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "149c9c326a5e7393a90ed5adf1ed5537fa86d2a3a9a734823d587e5640536e66d03f51a3516bb233911429844e0d5f54")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "1862bd62c291dacb8100e1652b3cdc62649ef8f11a4fae469a558ebde836ebeddc9af5fa0a274a17462bbeb03c12921a")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "12c7e1c3b28962e5bb1d0d53af3ff6bf14665bdd8846e19d6a643d5a6879fa2c0194160fa9b9ac4f05c9b8ca89f12c26")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "02419f98165871a4389547f2334a53910dfbd15dc41a594d1f07db10ea1a4df4fedc77ec1a9201c4b55ebf900b8a3e17")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0d2d7b829ce324d28346fe421f96bb1301458ef0159ebbef7c763e17763a06528e563e9d1ea6d0f5b416af000745fc20")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "046959cfcfd0bf49724b136c4cf2d9faf563e63704f7092f8f66b3ea59514fa46f2a2619951d823a93096bb538d64615")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "1017290919210e5f07f897e267a33f1ba06731f1d2bbe1ee41064965946d9b5991e9079c2c02d58fea748d4b6e405346")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "106d87d1b51d13b9c4b92d15db8acca854759078e5be683807afe37afff55002eecc53161264562a872aa6c17d985097")),
};
constexpr std::array<FieldElement, 16> G1_ISO_YDEN = {
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0a8b981ee47691f152f45700b70d5c69723e71dcc5fc1323ddfa71a0889d5b7e18ef5f8a10634d60eb6c359d47e52b1c")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0fadeff77b6bfe3e6a33dca5235607763e50dffea3c62658f25f4cc5e35c65da6f5f037395dbd911616a3c4f5535b9fb")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "01c2a7a256fe9c4104fe8bb2b8d81af4b6634a652ee5884d115dbe7ad10c2a3724a2c159a3d367422be9b66df470059c")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "11037cd58b3dbfbd59b0c17f7631448ac8e0bbd6fe11080624482e6b8c2f4e5f898b367476c9073ff27bf8ef3b75a386")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "044393bb632d94fbb1cce69b6aa9ad9a3cae528fbee9a2a4d30d4fe3ba86fdb11dbf6f1c5fcdb70031c7912ea267eec6")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "096c3a09773272d40e49df01d942a628104fc1aafb0919cc71b1a4d2f119981d9824c289dd72bb55c66ef6efeeb5c7e8")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0c81d4645f4cb6edd466a75599ce728ec4b76271ea6506b3fb1fa3721569734c32dca50a885728f09abc11eb5fadeff4")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0d3378023e4c7406f08d33680a2374659e9efb24aa6424c6cb353efe9b33e4ffda64e495b1e879304199f10e5b8be45b")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0ef3c33371e2fdb5564c2935a96bfa9303bfd9cca75cbdeb5be603899e907687c341b4aa9fac34977eb4ae92ec74d3a5")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0d22d5a40cec7cff6cb95e0fa776aeadd0fda172174ed023773a8ca5196b1380e5d5bd5cb9357a307ee91fd449f6ac2e")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0467ffaef23fc49efce95ebdeb5b490a178419613d90d8f87549d8bd057894aedc9d55a83017897bf727e09285fd8519")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "116aefa749127bff828e0f1e772a53cd6e20829e5c230c455461c75a23ede3b579bc930deac01c03c1769e6a7c385f1b")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "189e5fe4470cd73cb9000209d5bd08d3fc009d4996dc5153a0ecf39ef026f602bbf18d053a6a3154101c10bf2744c10a")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "13dddbc4799d81d698738983c2107ff3b0a1ba04228520cc57b2b625b6d4ca21e47d5a981d081b557ebd546ca1575ed2")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "0ef9c24eccaf5e0efb95832e7d78742efd04e3dfc608646755ba77a9a2f76493039e952cbdb05c2109319f2e39834935")),
   FieldElement::_unchecked_from_words(hex_to_words<word>(
      "15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd")),
};

// The precomputed values -B/A and B/(Z*A) (RFC 9380 6.6.2)
constexpr auto G1_SSWU_C1 = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "097cab54770ca0d399fffd1f34fc181d2527e7dc638517671b75faa0105ec9833b40d72430f93c82052583c93555a7fe"));
constexpr auto G1_SSWU_C2 = FieldElement::_unchecked_from_words(hex_to_words<word>(
   "1469e7cf3b7ec553bb16a0c0d526ff964ed257417860c764af05f2a3b113ce5770cca69e8ca26edcaefbc579583dc22f"));

// h_eff = 0xD201000000010001 (RFC 9380 8.8.1)
constexpr uint64_t G1_H_EFF = 0xD201000000010001;

// G2 SSWU (RFC 9380 8.8.2) and 3-isogeny (E.3) constants, preconverted to Montgomery
constexpr auto G2_SSWU_A = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
   hex_to_words<word>(
      "1220b4e979ea546702d6985717c744ab0b51375126310601e7889edbe340f6bd01080c0fdef80285e53a000003135242"));

constexpr auto G2_SSWU_B = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "125cdb5e74dc4fd13dd3a569412c0a3475bf3c53a79473ba6e1b94403db5a66e6ec832df71380aa422ea00000cf89db2"),
   hex_to_words<word>(
      "125cdb5e74dc4fd13dd3a569412c0a3475bf3c53a79473ba6e1b94403db5a66e6ec832df71380aa422ea00000cf89db2"));

constexpr auto G2_SSWU_Z = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "0815664c7dfe040dde291a3d41e980d3d951e663066576f40fd0749345d33ad2656fffe5da8ffffa87ebfffffff9555c"),
   hex_to_words<word>(
      "040ab3263eff0206ef148d1ea0f4c069eca8f3318332bb7a07e83a49a2e99d6932b7fff2ed47fffd43f5fffffffcaaae"));

// The precomputed values -B/A and B/(Z*A) (RFC 9380 6.6.2)
constexpr auto G2_SSWU_C1 = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "0e7146f483e23a05467a4ad10ee6de53c68946b6aebbd0629f8e582eefe0fade5f98cc95ce451105903c555555474fb3"),
   hex_to_words<word>(
      "0b8fcaf5b59dac9504a15ce53464ce839dee04ce44c9425cc7a27a7206cffb45bf133368e30eeefa29c2aaaaaab85af8"));

constexpr auto G2_SSWU_C2 = FieldElement2::_unchecked_from_words(
   hex_to_words<word>(
      "127db28a3ce062c407f5d9fd91c1fa91fd963b744ea89b535dd35cd05d972c422585c28393a69d00f2d8444444414324"),
   hex_to_words<word>(
      "168a1e1ff5de8b82c971692a149d16d034a33031ee9566441c186171cb4d5da5eb72b871590828fc55743333333b3695"));

constexpr std::array<FieldElement2, 4> G2_ISO_XNUM = {
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "13808f550920ea41c54516acc8d037f6048103ea9e6cd0627c80cd2af3fd71a206dd57071206393e47f671c71ce05e62"),
      hex_to_words<word>(
         "13808f550920ea41c54516acc8d037f6048103ea9e6cd0627c80cd2af3fd71a206dd57071206393e47f671c71ce05e62")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
      hex_to_words<word>(
         "0ac73310a7fd5abd2836cda7028cabc521c28884088749456a6b4619b26ef918873fffdd236aaaa35fe55555554c71d0")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "149d7861e581393bb70040e2c20556f4d3960742ef416e1cb1fb2f941d797997db0c00101f9eaaae0a0c5555555971c3"),
      hex_to_words<word>(
         "0563998853fead5e941b66d3814655e290e144420443a4a2b535a30cd9377c8c439fffee91b55551aff2aaaaaaa638e8")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "198e1a74328002d2696eb479f885d059d86485d4c87f6fb1d817050a8f41abc3190955557a84e38e40aac71c71c725ed"),
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
};
constexpr std::array<FieldElement2, 3> G2_ISO_XDEN = {
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
      hex_to_words<word>(
         "04f69db13f39a95203977bc86095b0893e6427366f8cec18ca3757cb3819b208f25bfc611da3ff3e1f3affffff13ab97")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "0381be097f0bb4e16140b1fcfb1e54b7b10330b7c0a95bc66f7ee9ce4a6e8b59dcb8009a43480020447600000027552e"),
      hex_to_words<word>(
         "167f53e0ba7431b8e9daf5b9482d581fb3741acd32dbb6f8f7b1e8d2ac426aca41f3ff646e0bffdf7588ffffffd8557d")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd"),
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
};

constexpr std::array<FieldElement2, 4> G2_ISO_YNUM = {
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "08c8055e31c5d5c30fd2e39eada3eba957cb23ecfae804e1184a88ff379652fdb530e4f43b66d0e296d8f684bdfc77be"),
      hex_to_words<word>(
         "08c8055e31c5d5c30fd2e39eada3eba957cb23ecfae804e1184a88ff379652fdb530e4f43b66d0e296d8f684bdfc77be")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
      hex_to_words<word>(
         "0c7d13420b09807f02c3b2b2d2938e86a27aa27b1d1a18d59d82f98e5f205aee4d6d55d28b7638fdbf0a71c71c91b406")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "02b1ccc429ff56af4a0db369c0a32af14870a2210221d2515a9ad1866c9bbe4621cffff748daaaa8d7f9555555531c74"),
      hex_to_words<word>(
         "174f45260f808feb010df44c82a881e61c06a963f163406e0c96011a8a1537ddfcdc000768795556e205aaaaaaac8e37")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "117c5e6e28aa905427f6c0e2f07467641c55c9935b5a982ec9d3d0f2c6f0678dc0fe38e23327b425a470bda12f67f35c"),
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
};
constexpr std::array<FieldElement2, 4> G2_ISO_YDEN = {
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "03c6a03d41da1151ca713efc0036766011e19fc1a9c875d5561b3c2259e936118f7bea480083fb750162fffffa765adf"),
      hex_to_words<word>(
         "03c6a03d41da1151ca713efc0036766011e19fc1a9c875d5561b3c2259e936118f7bea480083fb750162fffffa765adf")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
      hex_to_words<word>(
         "0ee3d913bdacfbf60ac6735921c1119bbb2c75a34ea6c44a5ea60761a84d161ad713f52358ebfdba5db0fffffd3b02c5")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "05429d0e3e918f5211e10afb78ad7f138984c913a0fe09a9a73e5eb56fa5d106cb1400e764ec003066b10000003affc5"),
      hex_to_words<word>(
         "14be74dbfaee5748393a9cbaca9e2dc3daf2827152870915bff273eb870b251d5397ff174c67ffcf534dffffffc4aae6")),
   FieldElement2::_unchecked_from_words(
      hex_to_words<word>(
         "15f65ec3fa80e4935c071a97a256ec6d77ce5853705257455f48985753c758baebf4000bc40c0002760900000002fffd"),
      hex_to_words<word>(
         "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
};

constexpr size_t H2C_L = 64;

FieldElement fe_from_uniform(std::span<const uint8_t> bytes64) {
   std::array<uint8_t, 96> padded{};
   copy_mem(padded.data() + 32, bytes64.data(), 64);
   return FieldElement::from_bytes_wide(padded);
}

uint8_t sgn0(const FieldElement& x) {
   return x.serialize()[FieldElement::BYTES - 1] & 1;
}

uint8_t sgn0(const FieldElement2& x) {
   // RFC 9380 4.1 sgn0 for extension fields, on (c0, c1)
   const uint8_t sign_0 = sgn0(x.c0());
   const uint8_t zero_0 = x.c0().is_zero().into_bitmask<uint8_t>() & 1;
   const uint8_t sign_1 = sgn0(x.c1());
   return sign_0 | (zero_0 & sign_1);
}

template <typename FE, size_t N>
FE eval_polynomial(const std::array<FE, N>& coeffs, const FE& x) {
   auto acc = coeffs[N - 1];
   for(size_t i = N - 1; i > 0; --i) {
      acc = acc * x + coeffs[i - 1];
   }
   return acc;
}

/**
* Simplified SWU for AB == 0 (RFC 9380 6.6.2 and 6.6.3), returning an
* affine point on the isogenous curve E': y^2 = x^3 + A*x + B
*
* C1 and C2 are the precomputed constants -B/A and B/(Z*A)
*/
template <typename FE>
std::pair<FE, FE> map_to_curve_sswu(const FE& u, const FE& A, const FE& B, const FE& Z, const FE& C1, const FE& C2) {
   const auto zu2 = Z * u.square();

   // invert() maps zero to zero, as inv0 requires
   const auto tv1 = (zu2.square() + zu2).invert();

   FE x1;
   if(tv1.is_zero().as_bool()) {
      // x1 = B / (Z * A)
      x1 = C2;
   } else {
      // x1 = (-B / A) * (1 + tv1)
      x1 = C1 * (FE::one() + tv1);
   }

   const auto gx1 = (x1.square() + A) * x1 + B;
   const auto x2 = zu2 * x1;
   const auto gx2 = (x2.square() + A) * x2 + B;

   FE x;
   FE y;
   if(const auto y1 = gx1.sqrt()) {
      x = x1;
      y = *y1;
   } else {
      const auto y2 = gx2.sqrt();
      BOTAN_ASSERT_NOMSG(y2.has_value());
      x = x2;
      y = *y2;
   }

   if(sgn0(u) != sgn0(y)) {
      y = y.negate();
   }

   return {x, y};
}

std::optional<std::pair<FieldElement, FieldElement>> map_to_curve_g1(const FieldElement& u) {
   const auto [xp, yp] = map_to_curve_sswu(u, G1_SSWU_A, G1_SSWU_B, G1_SSWU_Z, G1_SSWU_C1, G1_SSWU_C2);

   // The 11-isogeny map from E' to E (RFC 9380 E.2)
   const auto xnum = eval_polynomial(G1_ISO_XNUM, xp);
   const auto xden = eval_polynomial(G1_ISO_XDEN, xp);
   const auto ynum = eval_polynomial(G1_ISO_YNUM, xp);
   const auto yden = eval_polynomial(G1_ISO_YDEN, xp);

   if((xden.is_zero() || yden.is_zero()).as_bool()) {
      // The exceptional case maps to the point at infinity
      return {};
   }

   // One shared inversion for both denominators
   const auto den_inv = (xden * yden).invert();

   return std::pair{xnum * yden * den_inv, yp * ynum * xden * den_inv};
}

std::optional<std::pair<FieldElement2, FieldElement2>> map_to_curve_g2(const FieldElement2& u) {
   const auto [xp, yp] = map_to_curve_sswu(u, G2_SSWU_A, G2_SSWU_B, G2_SSWU_Z, G2_SSWU_C1, G2_SSWU_C2);

   // The 3-isogeny map from E' to E (RFC 9380 E.3)
   const auto xnum = eval_polynomial(G2_ISO_XNUM, xp);
   const auto xden = eval_polynomial(G2_ISO_XDEN, xp);
   const auto ynum = eval_polynomial(G2_ISO_YNUM, xp);
   const auto yden = eval_polynomial(G2_ISO_YDEN, xp);

   if((xden.is_zero() || yden.is_zero()).as_bool()) {
      // The exceptional case maps to the point at infinity
      return {};
   }

   // One shared inversion for both denominators
   const auto den_inv = (xden * yden).invert();

   return std::pair{xnum * yden * den_inv, yp * ynum * xden * den_inv};
}

G1Projective clear_cofactor_g1(const G1Projective& pt) {
   // Multiplication by h_eff (RFC 9380 8.8.1)
   auto accum = G1Projective::identity();
   for(size_t b = 64; b > 0; --b) {
      accum = accum.add(accum);
      if(((G1_H_EFF >> (b - 1)) & 1) == 1) {
         accum = accum.add(pt);
      }
   }
   return accum;
}

template <size_t N>
std::array<uint8_t, N> bls_expand_message(std::span<const uint8_t> input, std::span<const uint8_t> dst) {
   if(dst.empty()) {
      // RFC 9380 section 3.1: "Tags MUST have nonzero length."
      throw Invalid_Argument("BLS12_381 requires a non-empty domain separation tag");
   }

   // Tags longer than 255 bytes are handled inside expand_message_xmd,
   // by hashing per RFC 9380 section 5.3.3
   std::array<uint8_t, N> output{};
   expand_message_xmd("SHA-256", output, input, dst);
   return output;
}

}  // namespace

//static
Scalar Scalar::hash(std::span<const uint8_t> input, std::span<const uint8_t> dst) {
   // L = ceil((ceil(log2(r)) + k) / 8) = 48, for k = 128 (RFC 9380)
   auto uniform = bls_expand_message<48>(input, dst);

   std::array<uint8_t, 64> padded{};
   copy_mem(padded.data() + padded.size() - uniform.size(), uniform.data(), uniform.size());
   const auto s = Scalar::from_bytes_wide(padded);

   // The result may be a secret (eg a key derived from a seed)
   secure_scrub_memory(uniform);
   secure_scrub_memory(padded);

   return s;
}

namespace {

G1Projective g1_from_mapped(const std::optional<std::pair<FieldElement, FieldElement>>& m) {
   return m ? G1Projective::_unchecked_from_affine_coords(m->first, m->second) : G1Projective::identity();
}

G2Projective g2_from_mapped(const std::optional<std::pair<FieldElement2, FieldElement2>>& m) {
   return m ? G2Projective::_unchecked_from_affine_coords(m->first, m->second) : G2Projective::identity();
}

}  // namespace

//static
G1Projective G1Projective::hash_to_curve_ro(std::span<const uint8_t> input, std::span<const uint8_t> dst) {
   const auto uniform = bls_expand_message<2 * H2C_L>(input, dst);

   const auto u0 = fe_from_uniform(std::span{uniform}.first<H2C_L>());
   const auto u1 = fe_from_uniform(std::span{uniform}.last<H2C_L>());

   const auto q0 = g1_from_mapped(map_to_curve_g1(u0));
   const auto q1 = g1_from_mapped(map_to_curve_g1(u1));

   return clear_cofactor_g1(q0.add(q1));
}

//static
G1Projective G1Projective::hash_to_curve_nu(std::span<const uint8_t> input, std::span<const uint8_t> dst) {
   const auto uniform = bls_expand_message<H2C_L>(input, dst);

   return clear_cofactor_g1(g1_from_mapped(map_to_curve_g1(fe_from_uniform(uniform))));
}

//static
G2Projective G2Projective::hash_to_curve_ro(std::span<const uint8_t> input, std::span<const uint8_t> dst) {
   const auto uniform = bls_expand_message<4 * H2C_L>(input, dst);

   const auto us = std::span{uniform};
   const auto u0 = FieldElement2(fe_from_uniform(us.subspan(0, H2C_L)), fe_from_uniform(us.subspan(H2C_L, H2C_L)));
   const auto u1 =
      FieldElement2(fe_from_uniform(us.subspan(2 * H2C_L, H2C_L)), fe_from_uniform(us.subspan(3 * H2C_L, H2C_L)));

   const auto q0 = g2_from_mapped(map_to_curve_g2(u0));
   const auto q1 = g2_from_mapped(map_to_curve_g2(u1));

   return q0.add(q1).clear_cofactor();
}

//static
G2Projective G2Projective::hash_to_curve_nu(std::span<const uint8_t> input, std::span<const uint8_t> dst) {
   const auto uniform = bls_expand_message<2 * H2C_L>(input, dst);

   const auto u = FieldElement2(fe_from_uniform(std::span{uniform}.first<H2C_L>()),
                                fe_from_uniform(std::span{uniform}.last<H2C_L>()));

   return g2_from_mapped(map_to_curve_g2(u)).clear_cofactor();
}

}  // namespace Botan::BLS12_381
