/*
* Whirlpool
* (C) 1999-2007,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/whirlpool.h>

#include <botan/internal/loadstor.h>
#include <botan/internal/rotate.h>

namespace Botan {

namespace {

alignas(256) const uint64_t WHIRL_S[256] = {
0x18186018C07830D8, 0x23238C2305AF4626, 0xC6C63FC67EF991B8, 0xE8E887E8136FCDFB,
0x878726874CA113CB, 0xB8B8DAB8A9626D11, 0x0101040108050209, 0x4F4F214F426E9E0D,
0x3636D836ADEE6C9B, 0xA6A6A2A6590451FF, 0xD2D26FD2DEBDB90C, 0xF5F5F3F5FB06F70E,
0x7979F979EF80F296, 0x6F6FA16F5FCEDE30, 0x91917E91FCEF3F6D, 0x52525552AA07A4F8,
0x60609D6027FDC047, 0xBCBCCABC89766535, 0x9B9B569BACCD2B37, 0x8E8E028E048C018A,
0xA3A3B6A371155BD2, 0x0C0C300C603C186C, 0x7B7BF17BFF8AF684, 0x3535D435B5E16A80,
0x1D1D741DE8693AF5, 0xE0E0A7E05347DDB3, 0xD7D77BD7F6ACB321, 0xC2C22FC25EED999C,
0x2E2EB82E6D965C43, 0x4B4B314B627A9629, 0xFEFEDFFEA321E15D, 0x575741578216AED5,
0x15155415A8412ABD, 0x7777C1779FB6EEE8, 0x3737DC37A5EB6E92, 0xE5E5B3E57B56D79E,
0x9F9F469F8CD92313, 0xF0F0E7F0D317FD23, 0x4A4A354A6A7F9420, 0xDADA4FDA9E95A944,
0x58587D58FA25B0A2, 0xC9C903C906CA8FCF, 0x2929A429558D527C, 0x0A0A280A5022145A,
0xB1B1FEB1E14F7F50, 0xA0A0BAA0691A5DC9, 0x6B6BB16B7FDAD614, 0x85852E855CAB17D9,
0xBDBDCEBD8173673C, 0x5D5D695DD234BA8F, 0x1010401080502090, 0xF4F4F7F4F303F507,
0xCBCB0BCB16C08BDD, 0x3E3EF83EEDC67CD3, 0x0505140528110A2D, 0x676781671FE6CE78,
0xE4E4B7E47353D597, 0x27279C2725BB4E02, 0x4141194132588273, 0x8B8B168B2C9D0BA7,
0xA7A7A6A7510153F6, 0x7D7DE97DCF94FAB2, 0x95956E95DCFB3749, 0xD8D847D88E9FAD56,
0xFBFBCBFB8B30EB70, 0xEEEE9FEE2371C1CD, 0x7C7CED7CC791F8BB, 0x6666856617E3CC71,
0xDDDD53DDA68EA77B, 0x17175C17B84B2EAF, 0x4747014702468E45, 0x9E9E429E84DC211A,
0xCACA0FCA1EC589D4, 0x2D2DB42D75995A58, 0xBFBFC6BF9179632E, 0x07071C07381B0E3F,
0xADAD8EAD012347AC, 0x5A5A755AEA2FB4B0, 0x838336836CB51BEF, 0x3333CC3385FF66B6,
0x636391633FF2C65C, 0x02020802100A0412, 0xAAAA92AA39384993, 0x7171D971AFA8E2DE,
0xC8C807C80ECF8DC6, 0x19196419C87D32D1, 0x494939497270923B, 0xD9D943D9869AAF5F,
0xF2F2EFF2C31DF931, 0xE3E3ABE34B48DBA8, 0x5B5B715BE22AB6B9, 0x88881A8834920DBC,
0x9A9A529AA4C8293E, 0x262698262DBE4C0B, 0x3232C8328DFA64BF, 0xB0B0FAB0E94A7D59,
0xE9E983E91B6ACFF2, 0x0F0F3C0F78331E77, 0xD5D573D5E6A6B733, 0x80803A8074BA1DF4,
0xBEBEC2BE997C6127, 0xCDCD13CD26DE87EB, 0x3434D034BDE46889, 0x48483D487A759032,
0xFFFFDBFFAB24E354, 0x7A7AF57AF78FF48D, 0x90907A90F4EA3D64, 0x5F5F615FC23EBE9D,
0x202080201DA0403D, 0x6868BD6867D5D00F, 0x1A1A681AD07234CA, 0xAEAE82AE192C41B7,
0xB4B4EAB4C95E757D, 0x54544D549A19A8CE, 0x93937693ECE53B7F, 0x222288220DAA442F,
0x64648D6407E9C863, 0xF1F1E3F1DB12FF2A, 0x7373D173BFA2E6CC, 0x12124812905A2482,
0x40401D403A5D807A, 0x0808200840281048, 0xC3C32BC356E89B95, 0xECEC97EC337BC5DF,
0xDBDB4BDB9690AB4D, 0xA1A1BEA1611F5FC0, 0x8D8D0E8D1C830791, 0x3D3DF43DF5C97AC8,
0x97976697CCF1335B, 0x0000000000000000, 0xCFCF1BCF36D483F9, 0x2B2BAC2B4587566E,
0x7676C57697B3ECE1, 0x8282328264B019E6, 0xD6D67FD6FEA9B128, 0x1B1B6C1BD87736C3,
0xB5B5EEB5C15B7774, 0xAFAF86AF112943BE, 0x6A6AB56A77DFD41D, 0x50505D50BA0DA0EA,
0x45450945124C8A57, 0xF3F3EBF3CB18FB38, 0x3030C0309DF060AD, 0xEFEF9BEF2B74C3C4,
0x3F3FFC3FE5C37EDA, 0x55554955921CAAC7, 0xA2A2B2A2791059DB, 0xEAEA8FEA0365C9E9,
0x656589650FECCA6A, 0xBABAD2BAB9686903, 0x2F2FBC2F65935E4A, 0xC0C027C04EE79D8E,
0xDEDE5FDEBE81A160, 0x1C1C701CE06C38FC, 0xFDFDD3FDBB2EE746, 0x4D4D294D52649A1F,
0x92927292E4E03976, 0x7575C9758FBCEAFA, 0x06061806301E0C36, 0x8A8A128A249809AE,
0xB2B2F2B2F940794B, 0xE6E6BFE66359D185, 0x0E0E380E70361C7E, 0x1F1F7C1FF8633EE7,
0x6262956237F7C455, 0xD4D477D4EEA3B53A, 0xA8A89AA829324D81, 0x96966296C4F43152,
0xF9F9C3F99B3AEF62, 0xC5C533C566F697A3, 0x2525942535B14A10, 0x59597959F220B2AB,
0x84842A8454AE15D0, 0x7272D572B7A7E4C5, 0x3939E439D5DD72EC, 0x4C4C2D4C5A619816,
0x5E5E655ECA3BBC94, 0x7878FD78E785F09F, 0x3838E038DDD870E5, 0x8C8C0A8C14860598,
0xD1D163D1C6B2BF17, 0xA5A5AEA5410B57E4, 0xE2E2AFE2434DD9A1, 0x616199612FF8C24E,
0xB3B3F6B3F1457B42, 0x2121842115A54234, 0x9C9C4A9C94D62508, 0x1E1E781EF0663CEE,
0x4343114322528661, 0xC7C73BC776FC93B1, 0xFCFCD7FCB32BE54F, 0x0404100420140824,
0x51515951B208A2E3, 0x99995E99BCC72F25, 0x6D6DA96D4FC4DA22, 0x0D0D340D68391A65,
0xFAFACFFA8335E979, 0xDFDF5BDFB684A369, 0x7E7EE57ED79BFCA9, 0x242490243DB44819,
0x3B3BEC3BC5D776FE, 0xABAB96AB313D4B9A, 0xCECE1FCE3ED181F0, 0x1111441188552299,
0x8F8F068F0C890383, 0x4E4E254E4A6B9C04, 0xB7B7E6B7D1517366, 0xEBEB8BEB0B60CBE0,
0x3C3CF03CFDCC78C1, 0x81813E817CBF1FFD, 0x94946A94D4FE3540, 0xF7F7FBF7EB0CF31C,
0xB9B9DEB9A1676F18, 0x13134C13985F268B, 0x2C2CB02C7D9C5851, 0xD3D36BD3D6B8BB05,
0xE7E7BBE76B5CD38C, 0x6E6EA56E57CBDC39, 0xC4C437C46EF395AA, 0x03030C03180F061B,
0x565645568A13ACDC, 0x44440D441A49885E, 0x7F7FE17FDF9EFEA0, 0xA9A99EA921374F88,
0x2A2AA82A4D825467, 0xBBBBD6BBB16D6B0A, 0xC1C123C146E29F87, 0x53535153A202A6F1,
0xDCDC57DCAE8BA572, 0x0B0B2C0B58271653, 0x9D9D4E9D9CD32701, 0x6C6CAD6C47C1D82B,
0x3131C43195F562A4, 0x7474CD7487B9E8F3, 0xF6F6FFF6E309F115, 0x464605460A438C4C,
0xACAC8AAC092645A5, 0x89891E893C970FB5, 0x14145014A04428B4, 0xE1E1A3E15B42DFBA,
0x16165816B04E2CA6, 0x3A3AE83ACDD274F7, 0x6969B9696FD0D206, 0x09092409482D1241,
0x7070DD70A7ADE0D7, 0xB6B6E2B6D954716F, 0xD0D067D0CEB7BD1E, 0xEDED93ED3B7EC7D6,
0xCCCC17CC2EDB85E2, 0x424215422A578468, 0x98985A98B4C22D2C, 0xA4A4AAA4490E55ED,
0x2828A0285D885075, 0x5C5C6D5CDA31B886, 0xF8F8C7F8933FED6B, 0x8686228644A411C2 };

}

/*
* Whirlpool Compression Function
*/
void Whirlpool_Impl::compress_n(Whirlpool_Impl::digest_type& digest, const uint8_t in[], size_t blocks)
   {
   static const uint64_t RC[10] = {
      0x1823C6E887B8014F, 0x36A6D2F5796F9152,
      0x60BC9B8EA30C7B35, 0x1DE0D7C22E4BFE57,
      0x157737E59FF04ADA, 0x58C9290AB1A06B85,
      0xBD5D10F4CB3E0567, 0xE427418BA77D95D8,
      0xFBEE7C66DD17479E, 0xCA2DBF07AD5A8333
   };

   uint64_t M[8];

   for(size_t i = 0; i != blocks; ++i)
      {
      load_be(M, in, 8);

      uint64_t K0 = digest[0];
      uint64_t K1 = digest[1];
      uint64_t K2 = digest[2];
      uint64_t K3 = digest[3];
      uint64_t K4 = digest[4];
      uint64_t K5 = digest[5];
      uint64_t K6 = digest[6];
      uint64_t K7 = digest[7];

      uint64_t B0 = K0 ^ M[0];
      uint64_t B1 = K1 ^ M[1];
      uint64_t B2 = K2 ^ M[2];
      uint64_t B3 = K3 ^ M[3];
      uint64_t B4 = K4 ^ M[4];
      uint64_t B5 = K5 ^ M[5];
      uint64_t B6 = K6 ^ M[6];
      uint64_t B7 = K7 ^ M[7];

      for(size_t j = 0; j != 10; ++j)
         {
         uint64_t T0, T1, T2, T3, T4, T5, T6, T7;
         T0 = WHIRL_S[get_byte<0>(K0)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K7)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K6)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K5)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K4)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K3)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K2)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K1)]) ^ RC[j];

         T1 = WHIRL_S[get_byte<0>(K1)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K0)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K7)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K6)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K5)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K4)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K3)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K2)]);
         T2 = WHIRL_S[get_byte<0>(K2)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K1)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K0)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K7)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K6)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K5)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K4)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K3)]);
         T3 = WHIRL_S[get_byte<0>(K3)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K2)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K1)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K0)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K7)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K6)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K5)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K4)]);
         T4 = WHIRL_S[get_byte<0>(K4)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K3)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K2)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K1)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K0)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K7)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K6)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K5)]);
         T5 = WHIRL_S[get_byte<0>(K5)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K4)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K3)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K2)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K1)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K0)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K7)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K6)]);
         T6 = WHIRL_S[get_byte<0>(K6)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K5)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K4)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K3)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K2)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K1)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K0)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K7)]);
         T7 = WHIRL_S[get_byte<0>(K7)] ^
            rotr<8>(WHIRL_S[get_byte<1>(K6)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(K5)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(K4)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(K3)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(K2)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(K1)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(K0)]);

         K0 = T0; K1 = T1; K2 = T2; K3 = T3;
         K4 = T4; K5 = T5; K6 = T6; K7 = T7;

         T0 = WHIRL_S[get_byte<0>(B0)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B7)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B6)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B5)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B4)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B3)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B2)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B1)]) ^ K0;
         T1 = WHIRL_S[get_byte<0>(B1)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B0)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B7)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B6)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B5)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B4)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B3)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B2)]) ^ K1;
         T2 = WHIRL_S[get_byte<0>(B2)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B1)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B0)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B7)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B6)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B5)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B4)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B3)]) ^ K2;
         T3 = WHIRL_S[get_byte<0>(B3)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B2)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B1)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B0)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B7)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B6)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B5)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B4)]) ^ K3;
         T4 = WHIRL_S[get_byte<0>(B4)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B3)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B2)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B1)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B0)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B7)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B6)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B5)]) ^ K4;
         T5 = WHIRL_S[get_byte<0>(B5)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B4)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B3)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B2)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B1)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B0)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B7)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B6)]) ^ K5;
         T6 = WHIRL_S[get_byte<0>(B6)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B5)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B4)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B3)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B2)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B1)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B0)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B7)]) ^ K6;
         T7 = WHIRL_S[get_byte<0>(B7)] ^
            rotr<8>(WHIRL_S[get_byte<1>(B6)]) ^
            rotr<16>(WHIRL_S[get_byte<2>(B5)]) ^
            rotr<24>(WHIRL_S[get_byte<3>(B4)]) ^
            rotr<32>(WHIRL_S[get_byte<4>(B3)]) ^
            rotr<40>(WHIRL_S[get_byte<5>(B2)]) ^
            rotr<48>(WHIRL_S[get_byte<6>(B1)]) ^
            rotr<56>(WHIRL_S[get_byte<7>(B0)]) ^ K7;

         B0 = T0; B1 = T1; B2 = T2; B3 = T3;
         B4 = T4; B5 = T5; B6 = T6; B7 = T7;
         }

      digest[0] ^= B0 ^ M[0];
      digest[1] ^= B1 ^ M[1];
      digest[2] ^= B2 ^ M[2];
      digest[3] ^= B3 ^ M[3];
      digest[4] ^= B4 ^ M[4];
      digest[5] ^= B5 ^ M[5];
      digest[6] ^= B6 ^ M[6];
      digest[7] ^= B7 ^ M[7];

      in += 64;
      }
   }

void Whirlpool_Impl::init(Whirlpool_Impl::digest_type& digest)
   {
   clear_mem(digest.data(), 8);
   }

}
