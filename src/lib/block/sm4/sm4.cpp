/*
* SM4
* (C) 2017 Ribose Inc
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/sm4.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>
#include <botan/cpuid.h>

namespace Botan {

namespace {

alignas(64)
const uint8_t SM4_SBOX[256] = {
0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

/*
* SM4_SBOX_T[j] == L(SM4_SBOX[j]).
*/
alignas(64)
const uint32_t SM4_SBOX_T[256] = {
   0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787,
   0xC93DF4F4, 0x6BB5DEDE, 0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B,
   0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414, 0x872BACAC, 0xFB669D9D,
   0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
   0x02A8AAAA, 0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A,
   0x1E061818, 0xFD9B6666, 0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3,
   0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9, 0xFF33CCCC, 0x04555151,
   0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
   0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020,
   0x48EBA3A3, 0xC1975656, 0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB,
   0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A, 0x5B461D1D, 0x1B071C1C,
   0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
   0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616,
   0x734E3D3D, 0x08AAA2A2, 0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA,
   0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E, 0x18FBE3E3, 0x47E8AFAF,
   0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4,
   0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161,
   0x95D24747, 0x2AA08A8A, 0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC,
   0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E, 0x84D75353, 0x00000000,
   0x5E471919, 0x0B565D5D, 0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
   0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313,
   0xE8CB2323, 0xE69C7A7A, 0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B,
   0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6, 0x2FA18E8E, 0x2BF4DFDF,
   0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
   0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0,
   0x721A6868, 0x01545555, 0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0,
   0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F, 0x691D7474, 0x2EF5DBDB,
   0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
   0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x07A9AEAE, 0x390D3434, 0x1F524D4D,
   0x764F3939, 0xD36EBDBD, 0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515,
   0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC, 0x0F030C0C, 0x03FCFFFF,
   0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
   0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777,
   0x4CBEF2F2, 0x837EFDFD, 0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505,
   0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363, 0x220A2828, 0xC5C20707,
   0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
   0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797,
   0x64B6D2D2, 0x70B2C2C2, 0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929,
   0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9, 0xF1649595, 0x5DBBE6E6,
   0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
   0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373,
   0x794C3535, 0xA0208080, 0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8,
   0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121 };

alignas(64U)
const uint32_t SM4_SBOX_T8[256] = {
   rotr<8>(0x8ED55B5BU), rotr<8>(0xD0924242U), rotr<8>(0x4DEAA7A7U), rotr<8>(0x06FDFBFBU),
   rotr<8>(0xFCCF3333U), rotr<8>(0x65E28787U), rotr<8>(0xC93DF4F4U), rotr<8>(0x6BB5DEDEU),
   rotr<8>(0x4E165858U), rotr<8>(0x6EB4DADAU), rotr<8>(0x44145050U), rotr<8>(0xCAC10B0BU),
   rotr<8>(0x8828A0A0U), rotr<8>(0x17F8EFEFU), rotr<8>(0x9C2CB0B0U), rotr<8>(0x11051414U),
   rotr<8>(0x872BACACU), rotr<8>(0xFB669D9DU), rotr<8>(0xF2986A6AU), rotr<8>(0xAE77D9D9U),
   rotr<8>(0x822AA8A8U), rotr<8>(0x46BCFAFAU), rotr<8>(0x14041010U), rotr<8>(0xCFC00F0FU),
   rotr<8>(0x02A8AAAAU), rotr<8>(0x54451111U), rotr<8>(0x5F134C4CU), rotr<8>(0xBE269898U),
   rotr<8>(0x6D482525U), rotr<8>(0x9E841A1AU), rotr<8>(0x1E061818U), rotr<8>(0xFD9B6666U),
   rotr<8>(0xEC9E7272U), rotr<8>(0x4A430909U), rotr<8>(0x10514141U), rotr<8>(0x24F7D3D3U),
   rotr<8>(0xD5934646U), rotr<8>(0x53ECBFBFU), rotr<8>(0xF89A6262U), rotr<8>(0x927BE9E9U),
   rotr<8>(0xFF33CCCCU), rotr<8>(0x04555151U), rotr<8>(0x270B2C2CU), rotr<8>(0x4F420D0DU),
   rotr<8>(0x59EEB7B7U), rotr<8>(0xF3CC3F3FU), rotr<8>(0x1CAEB2B2U), rotr<8>(0xEA638989U),
   rotr<8>(0x74E79393U), rotr<8>(0x7FB1CECEU), rotr<8>(0x6C1C7070U), rotr<8>(0x0DABA6A6U),
   rotr<8>(0xEDCA2727U), rotr<8>(0x28082020U), rotr<8>(0x48EBA3A3U), rotr<8>(0xC1975656U),
   rotr<8>(0x80820202U), rotr<8>(0xA3DC7F7FU), rotr<8>(0xC4965252U), rotr<8>(0x12F9EBEBU),
   rotr<8>(0xA174D5D5U), rotr<8>(0xB38D3E3EU), rotr<8>(0xC33FFCFCU), rotr<8>(0x3EA49A9AU),
   rotr<8>(0x5B461D1DU), rotr<8>(0x1B071C1CU), rotr<8>(0x3BA59E9EU), rotr<8>(0x0CFFF3F3U),
   rotr<8>(0x3FF0CFCFU), rotr<8>(0xBF72CDCDU), rotr<8>(0x4B175C5CU), rotr<8>(0x52B8EAEAU),
   rotr<8>(0x8F810E0EU), rotr<8>(0x3D586565U), rotr<8>(0xCC3CF0F0U), rotr<8>(0x7D196464U),
   rotr<8>(0x7EE59B9BU), rotr<8>(0x91871616U), rotr<8>(0x734E3D3DU), rotr<8>(0x08AAA2A2U),
   rotr<8>(0xC869A1A1U), rotr<8>(0xC76AADADU), rotr<8>(0x85830606U), rotr<8>(0x7AB0CACAU),
   rotr<8>(0xB570C5C5U), rotr<8>(0xF4659191U), rotr<8>(0xB2D96B6BU), rotr<8>(0xA7892E2EU),
   rotr<8>(0x18FBE3E3U), rotr<8>(0x47E8AFAFU), rotr<8>(0x330F3C3CU), rotr<8>(0x674A2D2DU),
   rotr<8>(0xB071C1C1U), rotr<8>(0x0E575959U), rotr<8>(0xE99F7676U), rotr<8>(0xE135D4D4U),
   rotr<8>(0x661E7878U), rotr<8>(0xB4249090U), rotr<8>(0x360E3838U), rotr<8>(0x265F7979U),
   rotr<8>(0xEF628D8DU), rotr<8>(0x38596161U), rotr<8>(0x95D24747U), rotr<8>(0x2AA08A8AU),
   rotr<8>(0xB1259494U), rotr<8>(0xAA228888U), rotr<8>(0x8C7DF1F1U), rotr<8>(0xD73BECECU),
   rotr<8>(0x05010404U), rotr<8>(0xA5218484U), rotr<8>(0x9879E1E1U), rotr<8>(0x9B851E1EU),
   rotr<8>(0x84D75353U), rotr<8>(0x00000000U), rotr<8>(0x5E471919U), rotr<8>(0x0B565D5DU),
   rotr<8>(0xE39D7E7EU), rotr<8>(0x9FD04F4FU), rotr<8>(0xBB279C9CU), rotr<8>(0x1A534949U),
   rotr<8>(0x7C4D3131U), rotr<8>(0xEE36D8D8U), rotr<8>(0x0A020808U), rotr<8>(0x7BE49F9FU),
   rotr<8>(0x20A28282U), rotr<8>(0xD4C71313U), rotr<8>(0xE8CB2323U), rotr<8>(0xE69C7A7AU),
   rotr<8>(0x42E9ABABU), rotr<8>(0x43BDFEFEU), rotr<8>(0xA2882A2AU), rotr<8>(0x9AD14B4BU),
   rotr<8>(0x40410101U), rotr<8>(0xDBC41F1FU), rotr<8>(0xD838E0E0U), rotr<8>(0x61B7D6D6U),
   rotr<8>(0x2FA18E8EU), rotr<8>(0x2BF4DFDFU), rotr<8>(0x3AF1CBCBU), rotr<8>(0xF6CD3B3BU),
   rotr<8>(0x1DFAE7E7U), rotr<8>(0xE5608585U), rotr<8>(0x41155454U), rotr<8>(0x25A38686U),
   rotr<8>(0x60E38383U), rotr<8>(0x16ACBABAU), rotr<8>(0x295C7575U), rotr<8>(0x34A69292U),
   rotr<8>(0xF7996E6EU), rotr<8>(0xE434D0D0U), rotr<8>(0x721A6868U), rotr<8>(0x01545555U),
   rotr<8>(0x19AFB6B6U), rotr<8>(0xDF914E4EU), rotr<8>(0xFA32C8C8U), rotr<8>(0xF030C0C0U),
   rotr<8>(0x21F6D7D7U), rotr<8>(0xBC8E3232U), rotr<8>(0x75B3C6C6U), rotr<8>(0x6FE08F8FU),
   rotr<8>(0x691D7474U), rotr<8>(0x2EF5DBDBU), rotr<8>(0x6AE18B8BU), rotr<8>(0x962EB8B8U),
   rotr<8>(0x8A800A0AU), rotr<8>(0xFE679999U), rotr<8>(0xE2C92B2BU), rotr<8>(0xE0618181U),
   rotr<8>(0xC0C30303U), rotr<8>(0x8D29A4A4U), rotr<8>(0xAF238C8CU), rotr<8>(0x07A9AEAEU),
   rotr<8>(0x390D3434U), rotr<8>(0x1F524D4DU), rotr<8>(0x764F3939U), rotr<8>(0xD36EBDBDU),
   rotr<8>(0x81D65757U), rotr<8>(0xB7D86F6FU), rotr<8>(0xEB37DCDCU), rotr<8>(0x51441515U),
   rotr<8>(0xA6DD7B7BU), rotr<8>(0x09FEF7F7U), rotr<8>(0xB68C3A3AU), rotr<8>(0x932FBCBCU),
   rotr<8>(0x0F030C0CU), rotr<8>(0x03FCFFFFU), rotr<8>(0xC26BA9A9U), rotr<8>(0xBA73C9C9U),
   rotr<8>(0xD96CB5B5U), rotr<8>(0xDC6DB1B1U), rotr<8>(0x375A6D6DU), rotr<8>(0x15504545U),
   rotr<8>(0xB98F3636U), rotr<8>(0x771B6C6CU), rotr<8>(0x13ADBEBEU), rotr<8>(0xDA904A4AU),
   rotr<8>(0x57B9EEEEU), rotr<8>(0xA9DE7777U), rotr<8>(0x4CBEF2F2U), rotr<8>(0x837EFDFDU),
   rotr<8>(0x55114444U), rotr<8>(0xBDDA6767U), rotr<8>(0x2C5D7171U), rotr<8>(0x45400505U),
   rotr<8>(0x631F7C7CU), rotr<8>(0x50104040U), rotr<8>(0x325B6969U), rotr<8>(0xB8DB6363U),
   rotr<8>(0x220A2828U), rotr<8>(0xC5C20707U), rotr<8>(0xF531C4C4U), rotr<8>(0xA88A2222U),
   rotr<8>(0x31A79696U), rotr<8>(0xF9CE3737U), rotr<8>(0x977AEDEDU), rotr<8>(0x49BFF6F6U),
   rotr<8>(0x992DB4B4U), rotr<8>(0xA475D1D1U), rotr<8>(0x90D34343U), rotr<8>(0x5A124848U),
   rotr<8>(0x58BAE2E2U), rotr<8>(0x71E69797U), rotr<8>(0x64B6D2D2U), rotr<8>(0x70B2C2C2U),
   rotr<8>(0xAD8B2626U), rotr<8>(0xCD68A5A5U), rotr<8>(0xCB955E5EU), rotr<8>(0x624B2929U),
   rotr<8>(0x3C0C3030U), rotr<8>(0xCE945A5AU), rotr<8>(0xAB76DDDDU), rotr<8>(0x867FF9F9U),
   rotr<8>(0xF1649595U), rotr<8>(0x5DBBE6E6U), rotr<8>(0x35F2C7C7U), rotr<8>(0x2D092424U),
   rotr<8>(0xD1C61717U), rotr<8>(0xD66FB9B9U), rotr<8>(0xDEC51B1BU), rotr<8>(0x94861212U),
   rotr<8>(0x78186060U), rotr<8>(0x30F3C3C3U), rotr<8>(0x897CF5F5U), rotr<8>(0x5CEFB3B3U),
   rotr<8>(0xD23AE8E8U), rotr<8>(0xACDF7373U), rotr<8>(0x794C3535U), rotr<8>(0xA0208080U),
   rotr<8>(0x9D78E5E5U), rotr<8>(0x56EDBBBBU), rotr<8>(0x235E7D7DU), rotr<8>(0xC63EF8F8U),
   rotr<8>(0x8BD45F5FU), rotr<8>(0xE7C82F2FU), rotr<8>(0xDD39E4E4U), rotr<8>(0x68492121U)};

alignas(64U)
const uint32_t SM4_SBOX_T16[256] = {
   rotr<16>(0x8ED55B5BU), rotr<16>(0xD0924242U), rotr<16>(0x4DEAA7A7U), rotr<16>(0x06FDFBFBU),
   rotr<16>(0xFCCF3333U), rotr<16>(0x65E28787U), rotr<16>(0xC93DF4F4U), rotr<16>(0x6BB5DEDEU),
   rotr<16>(0x4E165858U), rotr<16>(0x6EB4DADAU), rotr<16>(0x44145050U), rotr<16>(0xCAC10B0BU),
   rotr<16>(0x8828A0A0U), rotr<16>(0x17F8EFEFU), rotr<16>(0x9C2CB0B0U), rotr<16>(0x11051414U),
   rotr<16>(0x872BACACU), rotr<16>(0xFB669D9DU), rotr<16>(0xF2986A6AU), rotr<16>(0xAE77D9D9U),
   rotr<16>(0x822AA8A8U), rotr<16>(0x46BCFAFAU), rotr<16>(0x14041010U), rotr<16>(0xCFC00F0FU),
   rotr<16>(0x02A8AAAAU), rotr<16>(0x54451111U), rotr<16>(0x5F134C4CU), rotr<16>(0xBE269898U),
   rotr<16>(0x6D482525U), rotr<16>(0x9E841A1AU), rotr<16>(0x1E061818U), rotr<16>(0xFD9B6666U),
   rotr<16>(0xEC9E7272U), rotr<16>(0x4A430909U), rotr<16>(0x10514141U), rotr<16>(0x24F7D3D3U),
   rotr<16>(0xD5934646U), rotr<16>(0x53ECBFBFU), rotr<16>(0xF89A6262U), rotr<16>(0x927BE9E9U),
   rotr<16>(0xFF33CCCCU), rotr<16>(0x04555151U), rotr<16>(0x270B2C2CU), rotr<16>(0x4F420D0DU),
   rotr<16>(0x59EEB7B7U), rotr<16>(0xF3CC3F3FU), rotr<16>(0x1CAEB2B2U), rotr<16>(0xEA638989U),
   rotr<16>(0x74E79393U), rotr<16>(0x7FB1CECEU), rotr<16>(0x6C1C7070U), rotr<16>(0x0DABA6A6U),
   rotr<16>(0xEDCA2727U), rotr<16>(0x28082020U), rotr<16>(0x48EBA3A3U), rotr<16>(0xC1975656U),
   rotr<16>(0x80820202U), rotr<16>(0xA3DC7F7FU), rotr<16>(0xC4965252U), rotr<16>(0x12F9EBEBU),
   rotr<16>(0xA174D5D5U), rotr<16>(0xB38D3E3EU), rotr<16>(0xC33FFCFCU), rotr<16>(0x3EA49A9AU),
   rotr<16>(0x5B461D1DU), rotr<16>(0x1B071C1CU), rotr<16>(0x3BA59E9EU), rotr<16>(0x0CFFF3F3U),
   rotr<16>(0x3FF0CFCFU), rotr<16>(0xBF72CDCDU), rotr<16>(0x4B175C5CU), rotr<16>(0x52B8EAEAU),
   rotr<16>(0x8F810E0EU), rotr<16>(0x3D586565U), rotr<16>(0xCC3CF0F0U), rotr<16>(0x7D196464U),
   rotr<16>(0x7EE59B9BU), rotr<16>(0x91871616U), rotr<16>(0x734E3D3DU), rotr<16>(0x08AAA2A2U),
   rotr<16>(0xC869A1A1U), rotr<16>(0xC76AADADU), rotr<16>(0x85830606U), rotr<16>(0x7AB0CACAU),
   rotr<16>(0xB570C5C5U), rotr<16>(0xF4659191U), rotr<16>(0xB2D96B6BU), rotr<16>(0xA7892E2EU),
   rotr<16>(0x18FBE3E3U), rotr<16>(0x47E8AFAFU), rotr<16>(0x330F3C3CU), rotr<16>(0x674A2D2DU),
   rotr<16>(0xB071C1C1U), rotr<16>(0x0E575959U), rotr<16>(0xE99F7676U), rotr<16>(0xE135D4D4U),
   rotr<16>(0x661E7878U), rotr<16>(0xB4249090U), rotr<16>(0x360E3838U), rotr<16>(0x265F7979U),
   rotr<16>(0xEF628D8DU), rotr<16>(0x38596161U), rotr<16>(0x95D24747U), rotr<16>(0x2AA08A8AU),
   rotr<16>(0xB1259494U), rotr<16>(0xAA228888U), rotr<16>(0x8C7DF1F1U), rotr<16>(0xD73BECECU),
   rotr<16>(0x05010404U), rotr<16>(0xA5218484U), rotr<16>(0x9879E1E1U), rotr<16>(0x9B851E1EU),
   rotr<16>(0x84D75353U), rotr<16>(0x00000000U), rotr<16>(0x5E471919U), rotr<16>(0x0B565D5DU),
   rotr<16>(0xE39D7E7EU), rotr<16>(0x9FD04F4FU), rotr<16>(0xBB279C9CU), rotr<16>(0x1A534949U),
   rotr<16>(0x7C4D3131U), rotr<16>(0xEE36D8D8U), rotr<16>(0x0A020808U), rotr<16>(0x7BE49F9FU),
   rotr<16>(0x20A28282U), rotr<16>(0xD4C71313U), rotr<16>(0xE8CB2323U), rotr<16>(0xE69C7A7AU),
   rotr<16>(0x42E9ABABU), rotr<16>(0x43BDFEFEU), rotr<16>(0xA2882A2AU), rotr<16>(0x9AD14B4BU),
   rotr<16>(0x40410101U), rotr<16>(0xDBC41F1FU), rotr<16>(0xD838E0E0U), rotr<16>(0x61B7D6D6U),
   rotr<16>(0x2FA18E8EU), rotr<16>(0x2BF4DFDFU), rotr<16>(0x3AF1CBCBU), rotr<16>(0xF6CD3B3BU),
   rotr<16>(0x1DFAE7E7U), rotr<16>(0xE5608585U), rotr<16>(0x41155454U), rotr<16>(0x25A38686U),
   rotr<16>(0x60E38383U), rotr<16>(0x16ACBABAU), rotr<16>(0x295C7575U), rotr<16>(0x34A69292U),
   rotr<16>(0xF7996E6EU), rotr<16>(0xE434D0D0U), rotr<16>(0x721A6868U), rotr<16>(0x01545555U),
   rotr<16>(0x19AFB6B6U), rotr<16>(0xDF914E4EU), rotr<16>(0xFA32C8C8U), rotr<16>(0xF030C0C0U),
   rotr<16>(0x21F6D7D7U), rotr<16>(0xBC8E3232U), rotr<16>(0x75B3C6C6U), rotr<16>(0x6FE08F8FU),
   rotr<16>(0x691D7474U), rotr<16>(0x2EF5DBDBU), rotr<16>(0x6AE18B8BU), rotr<16>(0x962EB8B8U),
   rotr<16>(0x8A800A0AU), rotr<16>(0xFE679999U), rotr<16>(0xE2C92B2BU), rotr<16>(0xE0618181U),
   rotr<16>(0xC0C30303U), rotr<16>(0x8D29A4A4U), rotr<16>(0xAF238C8CU), rotr<16>(0x07A9AEAEU),
   rotr<16>(0x390D3434U), rotr<16>(0x1F524D4DU), rotr<16>(0x764F3939U), rotr<16>(0xD36EBDBDU),
   rotr<16>(0x81D65757U), rotr<16>(0xB7D86F6FU), rotr<16>(0xEB37DCDCU), rotr<16>(0x51441515U),
   rotr<16>(0xA6DD7B7BU), rotr<16>(0x09FEF7F7U), rotr<16>(0xB68C3A3AU), rotr<16>(0x932FBCBCU),
   rotr<16>(0x0F030C0CU), rotr<16>(0x03FCFFFFU), rotr<16>(0xC26BA9A9U), rotr<16>(0xBA73C9C9U),
   rotr<16>(0xD96CB5B5U), rotr<16>(0xDC6DB1B1U), rotr<16>(0x375A6D6DU), rotr<16>(0x15504545U),
   rotr<16>(0xB98F3636U), rotr<16>(0x771B6C6CU), rotr<16>(0x13ADBEBEU), rotr<16>(0xDA904A4AU),
   rotr<16>(0x57B9EEEEU), rotr<16>(0xA9DE7777U), rotr<16>(0x4CBEF2F2U), rotr<16>(0x837EFDFDU),
   rotr<16>(0x55114444U), rotr<16>(0xBDDA6767U), rotr<16>(0x2C5D7171U), rotr<16>(0x45400505U),
   rotr<16>(0x631F7C7CU), rotr<16>(0x50104040U), rotr<16>(0x325B6969U), rotr<16>(0xB8DB6363U),
   rotr<16>(0x220A2828U), rotr<16>(0xC5C20707U), rotr<16>(0xF531C4C4U), rotr<16>(0xA88A2222U),
   rotr<16>(0x31A79696U), rotr<16>(0xF9CE3737U), rotr<16>(0x977AEDEDU), rotr<16>(0x49BFF6F6U),
   rotr<16>(0x992DB4B4U), rotr<16>(0xA475D1D1U), rotr<16>(0x90D34343U), rotr<16>(0x5A124848U),
   rotr<16>(0x58BAE2E2U), rotr<16>(0x71E69797U), rotr<16>(0x64B6D2D2U), rotr<16>(0x70B2C2C2U),
   rotr<16>(0xAD8B2626U), rotr<16>(0xCD68A5A5U), rotr<16>(0xCB955E5EU), rotr<16>(0x624B2929U),
   rotr<16>(0x3C0C3030U), rotr<16>(0xCE945A5AU), rotr<16>(0xAB76DDDDU), rotr<16>(0x867FF9F9U),
   rotr<16>(0xF1649595U), rotr<16>(0x5DBBE6E6U), rotr<16>(0x35F2C7C7U), rotr<16>(0x2D092424U),
   rotr<16>(0xD1C61717U), rotr<16>(0xD66FB9B9U), rotr<16>(0xDEC51B1BU), rotr<16>(0x94861212U),
   rotr<16>(0x78186060U), rotr<16>(0x30F3C3C3U), rotr<16>(0x897CF5F5U), rotr<16>(0x5CEFB3B3U),
   rotr<16>(0xD23AE8E8U), rotr<16>(0xACDF7373U), rotr<16>(0x794C3535U), rotr<16>(0xA0208080U),
   rotr<16>(0x9D78E5E5U), rotr<16>(0x56EDBBBBU), rotr<16>(0x235E7D7DU), rotr<16>(0xC63EF8F8U),
   rotr<16>(0x8BD45F5FU), rotr<16>(0xE7C82F2FU), rotr<16>(0xDD39E4E4U), rotr<16>(0x68492121U)};

alignas(64U)
const uint32_t SM4_SBOX_T24[256] = {
   rotr<24>(0x8ED55B5BU), rotr<24>(0xD0924242U), rotr<24>(0x4DEAA7A7U), rotr<24>(0x06FDFBFBU),
   rotr<24>(0xFCCF3333U), rotr<24>(0x65E28787U), rotr<24>(0xC93DF4F4U), rotr<24>(0x6BB5DEDEU),
   rotr<24>(0x4E165858U), rotr<24>(0x6EB4DADAU), rotr<24>(0x44145050U), rotr<24>(0xCAC10B0BU),
   rotr<24>(0x8828A0A0U), rotr<24>(0x17F8EFEFU), rotr<24>(0x9C2CB0B0U), rotr<24>(0x11051414U),
   rotr<24>(0x872BACACU), rotr<24>(0xFB669D9DU), rotr<24>(0xF2986A6AU), rotr<24>(0xAE77D9D9U),
   rotr<24>(0x822AA8A8U), rotr<24>(0x46BCFAFAU), rotr<24>(0x14041010U), rotr<24>(0xCFC00F0FU),
   rotr<24>(0x02A8AAAAU), rotr<24>(0x54451111U), rotr<24>(0x5F134C4CU), rotr<24>(0xBE269898U),
   rotr<24>(0x6D482525U), rotr<24>(0x9E841A1AU), rotr<24>(0x1E061818U), rotr<24>(0xFD9B6666U),
   rotr<24>(0xEC9E7272U), rotr<24>(0x4A430909U), rotr<24>(0x10514141U), rotr<24>(0x24F7D3D3U),
   rotr<24>(0xD5934646U), rotr<24>(0x53ECBFBFU), rotr<24>(0xF89A6262U), rotr<24>(0x927BE9E9U),
   rotr<24>(0xFF33CCCCU), rotr<24>(0x04555151U), rotr<24>(0x270B2C2CU), rotr<24>(0x4F420D0DU),
   rotr<24>(0x59EEB7B7U), rotr<24>(0xF3CC3F3FU), rotr<24>(0x1CAEB2B2U), rotr<24>(0xEA638989U),
   rotr<24>(0x74E79393U), rotr<24>(0x7FB1CECEU), rotr<24>(0x6C1C7070U), rotr<24>(0x0DABA6A6U),
   rotr<24>(0xEDCA2727U), rotr<24>(0x28082020U), rotr<24>(0x48EBA3A3U), rotr<24>(0xC1975656U),
   rotr<24>(0x80820202U), rotr<24>(0xA3DC7F7FU), rotr<24>(0xC4965252U), rotr<24>(0x12F9EBEBU),
   rotr<24>(0xA174D5D5U), rotr<24>(0xB38D3E3EU), rotr<24>(0xC33FFCFCU), rotr<24>(0x3EA49A9AU),
   rotr<24>(0x5B461D1DU), rotr<24>(0x1B071C1CU), rotr<24>(0x3BA59E9EU), rotr<24>(0x0CFFF3F3U),
   rotr<24>(0x3FF0CFCFU), rotr<24>(0xBF72CDCDU), rotr<24>(0x4B175C5CU), rotr<24>(0x52B8EAEAU),
   rotr<24>(0x8F810E0EU), rotr<24>(0x3D586565U), rotr<24>(0xCC3CF0F0U), rotr<24>(0x7D196464U),
   rotr<24>(0x7EE59B9BU), rotr<24>(0x91871616U), rotr<24>(0x734E3D3DU), rotr<24>(0x08AAA2A2U),
   rotr<24>(0xC869A1A1U), rotr<24>(0xC76AADADU), rotr<24>(0x85830606U), rotr<24>(0x7AB0CACAU),
   rotr<24>(0xB570C5C5U), rotr<24>(0xF4659191U), rotr<24>(0xB2D96B6BU), rotr<24>(0xA7892E2EU),
   rotr<24>(0x18FBE3E3U), rotr<24>(0x47E8AFAFU), rotr<24>(0x330F3C3CU), rotr<24>(0x674A2D2DU),
   rotr<24>(0xB071C1C1U), rotr<24>(0x0E575959U), rotr<24>(0xE99F7676U), rotr<24>(0xE135D4D4U),
   rotr<24>(0x661E7878U), rotr<24>(0xB4249090U), rotr<24>(0x360E3838U), rotr<24>(0x265F7979U),
   rotr<24>(0xEF628D8DU), rotr<24>(0x38596161U), rotr<24>(0x95D24747U), rotr<24>(0x2AA08A8AU),
   rotr<24>(0xB1259494U), rotr<24>(0xAA228888U), rotr<24>(0x8C7DF1F1U), rotr<24>(0xD73BECECU),
   rotr<24>(0x05010404U), rotr<24>(0xA5218484U), rotr<24>(0x9879E1E1U), rotr<24>(0x9B851E1EU),
   rotr<24>(0x84D75353U), rotr<24>(0x00000000U), rotr<24>(0x5E471919U), rotr<24>(0x0B565D5DU),
   rotr<24>(0xE39D7E7EU), rotr<24>(0x9FD04F4FU), rotr<24>(0xBB279C9CU), rotr<24>(0x1A534949U),
   rotr<24>(0x7C4D3131U), rotr<24>(0xEE36D8D8U), rotr<24>(0x0A020808U), rotr<24>(0x7BE49F9FU),
   rotr<24>(0x20A28282U), rotr<24>(0xD4C71313U), rotr<24>(0xE8CB2323U), rotr<24>(0xE69C7A7AU),
   rotr<24>(0x42E9ABABU), rotr<24>(0x43BDFEFEU), rotr<24>(0xA2882A2AU), rotr<24>(0x9AD14B4BU),
   rotr<24>(0x40410101U), rotr<24>(0xDBC41F1FU), rotr<24>(0xD838E0E0U), rotr<24>(0x61B7D6D6U),
   rotr<24>(0x2FA18E8EU), rotr<24>(0x2BF4DFDFU), rotr<24>(0x3AF1CBCBU), rotr<24>(0xF6CD3B3BU),
   rotr<24>(0x1DFAE7E7U), rotr<24>(0xE5608585U), rotr<24>(0x41155454U), rotr<24>(0x25A38686U),
   rotr<24>(0x60E38383U), rotr<24>(0x16ACBABAU), rotr<24>(0x295C7575U), rotr<24>(0x34A69292U),
   rotr<24>(0xF7996E6EU), rotr<24>(0xE434D0D0U), rotr<24>(0x721A6868U), rotr<24>(0x01545555U),
   rotr<24>(0x19AFB6B6U), rotr<24>(0xDF914E4EU), rotr<24>(0xFA32C8C8U), rotr<24>(0xF030C0C0U),
   rotr<24>(0x21F6D7D7U), rotr<24>(0xBC8E3232U), rotr<24>(0x75B3C6C6U), rotr<24>(0x6FE08F8FU),
   rotr<24>(0x691D7474U), rotr<24>(0x2EF5DBDBU), rotr<24>(0x6AE18B8BU), rotr<24>(0x962EB8B8U),
   rotr<24>(0x8A800A0AU), rotr<24>(0xFE679999U), rotr<24>(0xE2C92B2BU), rotr<24>(0xE0618181U),
   rotr<24>(0xC0C30303U), rotr<24>(0x8D29A4A4U), rotr<24>(0xAF238C8CU), rotr<24>(0x07A9AEAEU),
   rotr<24>(0x390D3434U), rotr<24>(0x1F524D4DU), rotr<24>(0x764F3939U), rotr<24>(0xD36EBDBDU),
   rotr<24>(0x81D65757U), rotr<24>(0xB7D86F6FU), rotr<24>(0xEB37DCDCU), rotr<24>(0x51441515U),
   rotr<24>(0xA6DD7B7BU), rotr<24>(0x09FEF7F7U), rotr<24>(0xB68C3A3AU), rotr<24>(0x932FBCBCU),
   rotr<24>(0x0F030C0CU), rotr<24>(0x03FCFFFFU), rotr<24>(0xC26BA9A9U), rotr<24>(0xBA73C9C9U),
   rotr<24>(0xD96CB5B5U), rotr<24>(0xDC6DB1B1U), rotr<24>(0x375A6D6DU), rotr<24>(0x15504545U),
   rotr<24>(0xB98F3636U), rotr<24>(0x771B6C6CU), rotr<24>(0x13ADBEBEU), rotr<24>(0xDA904A4AU),
   rotr<24>(0x57B9EEEEU), rotr<24>(0xA9DE7777U), rotr<24>(0x4CBEF2F2U), rotr<24>(0x837EFDFDU),
   rotr<24>(0x55114444U), rotr<24>(0xBDDA6767U), rotr<24>(0x2C5D7171U), rotr<24>(0x45400505U),
   rotr<24>(0x631F7C7CU), rotr<24>(0x50104040U), rotr<24>(0x325B6969U), rotr<24>(0xB8DB6363U),
   rotr<24>(0x220A2828U), rotr<24>(0xC5C20707U), rotr<24>(0xF531C4C4U), rotr<24>(0xA88A2222U),
   rotr<24>(0x31A79696U), rotr<24>(0xF9CE3737U), rotr<24>(0x977AEDEDU), rotr<24>(0x49BFF6F6U),
   rotr<24>(0x992DB4B4U), rotr<24>(0xA475D1D1U), rotr<24>(0x90D34343U), rotr<24>(0x5A124848U),
   rotr<24>(0x58BAE2E2U), rotr<24>(0x71E69797U), rotr<24>(0x64B6D2D2U), rotr<24>(0x70B2C2C2U),
   rotr<24>(0xAD8B2626U), rotr<24>(0xCD68A5A5U), rotr<24>(0xCB955E5EU), rotr<24>(0x624B2929U),
   rotr<24>(0x3C0C3030U), rotr<24>(0xCE945A5AU), rotr<24>(0xAB76DDDDU), rotr<24>(0x867FF9F9U),
   rotr<24>(0xF1649595U), rotr<24>(0x5DBBE6E6U), rotr<24>(0x35F2C7C7U), rotr<24>(0x2D092424U),
   rotr<24>(0xD1C61717U), rotr<24>(0xD66FB9B9U), rotr<24>(0xDEC51B1BU), rotr<24>(0x94861212U),
   rotr<24>(0x78186060U), rotr<24>(0x30F3C3C3U), rotr<24>(0x897CF5F5U), rotr<24>(0x5CEFB3B3U),
   rotr<24>(0xD23AE8E8U), rotr<24>(0xACDF7373U), rotr<24>(0x794C3535U), rotr<24>(0xA0208080U),
   rotr<24>(0x9D78E5E5U), rotr<24>(0x56EDBBBBU), rotr<24>(0x235E7D7DU), rotr<24>(0xC63EF8F8U),
   rotr<24>(0x8BD45F5FU), rotr<24>(0xE7C82F2FU), rotr<24>(0xDD39E4E4U), rotr<24>(0x68492121U)};

inline uint32_t SM4_T_slow(uint32_t b)
   {
   const uint32_t t = make_uint32(SM4_SBOX[get_byte(0,b)],
                                  SM4_SBOX[get_byte(1,b)],
                                  SM4_SBOX[get_byte(2,b)],
                                  SM4_SBOX[get_byte(3,b)]);

   // L linear transform
   return t ^ rotl<2>(t) ^ rotl<10>(t) ^ rotl<18>(t) ^ rotl<24>(t);
   }

inline uint32_t SM4_T(uint32_t b)
   {
   return    SM4_SBOX_T[get_byte(0,b)]
           ^ SM4_SBOX_T8[get_byte(1,b)]
           ^ SM4_SBOX_T16[get_byte(2,b)]
           ^ SM4_SBOX_T24[get_byte(3,b)];
   }

// Variant of T for key schedule
inline uint32_t SM4_Tp(uint32_t b)
   {
   const uint32_t t = make_uint32(SM4_SBOX[get_byte(0,b)],
                                  SM4_SBOX[get_byte(1,b)],
                                  SM4_SBOX[get_byte(2,b)],
                                  SM4_SBOX[get_byte(3,b)]);

   // L' linear transform
   return t ^ rotl<13>(t) ^ rotl<23>(t);
   }

#define SM4_E_RNDS(B, R, F) do {                           \
   B##0 ^= F(B##1 ^ B##2 ^ B##3 ^ m_RK[4*R+0]);            \
   B##1 ^= F(B##0 ^ B##2 ^ B##3 ^ m_RK[4*R+1]);            \
   B##2 ^= F(B##0 ^ B##1 ^ B##3 ^ m_RK[4*R+2]);            \
   B##3 ^= F(B##0 ^ B##1 ^ B##2 ^ m_RK[4*R+3]);            \
   } while(0)

#define SM4_D_RNDS(B, R, F) do {                           \
   B##0 ^= F(B##1 ^ B##2 ^ B##3 ^ m_RK[4*R+3]);            \
   B##1 ^= F(B##0 ^ B##2 ^ B##3 ^ m_RK[4*R+2]);            \
   B##2 ^= F(B##0 ^ B##1 ^ B##3 ^ m_RK[4*R+1]);            \
   B##3 ^= F(B##0 ^ B##1 ^ B##2 ^ m_RK[4*R+0]);            \
   } while(0)

}

/*
* SM4 Encryption
*/
void SM4::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_RK.empty() == false);

#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has_arm_sm4())
      return sm4_armv8_encrypt(in, out, blocks);
#endif

   while(blocks >= 2)
      {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      uint32_t C0 = load_be<uint32_t>(in, 4);
      uint32_t C1 = load_be<uint32_t>(in, 5);
      uint32_t C2 = load_be<uint32_t>(in, 6);
      uint32_t C3 = load_be<uint32_t>(in, 7);

      SM4_E_RNDS(B, 0, SM4_T_slow);
      SM4_E_RNDS(C, 0, SM4_T_slow);
      SM4_E_RNDS(B, 1, SM4_T);
      SM4_E_RNDS(C, 1, SM4_T);
      SM4_E_RNDS(B, 2, SM4_T);
      SM4_E_RNDS(C, 2, SM4_T);
      SM4_E_RNDS(B, 3, SM4_T);
      SM4_E_RNDS(C, 3, SM4_T);
      SM4_E_RNDS(B, 4, SM4_T);
      SM4_E_RNDS(C, 4, SM4_T);
      SM4_E_RNDS(B, 5, SM4_T);
      SM4_E_RNDS(C, 5, SM4_T);
      SM4_E_RNDS(B, 6, SM4_T);
      SM4_E_RNDS(C, 6, SM4_T);
      SM4_E_RNDS(B, 7, SM4_T_slow);
      SM4_E_RNDS(C, 7, SM4_T_slow);

      store_be(out, B3, B2, B1, B0, C3, C2, C1, C0);

      in += 2*BLOCK_SIZE;
      out += 2*BLOCK_SIZE;
      blocks -= 2;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      SM4_E_RNDS(B, 0, SM4_T_slow);
      SM4_E_RNDS(B, 1, SM4_T);
      SM4_E_RNDS(B, 2, SM4_T);
      SM4_E_RNDS(B, 3, SM4_T);
      SM4_E_RNDS(B, 4, SM4_T);
      SM4_E_RNDS(B, 5, SM4_T);
      SM4_E_RNDS(B, 6, SM4_T);
      SM4_E_RNDS(B, 7, SM4_T_slow);

      store_be(out, B3, B2, B1, B0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* SM4 Decryption
*/
void SM4::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_RK.empty() == false);

#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has_arm_sm4())
      return sm4_armv8_decrypt(in, out, blocks);
#endif

   while(blocks >= 2)
      {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      uint32_t C0 = load_be<uint32_t>(in, 4);
      uint32_t C1 = load_be<uint32_t>(in, 5);
      uint32_t C2 = load_be<uint32_t>(in, 6);
      uint32_t C3 = load_be<uint32_t>(in, 7);

      SM4_D_RNDS(B, 7, SM4_T_slow);
      SM4_D_RNDS(C, 7, SM4_T_slow);
      SM4_D_RNDS(B, 6, SM4_T);
      SM4_D_RNDS(C, 6, SM4_T);
      SM4_D_RNDS(B, 5, SM4_T);
      SM4_D_RNDS(C, 5, SM4_T);
      SM4_D_RNDS(B, 4, SM4_T);
      SM4_D_RNDS(C, 4, SM4_T);
      SM4_D_RNDS(B, 3, SM4_T);
      SM4_D_RNDS(C, 3, SM4_T);
      SM4_D_RNDS(B, 2, SM4_T);
      SM4_D_RNDS(C, 2, SM4_T);
      SM4_D_RNDS(B, 1, SM4_T);
      SM4_D_RNDS(C, 1, SM4_T);
      SM4_D_RNDS(B, 0, SM4_T_slow);
      SM4_D_RNDS(C, 0, SM4_T_slow);

      store_be(out, B3, B2, B1, B0, C3, C2, C1, C0);

      in += 2*BLOCK_SIZE;
      out += 2*BLOCK_SIZE;
      blocks -= 2;
      }

   for(size_t i = 0; i != blocks; ++i)
      {
      uint32_t B0 = load_be<uint32_t>(in, 0);
      uint32_t B1 = load_be<uint32_t>(in, 1);
      uint32_t B2 = load_be<uint32_t>(in, 2);
      uint32_t B3 = load_be<uint32_t>(in, 3);

      SM4_D_RNDS(B, 7, SM4_T_slow);
      SM4_D_RNDS(B, 6, SM4_T);
      SM4_D_RNDS(B, 5, SM4_T);
      SM4_D_RNDS(B, 4, SM4_T);
      SM4_D_RNDS(B, 3, SM4_T);
      SM4_D_RNDS(B, 2, SM4_T);
      SM4_D_RNDS(B, 1, SM4_T);
      SM4_D_RNDS(B, 0, SM4_T_slow);

      store_be(out, B3, B2, B1, B0);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

#undef SM4_E_RNDS
#undef SM4_D_RNDS

/*
* SM4 Key Schedule
*/
void SM4::key_schedule(const uint8_t key[], size_t)
   {
   // System parameter or family key
   const uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

   const uint32_t CK[32] = {
      0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
      0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
      0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
      0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
      0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
      0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
      0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
      0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
   };

   secure_vector<uint32_t> K(4);
   K[0] = load_be<uint32_t>(key, 0) ^ FK[0];
   K[1] = load_be<uint32_t>(key, 1) ^ FK[1];
   K[2] = load_be<uint32_t>(key, 2) ^ FK[2];
   K[3] = load_be<uint32_t>(key, 3) ^ FK[3];

   m_RK.resize(32);
   for(size_t i = 0; i != 32; ++i)
      {
      K[i % 4] ^= SM4_Tp(K[(i+1)%4] ^ K[(i+2)%4] ^ K[(i+3)%4] ^ CK[i]);
      m_RK[i] = K[i % 4];
      }
   }

void SM4::clear()
   {
   zap(m_RK);
   }

size_t SM4::parallelism() const
   {
#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has_arm_sm4())
      {
      return 4;
      }
#endif

   return 1;
   }

std::string SM4::provider() const
   {
#if defined(BOTAN_HAS_SM4_ARMV8)
   if(CPUID::has_arm_sm4())
      {
      return "armv8";
      }
#endif

   return "base";
   }

}
