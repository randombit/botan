/*
* CAST-256
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cast256.h>
#include <botan/internal/cast_sboxes.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

/*
* CAST-256 Round Type 1
*/
void round1(u32bit& out, u32bit in, u32bit mask, u32bit rot)
   {
   u32bit temp = rotate_left(mask + in, rot);
   out  ^= (CAST_SBOX1[get_byte(0, temp)] ^ CAST_SBOX2[get_byte(1, temp)]) -
            CAST_SBOX3[get_byte(2, temp)] + CAST_SBOX4[get_byte(3, temp)];
   }

/*
* CAST-256 Round Type 2
*/
void round2(u32bit& out, u32bit in, u32bit mask, u32bit rot)
   {
   u32bit temp = rotate_left(mask ^ in, rot);
   out  ^= (CAST_SBOX1[get_byte(0, temp)]  - CAST_SBOX2[get_byte(1, temp)] +
            CAST_SBOX3[get_byte(2, temp)]) ^ CAST_SBOX4[get_byte(3, temp)];
   }

/*
* CAST-256 Round Type 3
*/
void round3(u32bit& out, u32bit in, u32bit mask, u32bit rot)
   {
   u32bit temp = rotate_left(mask - in, rot);
   out  ^= ((CAST_SBOX1[get_byte(0, temp)]  + CAST_SBOX2[get_byte(1, temp)]) ^
             CAST_SBOX3[get_byte(2, temp)]) - CAST_SBOX4[get_byte(3, temp)];
   }

}

/*
* CAST-256 Encryption
*/
void CAST_256::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_be<u32bit>(in, 0);
      u32bit B = load_be<u32bit>(in, 1);
      u32bit C = load_be<u32bit>(in, 2);
      u32bit D = load_be<u32bit>(in, 3);

      round1(C, D, MK[ 0], RK[ 0]); round2(B, C, MK[ 1], RK[ 1]);
      round3(A, B, MK[ 2], RK[ 2]); round1(D, A, MK[ 3], RK[ 3]);
      round1(C, D, MK[ 4], RK[ 4]); round2(B, C, MK[ 5], RK[ 5]);
      round3(A, B, MK[ 6], RK[ 6]); round1(D, A, MK[ 7], RK[ 7]);
      round1(C, D, MK[ 8], RK[ 8]); round2(B, C, MK[ 9], RK[ 9]);
      round3(A, B, MK[10], RK[10]); round1(D, A, MK[11], RK[11]);
      round1(C, D, MK[12], RK[12]); round2(B, C, MK[13], RK[13]);
      round3(A, B, MK[14], RK[14]); round1(D, A, MK[15], RK[15]);
      round1(C, D, MK[16], RK[16]); round2(B, C, MK[17], RK[17]);
      round3(A, B, MK[18], RK[18]); round1(D, A, MK[19], RK[19]);
      round1(C, D, MK[20], RK[20]); round2(B, C, MK[21], RK[21]);
      round3(A, B, MK[22], RK[22]); round1(D, A, MK[23], RK[23]);
      round1(D, A, MK[27], RK[27]); round3(A, B, MK[26], RK[26]);
      round2(B, C, MK[25], RK[25]); round1(C, D, MK[24], RK[24]);
      round1(D, A, MK[31], RK[31]); round3(A, B, MK[30], RK[30]);
      round2(B, C, MK[29], RK[29]); round1(C, D, MK[28], RK[28]);
      round1(D, A, MK[35], RK[35]); round3(A, B, MK[34], RK[34]);
      round2(B, C, MK[33], RK[33]); round1(C, D, MK[32], RK[32]);
      round1(D, A, MK[39], RK[39]); round3(A, B, MK[38], RK[38]);
      round2(B, C, MK[37], RK[37]); round1(C, D, MK[36], RK[36]);
      round1(D, A, MK[43], RK[43]); round3(A, B, MK[42], RK[42]);
      round2(B, C, MK[41], RK[41]); round1(C, D, MK[40], RK[40]);
      round1(D, A, MK[47], RK[47]); round3(A, B, MK[46], RK[46]);
      round2(B, C, MK[45], RK[45]); round1(C, D, MK[44], RK[44]);

      store_be(out, A, B, C, D);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* CAST-256 Decryption
*/
void CAST_256::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_be<u32bit>(in, 0);
      u32bit B = load_be<u32bit>(in, 1);
      u32bit C = load_be<u32bit>(in, 2);
      u32bit D = load_be<u32bit>(in, 3);

      round1(C, D, MK[44], RK[44]); round2(B, C, MK[45], RK[45]);
      round3(A, B, MK[46], RK[46]); round1(D, A, MK[47], RK[47]);
      round1(C, D, MK[40], RK[40]); round2(B, C, MK[41], RK[41]);
      round3(A, B, MK[42], RK[42]); round1(D, A, MK[43], RK[43]);
      round1(C, D, MK[36], RK[36]); round2(B, C, MK[37], RK[37]);
      round3(A, B, MK[38], RK[38]); round1(D, A, MK[39], RK[39]);
      round1(C, D, MK[32], RK[32]); round2(B, C, MK[33], RK[33]);
      round3(A, B, MK[34], RK[34]); round1(D, A, MK[35], RK[35]);
      round1(C, D, MK[28], RK[28]); round2(B, C, MK[29], RK[29]);
      round3(A, B, MK[30], RK[30]); round1(D, A, MK[31], RK[31]);
      round1(C, D, MK[24], RK[24]); round2(B, C, MK[25], RK[25]);
      round3(A, B, MK[26], RK[26]); round1(D, A, MK[27], RK[27]);
      round1(D, A, MK[23], RK[23]); round3(A, B, MK[22], RK[22]);
      round2(B, C, MK[21], RK[21]); round1(C, D, MK[20], RK[20]);
      round1(D, A, MK[19], RK[19]); round3(A, B, MK[18], RK[18]);
      round2(B, C, MK[17], RK[17]); round1(C, D, MK[16], RK[16]);
      round1(D, A, MK[15], RK[15]); round3(A, B, MK[14], RK[14]);
      round2(B, C, MK[13], RK[13]); round1(C, D, MK[12], RK[12]);
      round1(D, A, MK[11], RK[11]); round3(A, B, MK[10], RK[10]);
      round2(B, C, MK[ 9], RK[ 9]); round1(C, D, MK[ 8], RK[ 8]);
      round1(D, A, MK[ 7], RK[ 7]); round3(A, B, MK[ 6], RK[ 6]);
      round2(B, C, MK[ 5], RK[ 5]); round1(C, D, MK[ 4], RK[ 4]);
      round1(D, A, MK[ 3], RK[ 3]); round3(A, B, MK[ 2], RK[ 2]);
      round2(B, C, MK[ 1], RK[ 1]); round1(C, D, MK[ 0], RK[ 0]);

      store_be(out, A, B, C, D);

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* CAST-256 Key Schedule
*/
void CAST_256::key_schedule(const byte key[], size_t length)
   {
   static const u32bit KEY_MASK[192] = {
      0x5A827999, 0xC95C653A, 0x383650DB, 0xA7103C7C, 0x15EA281D, 0x84C413BE,
      0xF39DFF5F, 0x6277EB00, 0xD151D6A1, 0x402BC242, 0xAF05ADE3, 0x1DDF9984,
      0x8CB98525, 0xFB9370C6, 0x6A6D5C67, 0xD9474808, 0x482133A9, 0xB6FB1F4A,
      0x25D50AEB, 0x94AEF68C, 0x0388E22D, 0x7262CDCE, 0xE13CB96F, 0x5016A510,
      0xBEF090B1, 0x2DCA7C52, 0x9CA467F3, 0x0B7E5394, 0x7A583F35, 0xE9322AD6,
      0x580C1677, 0xC6E60218, 0x35BFEDB9, 0xA499D95A, 0x1373C4FB, 0x824DB09C,
      0xF1279C3D, 0x600187DE, 0xCEDB737F, 0x3DB55F20, 0xAC8F4AC1, 0x1B693662,
      0x8A432203, 0xF91D0DA4, 0x67F6F945, 0xD6D0E4E6, 0x45AAD087, 0xB484BC28,
      0x235EA7C9, 0x9238936A, 0x01127F0B, 0x6FEC6AAC, 0xDEC6564D, 0x4DA041EE,
      0xBC7A2D8F, 0x2B541930, 0x9A2E04D1, 0x0907F072, 0x77E1DC13, 0xE6BBC7B4,
      0x5595B355, 0xC46F9EF6, 0x33498A97, 0xA2237638, 0x10FD61D9, 0x7FD74D7A,
      0xEEB1391B, 0x5D8B24BC, 0xCC65105D, 0x3B3EFBFE, 0xAA18E79F, 0x18F2D340,
      0x87CCBEE1, 0xF6A6AA82, 0x65809623, 0xD45A81C4, 0x43346D65, 0xB20E5906,
      0x20E844A7, 0x8FC23048, 0xFE9C1BE9, 0x6D76078A, 0xDC4FF32B, 0x4B29DECC,
      0xBA03CA6D, 0x28DDB60E, 0x97B7A1AF, 0x06918D50, 0x756B78F1, 0xE4456492,
      0x531F5033, 0xC1F93BD4, 0x30D32775, 0x9FAD1316, 0x0E86FEB7, 0x7D60EA58,
      0xEC3AD5F9, 0x5B14C19A, 0xC9EEAD3B, 0x38C898DC, 0xA7A2847D, 0x167C701E,
      0x85565BBF, 0xF4304760, 0x630A3301, 0xD1E41EA2, 0x40BE0A43, 0xAF97F5E4,
      0x1E71E185, 0x8D4BCD26, 0xFC25B8C7, 0x6AFFA468, 0xD9D99009, 0x48B37BAA,
      0xB78D674B, 0x266752EC, 0x95413E8D, 0x041B2A2E, 0x72F515CF, 0xE1CF0170,
      0x50A8ED11, 0xBF82D8B2, 0x2E5CC453, 0x9D36AFF4, 0x0C109B95, 0x7AEA8736,
      0xE9C472D7, 0x589E5E78, 0xC7784A19, 0x365235BA, 0xA52C215B, 0x14060CFC,
      0x82DFF89D, 0xF1B9E43E, 0x6093CFDF, 0xCF6DBB80, 0x3E47A721, 0xAD2192C2,
      0x1BFB7E63, 0x8AD56A04, 0xF9AF55A5, 0x68894146, 0xD7632CE7, 0x463D1888,
      0xB5170429, 0x23F0EFCA, 0x92CADB6B, 0x01A4C70C, 0x707EB2AD, 0xDF589E4E,
      0x4E3289EF, 0xBD0C7590, 0x2BE66131, 0x9AC04CD2, 0x099A3873, 0x78742414,
      0xE74E0FB5, 0x5627FB56, 0xC501E6F7, 0x33DBD298, 0xA2B5BE39, 0x118FA9DA,
      0x8069957B, 0xEF43811C, 0x5E1D6CBD, 0xCCF7585E, 0x3BD143FF, 0xAAAB2FA0,
      0x19851B41, 0x885F06E2, 0xF738F283, 0x6612DE24, 0xD4ECC9C5, 0x43C6B566,
      0xB2A0A107, 0x217A8CA8, 0x90547849, 0xFF2E63EA, 0x6E084F8B, 0xDCE23B2C,
      0x4BBC26CD, 0xBA96126E, 0x296FFE0F, 0x9849E9B0, 0x0723D551, 0x75FDC0F2,
      0xE4D7AC93, 0x53B19834, 0xC28B83D5, 0x31656F76, 0xA03F5B17, 0x0F1946B8 };

   static const byte KEY_ROT[32] = {
      0x13, 0x04, 0x15, 0x06, 0x17, 0x08, 0x19, 0x0A, 0x1B, 0x0C,
      0x1D, 0x0E, 0x1F, 0x10, 0x01, 0x12, 0x03, 0x14, 0x05, 0x16,
      0x07, 0x18, 0x09, 0x1A, 0x0B, 0x1C, 0x0D, 0x1E, 0x0F, 0x00,
      0x11, 0x02 };

   MK.resize(48);
   RK.resize(48);

   secure_vector<u32bit> K(8);
   for(size_t i = 0; i != length; ++i)
      K[i/4] = (K[i/4] << 8) + key[i];

   u32bit A = K[0], B = K[1], C = K[2], D = K[3],
          E = K[4], F = K[5], G = K[6], H = K[7];

   for(size_t i = 0; i != 48; i += 4)
      {
      round1(G, H, KEY_MASK[4*i+ 0], KEY_ROT[(4*i+ 0) % 32]);
      round2(F, G, KEY_MASK[4*i+ 1], KEY_ROT[(4*i+ 1) % 32]);
      round3(E, F, KEY_MASK[4*i+ 2], KEY_ROT[(4*i+ 2) % 32]);
      round1(D, E, KEY_MASK[4*i+ 3], KEY_ROT[(4*i+ 3) % 32]);
      round2(C, D, KEY_MASK[4*i+ 4], KEY_ROT[(4*i+ 4) % 32]);
      round3(B, C, KEY_MASK[4*i+ 5], KEY_ROT[(4*i+ 5) % 32]);
      round1(A, B, KEY_MASK[4*i+ 6], KEY_ROT[(4*i+ 6) % 32]);
      round2(H, A, KEY_MASK[4*i+ 7], KEY_ROT[(4*i+ 7) % 32]);
      round1(G, H, KEY_MASK[4*i+ 8], KEY_ROT[(4*i+ 8) % 32]);
      round2(F, G, KEY_MASK[4*i+ 9], KEY_ROT[(4*i+ 9) % 32]);
      round3(E, F, KEY_MASK[4*i+10], KEY_ROT[(4*i+10) % 32]);
      round1(D, E, KEY_MASK[4*i+11], KEY_ROT[(4*i+11) % 32]);
      round2(C, D, KEY_MASK[4*i+12], KEY_ROT[(4*i+12) % 32]);
      round3(B, C, KEY_MASK[4*i+13], KEY_ROT[(4*i+13) % 32]);
      round1(A, B, KEY_MASK[4*i+14], KEY_ROT[(4*i+14) % 32]);
      round2(H, A, KEY_MASK[4*i+15], KEY_ROT[(4*i+15) % 32]);

      RK[i  ] = (A % 32);
      RK[i+1] = (C % 32);
      RK[i+2] = (E % 32);
      RK[i+3] = (G % 32);
      MK[i  ] = H;
      MK[i+1] = F;
      MK[i+2] = D;
      MK[i+3] = B;
      }
   }

void CAST_256::clear()
   {
   zap(MK);
   zap(RK);
   }

}
