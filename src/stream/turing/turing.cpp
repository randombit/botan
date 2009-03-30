/*
* Turing
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/turing.h>
#include <botan/loadstor.h>
#include <botan/xor_buf.h>

namespace Botan {

namespace {

/*
* Perform an N-way PHT
*/
inline void PHT(MemoryRegion<u32bit>& buf)
   {
   u32bit sum = 0;
   for(u32bit j = 0; j < buf.size() - 1; ++j)
      sum += buf[j];
   buf[buf.size()-1] += sum;
   sum = buf[buf.size()-1];
   for(u32bit j = 0; j < buf.size() - 1; ++j)
      buf[j] += sum;
   }

}

/*
* Combine cipher stream with message
*/
void Turing::cipher(const byte in[], byte out[], u32bit length)
   {
   while(length >= buffer.size() - position)
      {
      xor_buf(out, in, buffer.begin() + position, buffer.size() - position);
      length -= (buffer.size() - position);
      in += (buffer.size() - position);
      out += (buffer.size() - position);
      generate();
      }
   xor_buf(out, in, buffer.begin() + position, length);
   position += length;
   }

/*
* Generate cipher stream
*/
void Turing::generate()
   {
   // Table for Turing's polynomial multiplication
   static const u32bit MULT_TAB[256] = {
      0x00000000, 0xD02B4367, 0xED5686CE, 0x3D7DC5A9, 0x97AC41D1, 0x478702B6,
      0x7AFAC71F, 0xAAD18478, 0x631582EF, 0xB33EC188, 0x8E430421, 0x5E684746,
      0xF4B9C33E, 0x24928059, 0x19EF45F0, 0xC9C40697, 0xC62A4993, 0x16010AF4,
      0x2B7CCF5D, 0xFB578C3A, 0x51860842, 0x81AD4B25, 0xBCD08E8C, 0x6CFBCDEB,
      0xA53FCB7C, 0x7514881B, 0x48694DB2, 0x98420ED5, 0x32938AAD, 0xE2B8C9CA,
      0xDFC50C63, 0x0FEE4F04, 0xC154926B, 0x117FD10C, 0x2C0214A5, 0xFC2957C2,
      0x56F8D3BA, 0x86D390DD, 0xBBAE5574, 0x6B851613, 0xA2411084, 0x726A53E3,
      0x4F17964A, 0x9F3CD52D, 0x35ED5155, 0xE5C61232, 0xD8BBD79B, 0x089094FC,
      0x077EDBF8, 0xD755989F, 0xEA285D36, 0x3A031E51, 0x90D29A29, 0x40F9D94E,
      0x7D841CE7, 0xADAF5F80, 0x646B5917, 0xB4401A70, 0x893DDFD9, 0x59169CBE,
      0xF3C718C6, 0x23EC5BA1, 0x1E919E08, 0xCEBADD6F, 0xCFA869D6, 0x1F832AB1,
      0x22FEEF18, 0xF2D5AC7F, 0x58042807, 0x882F6B60, 0xB552AEC9, 0x6579EDAE,
      0xACBDEB39, 0x7C96A85E, 0x41EB6DF7, 0x91C02E90, 0x3B11AAE8, 0xEB3AE98F,
      0xD6472C26, 0x066C6F41, 0x09822045, 0xD9A96322, 0xE4D4A68B, 0x34FFE5EC,
      0x9E2E6194, 0x4E0522F3, 0x7378E75A, 0xA353A43D, 0x6A97A2AA, 0xBABCE1CD,
      0x87C12464, 0x57EA6703, 0xFD3BE37B, 0x2D10A01C, 0x106D65B5, 0xC04626D2,
      0x0EFCFBBD, 0xDED7B8DA, 0xE3AA7D73, 0x33813E14, 0x9950BA6C, 0x497BF90B,
      0x74063CA2, 0xA42D7FC5, 0x6DE97952, 0xBDC23A35, 0x80BFFF9C, 0x5094BCFB,
      0xFA453883, 0x2A6E7BE4, 0x1713BE4D, 0xC738FD2A, 0xC8D6B22E, 0x18FDF149,
      0x258034E0, 0xF5AB7787, 0x5F7AF3FF, 0x8F51B098, 0xB22C7531, 0x62073656,
      0xABC330C1, 0x7BE873A6, 0x4695B60F, 0x96BEF568, 0x3C6F7110, 0xEC443277,
      0xD139F7DE, 0x0112B4B9, 0xD31DD2E1, 0x03369186, 0x3E4B542F, 0xEE601748,
      0x44B19330, 0x949AD057, 0xA9E715FE, 0x79CC5699, 0xB008500E, 0x60231369,
      0x5D5ED6C0, 0x8D7595A7, 0x27A411DF, 0xF78F52B8, 0xCAF29711, 0x1AD9D476,
      0x15379B72, 0xC51CD815, 0xF8611DBC, 0x284A5EDB, 0x829BDAA3, 0x52B099C4,
      0x6FCD5C6D, 0xBFE61F0A, 0x7622199D, 0xA6095AFA, 0x9B749F53, 0x4B5FDC34,
      0xE18E584C, 0x31A51B2B, 0x0CD8DE82, 0xDCF39DE5, 0x1249408A, 0xC26203ED,
      0xFF1FC644, 0x2F348523, 0x85E5015B, 0x55CE423C, 0x68B38795, 0xB898C4F2,
      0x715CC265, 0xA1778102, 0x9C0A44AB, 0x4C2107CC, 0xE6F083B4, 0x36DBC0D3,
      0x0BA6057A, 0xDB8D461D, 0xD4630919, 0x04484A7E, 0x39358FD7, 0xE91ECCB0,
      0x43CF48C8, 0x93E40BAF, 0xAE99CE06, 0x7EB28D61, 0xB7768BF6, 0x675DC891,
      0x5A200D38, 0x8A0B4E5F, 0x20DACA27, 0xF0F18940, 0xCD8C4CE9, 0x1DA70F8E,
      0x1CB5BB37, 0xCC9EF850, 0xF1E33DF9, 0x21C87E9E, 0x8B19FAE6, 0x5B32B981,
      0x664F7C28, 0xB6643F4F, 0x7FA039D8, 0xAF8B7ABF, 0x92F6BF16, 0x42DDFC71,
      0xE80C7809, 0x38273B6E, 0x055AFEC7, 0xD571BDA0, 0xDA9FF2A4, 0x0AB4B1C3,
      0x37C9746A, 0xE7E2370D, 0x4D33B375, 0x9D18F012, 0xA06535BB, 0x704E76DC,
      0xB98A704B, 0x69A1332C, 0x54DCF685, 0x84F7B5E2, 0x2E26319A, 0xFE0D72FD,
      0xC370B754, 0x135BF433, 0xDDE1295C, 0x0DCA6A3B, 0x30B7AF92, 0xE09CECF5,
      0x4A4D688D, 0x9A662BEA, 0xA71BEE43, 0x7730AD24, 0xBEF4ABB3, 0x6EDFE8D4,
      0x53A22D7D, 0x83896E1A, 0x2958EA62, 0xF973A905, 0xC40E6CAC, 0x14252FCB,
      0x1BCB60CF, 0xCBE023A8, 0xF69DE601, 0x26B6A566, 0x8C67211E, 0x5C4C6279,
      0x6131A7D0, 0xB11AE4B7, 0x78DEE220, 0xA8F5A147, 0x958864EE, 0x45A32789,
      0xEF72A3F1, 0x3F59E096, 0x0224253F, 0xD20F6658 };

   /*
    I tried an implementation without precomputed LFSR offsets, since
    I thought that might allow (especially on x86-64) the use of leal to
    compute all the offsets.. However on my Core2 with GCC 4.3 it
    turned out significantly slower (238 Mib/s, versus 300 Mib/s
    with precomputed offsets)

    I also tried using byte vs u32bit for the offset variable (since
    x86 memory addressing modes can be odd), but it made things even
    slower (186 Mib/s)
   */
   static const byte OFFSETS[221] = {
      0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 14, 15, 16,
      5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 2, 3, 4,
      10, 11, 12, 13, 14, 15, 16, 0, 1, 5, 7, 8, 9,
      15, 16, 0, 1, 2, 3, 4, 5, 6, 10, 12, 13, 14,
      3, 4, 5, 6, 7, 8, 9, 10, 11, 15, 0, 1, 2,
      8, 9, 10, 11, 12, 13, 14, 15, 16, 3, 5, 6, 7,
      13, 14, 15, 16, 0, 1, 2, 3, 4, 8, 10, 11, 12,
      1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 15, 16, 0,
      6, 7, 8, 9, 10, 11, 12, 13, 14, 1, 3, 4, 5,
      11, 12, 13, 14, 15, 16, 0, 1, 2, 6, 8, 9, 10,
      16, 0, 1, 2, 3, 4, 5, 6, 7, 11, 13, 14, 15,
      4, 5, 6, 7, 8, 9, 10, 11, 12, 16, 1, 2, 3,
      9, 10, 11, 12, 13, 14, 15, 16, 0, 4, 6, 7, 8,
      14, 15, 16, 0, 1, 2, 3, 4, 5, 9, 11, 12, 13,
      2, 3, 4, 5, 6, 7, 8, 9, 10, 14, 16, 0, 1,
      7, 8, 9, 10, 11, 12, 13, 14, 15, 2, 4, 5, 6,
      12, 13, 14, 15, 16, 0, 1, 2, 3, 7, 9, 10, 11 };

   for(u32bit j = 0; j != 17; ++j)
      {
      const byte* R_off = OFFSETS + 13*j;

      u32bit R0 = R[R_off[0]];
      u32bit R1 = R[R_off[1]];
      u32bit R2 = R[R_off[2]];
      u32bit R3 = R[R_off[3]];
      u32bit R4 = R[R_off[4]];

      const u32bit R5 = R[R_off[5]];
      const u32bit R6 = R[R_off[6]];
      const u32bit R7 = R[R_off[7]];
      const u32bit R8 = R[R_off[8]];
      const u32bit R9 = R[R_off[9]];
      const u32bit R10 = R[R_off[10]];
      const u32bit R11 = R[R_off[11]];
      const u32bit R12 = R[R_off[12]];

      R[R_off[0]] = R0 = ((R0 << 8) ^ MULT_TAB[(R0 >> 24) & 0xFF]) ^ R11 ^ R4;

      u32bit A = R0;
      u32bit B = R10;
      u32bit C = R7;
      u32bit D = R2;
      u32bit E = R1;

      E += A + B + C + D;

      A += E;
      B += E;
      C += E;
      D += E;

      A = S0[get_byte(0, A)] ^ S1[get_byte(1, A)] ^
          S2[get_byte(2, A)] ^ S3[get_byte(3, A)];
      B = S0[get_byte(1, B)] ^ S1[get_byte(2, B)] ^
          S2[get_byte(3, B)] ^ S3[get_byte(0, B)];
      C = S0[get_byte(2, C)] ^ S1[get_byte(3, C)] ^
          S2[get_byte(0, C)] ^ S3[get_byte(1, C)];
      D = S0[get_byte(3, D)] ^ S1[get_byte(0, D)] ^
          S2[get_byte(1, D)] ^ S3[get_byte(2, D)];
      E = S0[get_byte(0, E)] ^ S1[get_byte(1, E)] ^
          S2[get_byte(2, E)] ^ S3[get_byte(3, E)];

      E += A + B + C + D;

      A += E;
      B += E;
      C += E;
      D += E;

      R[R_off[1]] = R1 = ((R1 << 8) ^ MULT_TAB[(R1 >> 24) & 0xFF]) ^ R12 ^ R5;
      R[R_off[2]] = R2 = ((R2 << 8) ^ MULT_TAB[(R2 >> 24) & 0xFF]) ^ R0 ^ R6;
      R[R_off[3]] = ((R3 << 8) ^ MULT_TAB[(R3 >> 24) & 0xFF]) ^ R1 ^ R7;

      E += R4;

      R[R_off[4]] = ((R4 << 8) ^ MULT_TAB[(R4 >> 24) & 0xFF]) ^ R2 ^ R8;

      A += R1;
      B += R12;
      C += R9;
      D += R5;

      store_be(A, buffer + 20*j + 0);
      store_be(B, buffer + 20*j + 4);
      store_be(C, buffer + 20*j + 8);
      store_be(D, buffer + 20*j + 12);
      store_be(E, buffer + 20*j + 16);
      }

   position = 0;
   }

/*
* Turing's byte mixing step
*/
u32bit Turing::fixedS(u32bit W)
   {
   for(u32bit j = 0; j != 4; ++j)
      {
      byte B = SBOX[get_byte(j, W)];
      W ^= rotate_left(Q_BOX[B], j*8);
      W &= rotate_right(0x00FFFFFF, j*8);
      W |= B << (24-j*8);
      }
   return W;
   }

/*
* Generate the expanded Turing Sbox tables
*/
void Turing::gen_sbox(MemoryRegion<u32bit>& S, u32bit which,
                      const MemoryRegion<u32bit>& K)
   {
   for(u32bit j = 0; j != 256; ++j)
      {
      u32bit W = 0, C = j;

      for(u32bit k = 0; k < K.size(); ++k)
         {
         C = SBOX[get_byte(which, K[k]) ^ C];
         W ^= rotate_left(Q_BOX[C], k + 8*which);
         }
      S[j] = (W & rotate_right(0x00FFFFFF, 8*which)) | (C << (24 - 8*which));
      }
   }

/*
* Turing Key Schedule
*/
void Turing::key_schedule(const byte key[], u32bit length)
   {
   K.create(length / 4);
   for(u32bit j = 0; j != length; ++j)
      K[j/4] = (K[j/4] << 8) + key[j];

   for(u32bit j = 0; j != K.size(); ++j)
      K[j] = fixedS(K[j]);

   PHT(K);

   gen_sbox(S0, 0, K);
   gen_sbox(S1, 1, K);
   gen_sbox(S2, 2, K);
   gen_sbox(S3, 3, K);

   resync(0, 0);
   }

/*
* Resynchronization
*/
void Turing::resync(const byte iv[], u32bit length)
   {
   if(length % 4 != 0 || length > 16)
      throw Invalid_IV_Length(name(), length);

   SecureVector<u32bit> IV(length / 4);
   for(u32bit j = 0; j != length; ++j)
      IV[j/4] = (IV[j/4] << 8) + iv[j];

   for(u32bit j = 0; j != IV.size(); ++j)
      R[j] = IV[j] = fixedS(IV[j]);

   for(u32bit j = 0; j != K.size(); ++j)
      R[j+IV.size()] = K[j];

   R[K.size() + IV.size()] = (0x010203 << 8) | (K.size() << 4) | IV.size();

   for(u32bit j = K.size() + IV.size() + 1; j != 17; ++j)
      {
      const u32bit W = R[j-K.size()-IV.size()-1] + R[j-1];
      R[j] = S0[get_byte(0, W)] ^ S1[get_byte(1, W)] ^
             S2[get_byte(2, W)] ^ S3[get_byte(3, W)];
      }

   PHT(R);

   generate();
   }

/*
* Clear memory of sensitive data
*/
void Turing::clear() throw()
   {
   S0.clear();
   S1.clear();
   S2.clear();
   S3.clear();

   buffer.clear();
   position = 0;
   }

}
