/*************************************************
* SHA-256 Source File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/sha256.h>
#include <botan/bit_ops.h>

namespace Botan {

namespace {

/*************************************************
* SHA-256 Rho Function                           *
*************************************************/
inline u32bit rho(u32bit X, u32bit rot1, u32bit rot2, u32bit rot3)
   {
   return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^
           rotate_right(X, rot3));
   }

/*************************************************
* SHA-256 Sigma Function                         *
*************************************************/
inline u32bit sigma(u32bit X, u32bit rot1, u32bit rot2, u32bit shift)
   {
   return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^ (X >> shift));
   }

/*************************************************
* SHA-256 F1 Function                            *
*************************************************/
inline void F1(u32bit A, u32bit B, u32bit C, u32bit& D,
               u32bit E, u32bit F, u32bit G, u32bit& H,
               u32bit msg, u32bit magic)
   {
   magic += rho(E, 6, 11, 25) + ((E & F) ^ (~E & G)) + msg;
   D += magic + H;
   H += magic + rho(A, 2, 13, 22) + ((A & B) ^ (A & C) ^ (B & C));
   }

}

/*************************************************
* SHA-256 Compression Function                   *
*************************************************/
void SHA_256::hash(const byte input[])
   {
   for(u32bit j = 0; j != 16; ++j)
      W[j] = make_u32bit(input[4*j], input[4*j+1], input[4*j+2], input[4*j+3]);
   for(u32bit j = 16; j != 64; ++j)
      W[j] = sigma(W[j- 2], 17, 19, 10) + W[j- 7] +
             sigma(W[j-15],  7, 18,  3) + W[j-16];

   u32bit A = digest[0], B = digest[1], C = digest[2],
          D = digest[3], E = digest[4], F = digest[5],
          G = digest[6], H = digest[7];

   F1(A,B,C,D,E,F,G,H,W[ 0],0x428A2F98);  F1(H,A,B,C,D,E,F,G,W[ 1],0x71374491);
   F1(G,H,A,B,C,D,E,F,W[ 2],0xB5C0FBCF);  F1(F,G,H,A,B,C,D,E,W[ 3],0xE9B5DBA5);
   F1(E,F,G,H,A,B,C,D,W[ 4],0x3956C25B);  F1(D,E,F,G,H,A,B,C,W[ 5],0x59F111F1);
   F1(C,D,E,F,G,H,A,B,W[ 6],0x923F82A4);  F1(B,C,D,E,F,G,H,A,W[ 7],0xAB1C5ED5);
   F1(A,B,C,D,E,F,G,H,W[ 8],0xD807AA98);  F1(H,A,B,C,D,E,F,G,W[ 9],0x12835B01);
   F1(G,H,A,B,C,D,E,F,W[10],0x243185BE);  F1(F,G,H,A,B,C,D,E,W[11],0x550C7DC3);
   F1(E,F,G,H,A,B,C,D,W[12],0x72BE5D74);  F1(D,E,F,G,H,A,B,C,W[13],0x80DEB1FE);
   F1(C,D,E,F,G,H,A,B,W[14],0x9BDC06A7);  F1(B,C,D,E,F,G,H,A,W[15],0xC19BF174);
   F1(A,B,C,D,E,F,G,H,W[16],0xE49B69C1);  F1(H,A,B,C,D,E,F,G,W[17],0xEFBE4786);
   F1(G,H,A,B,C,D,E,F,W[18],0x0FC19DC6);  F1(F,G,H,A,B,C,D,E,W[19],0x240CA1CC);
   F1(E,F,G,H,A,B,C,D,W[20],0x2DE92C6F);  F1(D,E,F,G,H,A,B,C,W[21],0x4A7484AA);
   F1(C,D,E,F,G,H,A,B,W[22],0x5CB0A9DC);  F1(B,C,D,E,F,G,H,A,W[23],0x76F988DA);
   F1(A,B,C,D,E,F,G,H,W[24],0x983E5152);  F1(H,A,B,C,D,E,F,G,W[25],0xA831C66D);
   F1(G,H,A,B,C,D,E,F,W[26],0xB00327C8);  F1(F,G,H,A,B,C,D,E,W[27],0xBF597FC7);
   F1(E,F,G,H,A,B,C,D,W[28],0xC6E00BF3);  F1(D,E,F,G,H,A,B,C,W[29],0xD5A79147);
   F1(C,D,E,F,G,H,A,B,W[30],0x06CA6351);  F1(B,C,D,E,F,G,H,A,W[31],0x14292967);
   F1(A,B,C,D,E,F,G,H,W[32],0x27B70A85);  F1(H,A,B,C,D,E,F,G,W[33],0x2E1B2138);
   F1(G,H,A,B,C,D,E,F,W[34],0x4D2C6DFC);  F1(F,G,H,A,B,C,D,E,W[35],0x53380D13);
   F1(E,F,G,H,A,B,C,D,W[36],0x650A7354);  F1(D,E,F,G,H,A,B,C,W[37],0x766A0ABB);
   F1(C,D,E,F,G,H,A,B,W[38],0x81C2C92E);  F1(B,C,D,E,F,G,H,A,W[39],0x92722C85);
   F1(A,B,C,D,E,F,G,H,W[40],0xA2BFE8A1);  F1(H,A,B,C,D,E,F,G,W[41],0xA81A664B);
   F1(G,H,A,B,C,D,E,F,W[42],0xC24B8B70);  F1(F,G,H,A,B,C,D,E,W[43],0xC76C51A3);
   F1(E,F,G,H,A,B,C,D,W[44],0xD192E819);  F1(D,E,F,G,H,A,B,C,W[45],0xD6990624);
   F1(C,D,E,F,G,H,A,B,W[46],0xF40E3585);  F1(B,C,D,E,F,G,H,A,W[47],0x106AA070);
   F1(A,B,C,D,E,F,G,H,W[48],0x19A4C116);  F1(H,A,B,C,D,E,F,G,W[49],0x1E376C08);
   F1(G,H,A,B,C,D,E,F,W[50],0x2748774C);  F1(F,G,H,A,B,C,D,E,W[51],0x34B0BCB5);
   F1(E,F,G,H,A,B,C,D,W[52],0x391C0CB3);  F1(D,E,F,G,H,A,B,C,W[53],0x4ED8AA4A);
   F1(C,D,E,F,G,H,A,B,W[54],0x5B9CCA4F);  F1(B,C,D,E,F,G,H,A,W[55],0x682E6FF3);
   F1(A,B,C,D,E,F,G,H,W[56],0x748F82EE);  F1(H,A,B,C,D,E,F,G,W[57],0x78A5636F);
   F1(G,H,A,B,C,D,E,F,W[58],0x84C87814);  F1(F,G,H,A,B,C,D,E,W[59],0x8CC70208);
   F1(E,F,G,H,A,B,C,D,W[60],0x90BEFFFA);  F1(D,E,F,G,H,A,B,C,W[61],0xA4506CEB);
   F1(C,D,E,F,G,H,A,B,W[62],0xBEF9A3F7);  F1(B,C,D,E,F,G,H,A,W[63],0xC67178F2);

   digest[0] += A; digest[1] += B; digest[2] += C;
   digest[3] += D; digest[4] += E; digest[5] += F;
   digest[6] += G; digest[7] += H;
   }

/*************************************************
* Copy out the digest                            *
*************************************************/
void SHA_256::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; ++j)
      output[j] = get_byte(j % 4, digest[j/4]);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void SHA_256::clear() throw()
   {
   MDx_HashFunction::clear();
   W.clear();
   digest[0] = 0x6A09E667;
   digest[1] = 0xBB67AE85;
   digest[2] = 0x3C6EF372;
   digest[3] = 0xA54FF53A;
   digest[4] = 0x510E527F;
   digest[5] = 0x9B05688C;
   digest[6] = 0x1F83D9AB;
   digest[7] = 0x5BE0CD19;
   }

}
