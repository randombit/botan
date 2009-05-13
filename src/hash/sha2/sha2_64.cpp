/*
* SHA-{384,512}
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/sha2_64.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* SHA-{384,512} Rho Function
*/
inline u64bit rho(u64bit X, u32bit rot1, u32bit rot2, u32bit rot3)
   {
   return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^
           rotate_right(X, rot3));
   }

/*
* SHA-{384,512} F1 Function
*/
inline void F1(u64bit A, u64bit B, u64bit C, u64bit& D,
               u64bit E, u64bit F, u64bit G, u64bit& H,
               u64bit msg, u64bit magic)
   {
   magic += rho(E, 14, 18, 41) + ((E & F) ^ (~E & G)) + msg;
   D += magic + H;
   H += magic + rho(A, 28, 34, 39) + ((A & B) ^ (A & C) ^ (B & C));
   }

/*
* SHA-{384,512} Sigma Function
*/
inline u64bit sigma(u64bit X, u32bit rot1, u32bit rot2, u32bit shift)
   {
   return (rotate_right(X, rot1) ^ rotate_right(X, rot2) ^ (X >> shift));
   }

}

/*
* SHA-{384,512} Compression Function
*/
void SHA_384_512_BASE::compress_n(const byte input[], u32bit blocks)
   {
   u64bit A = digest[0], B = digest[1], C = digest[2],
          D = digest[3], E = digest[4], F = digest[5],
          G = digest[6], H = digest[7];

   for(u32bit i = 0; i != blocks; ++i)
      {
      for(u32bit j = 0; j != 16; ++j)
         W[j] = load_be<u64bit>(input, j);
      input += HASH_BLOCK_SIZE;

      for(u32bit j = 16; j != 80; ++j)
         W[j] = sigma(W[j- 2], 19, 61,  6) + W[j- 7] +
                sigma(W[j-15],  1,  8,  7) + W[j-16];

      F1(A, B, C, D, E, F, G, H, W[ 0], 0x428A2F98D728AE22);
      F1(H, A, B, C, D, E, F, G, W[ 1], 0x7137449123EF65CD);
      F1(G, H, A, B, C, D, E, F, W[ 2], 0xB5C0FBCFEC4D3B2F);
      F1(F, G, H, A, B, C, D, E, W[ 3], 0xE9B5DBA58189DBBC);
      F1(E, F, G, H, A, B, C, D, W[ 4], 0x3956C25BF348B538);
      F1(D, E, F, G, H, A, B, C, W[ 5], 0x59F111F1B605D019);
      F1(C, D, E, F, G, H, A, B, W[ 6], 0x923F82A4AF194F9B);
      F1(B, C, D, E, F, G, H, A, W[ 7], 0xAB1C5ED5DA6D8118);
      F1(A, B, C, D, E, F, G, H, W[ 8], 0xD807AA98A3030242);
      F1(H, A, B, C, D, E, F, G, W[ 9], 0x12835B0145706FBE);
      F1(G, H, A, B, C, D, E, F, W[10], 0x243185BE4EE4B28C);
      F1(F, G, H, A, B, C, D, E, W[11], 0x550C7DC3D5FFB4E2);
      F1(E, F, G, H, A, B, C, D, W[12], 0x72BE5D74F27B896F);
      F1(D, E, F, G, H, A, B, C, W[13], 0x80DEB1FE3B1696B1);
      F1(C, D, E, F, G, H, A, B, W[14], 0x9BDC06A725C71235);
      F1(B, C, D, E, F, G, H, A, W[15], 0xC19BF174CF692694);
      F1(A, B, C, D, E, F, G, H, W[16], 0xE49B69C19EF14AD2);
      F1(H, A, B, C, D, E, F, G, W[17], 0xEFBE4786384F25E3);
      F1(G, H, A, B, C, D, E, F, W[18], 0x0FC19DC68B8CD5B5);
      F1(F, G, H, A, B, C, D, E, W[19], 0x240CA1CC77AC9C65);
      F1(E, F, G, H, A, B, C, D, W[20], 0x2DE92C6F592B0275);
      F1(D, E, F, G, H, A, B, C, W[21], 0x4A7484AA6EA6E483);
      F1(C, D, E, F, G, H, A, B, W[22], 0x5CB0A9DCBD41FBD4);
      F1(B, C, D, E, F, G, H, A, W[23], 0x76F988DA831153B5);
      F1(A, B, C, D, E, F, G, H, W[24], 0x983E5152EE66DFAB);
      F1(H, A, B, C, D, E, F, G, W[25], 0xA831C66D2DB43210);
      F1(G, H, A, B, C, D, E, F, W[26], 0xB00327C898FB213F);
      F1(F, G, H, A, B, C, D, E, W[27], 0xBF597FC7BEEF0EE4);
      F1(E, F, G, H, A, B, C, D, W[28], 0xC6E00BF33DA88FC2);
      F1(D, E, F, G, H, A, B, C, W[29], 0xD5A79147930AA725);
      F1(C, D, E, F, G, H, A, B, W[30], 0x06CA6351E003826F);
      F1(B, C, D, E, F, G, H, A, W[31], 0x142929670A0E6E70);
      F1(A, B, C, D, E, F, G, H, W[32], 0x27B70A8546D22FFC);
      F1(H, A, B, C, D, E, F, G, W[33], 0x2E1B21385C26C926);
      F1(G, H, A, B, C, D, E, F, W[34], 0x4D2C6DFC5AC42AED);
      F1(F, G, H, A, B, C, D, E, W[35], 0x53380D139D95B3DF);
      F1(E, F, G, H, A, B, C, D, W[36], 0x650A73548BAF63DE);
      F1(D, E, F, G, H, A, B, C, W[37], 0x766A0ABB3C77B2A8);
      F1(C, D, E, F, G, H, A, B, W[38], 0x81C2C92E47EDAEE6);
      F1(B, C, D, E, F, G, H, A, W[39], 0x92722C851482353B);
      F1(A, B, C, D, E, F, G, H, W[40], 0xA2BFE8A14CF10364);
      F1(H, A, B, C, D, E, F, G, W[41], 0xA81A664BBC423001);
      F1(G, H, A, B, C, D, E, F, W[42], 0xC24B8B70D0F89791);
      F1(F, G, H, A, B, C, D, E, W[43], 0xC76C51A30654BE30);
      F1(E, F, G, H, A, B, C, D, W[44], 0xD192E819D6EF5218);
      F1(D, E, F, G, H, A, B, C, W[45], 0xD69906245565A910);
      F1(C, D, E, F, G, H, A, B, W[46], 0xF40E35855771202A);
      F1(B, C, D, E, F, G, H, A, W[47], 0x106AA07032BBD1B8);
      F1(A, B, C, D, E, F, G, H, W[48], 0x19A4C116B8D2D0C8);
      F1(H, A, B, C, D, E, F, G, W[49], 0x1E376C085141AB53);
      F1(G, H, A, B, C, D, E, F, W[50], 0x2748774CDF8EEB99);
      F1(F, G, H, A, B, C, D, E, W[51], 0x34B0BCB5E19B48A8);
      F1(E, F, G, H, A, B, C, D, W[52], 0x391C0CB3C5C95A63);
      F1(D, E, F, G, H, A, B, C, W[53], 0x4ED8AA4AE3418ACB);
      F1(C, D, E, F, G, H, A, B, W[54], 0x5B9CCA4F7763E373);
      F1(B, C, D, E, F, G, H, A, W[55], 0x682E6FF3D6B2B8A3);
      F1(A, B, C, D, E, F, G, H, W[56], 0x748F82EE5DEFB2FC);
      F1(H, A, B, C, D, E, F, G, W[57], 0x78A5636F43172F60);
      F1(G, H, A, B, C, D, E, F, W[58], 0x84C87814A1F0AB72);
      F1(F, G, H, A, B, C, D, E, W[59], 0x8CC702081A6439EC);
      F1(E, F, G, H, A, B, C, D, W[60], 0x90BEFFFA23631E28);
      F1(D, E, F, G, H, A, B, C, W[61], 0xA4506CEBDE82BDE9);
      F1(C, D, E, F, G, H, A, B, W[62], 0xBEF9A3F7B2C67915);
      F1(B, C, D, E, F, G, H, A, W[63], 0xC67178F2E372532B);
      F1(A, B, C, D, E, F, G, H, W[64], 0xCA273ECEEA26619C);
      F1(H, A, B, C, D, E, F, G, W[65], 0xD186B8C721C0C207);
      F1(G, H, A, B, C, D, E, F, W[66], 0xEADA7DD6CDE0EB1E);
      F1(F, G, H, A, B, C, D, E, W[67], 0xF57D4F7FEE6ED178);
      F1(E, F, G, H, A, B, C, D, W[68], 0x06F067AA72176FBA);
      F1(D, E, F, G, H, A, B, C, W[69], 0x0A637DC5A2C898A6);
      F1(C, D, E, F, G, H, A, B, W[70], 0x113F9804BEF90DAE);
      F1(B, C, D, E, F, G, H, A, W[71], 0x1B710B35131C471B);
      F1(A, B, C, D, E, F, G, H, W[72], 0x28DB77F523047D84);
      F1(H, A, B, C, D, E, F, G, W[73], 0x32CAAB7B40C72493);
      F1(G, H, A, B, C, D, E, F, W[74], 0x3C9EBE0A15C9BEBC);
      F1(F, G, H, A, B, C, D, E, W[75], 0x431D67C49C100D4C);
      F1(E, F, G, H, A, B, C, D, W[76], 0x4CC5D4BECB3E42B6);
      F1(D, E, F, G, H, A, B, C, W[77], 0x597F299CFC657E2A);
      F1(C, D, E, F, G, H, A, B, W[78], 0x5FCB6FAB3AD6FAEC);
      F1(B, C, D, E, F, G, H, A, W[79], 0x6C44198C4A475817);

      A = (digest[0] += A);
      B = (digest[1] += B);
      C = (digest[2] += C);
      D = (digest[3] += D);
      E = (digest[4] += E);
      F = (digest[5] += F);
      G = (digest[6] += G);
      H = (digest[7] += H);
      }
   }

/*
* Copy out the digest
*/
void SHA_384_512_BASE::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; j += 8)
      store_be(digest[j/8], output + j);
   }

/*
* Clear memory of sensitive data
*/
void SHA_384_512_BASE::clear() throw()
   {
   MDx_HashFunction::clear();
   W.clear();
   }

/*
* Clear memory of sensitive data
*/
void SHA_384::clear() throw()
   {
   SHA_384_512_BASE::clear();
   digest[0] = 0xCBBB9D5DC1059ED8;
   digest[1] = 0x629A292A367CD507;
   digest[2] = 0x9159015A3070DD17;
   digest[3] = 0x152FECD8F70E5939;
   digest[4] = 0x67332667FFC00B31;
   digest[5] = 0x8EB44A8768581511;
   digest[6] = 0xDB0C2E0D64F98FA7;
   digest[7] = 0x47B5481DBEFA4FA4;
   }

/*
* Clear memory of sensitive data
*/
void SHA_512::clear() throw()
   {
   SHA_384_512_BASE::clear();
   digest[0] = 0x6A09E667F3BCC908;
   digest[1] = 0xBB67AE8584CAA73B;
   digest[2] = 0x3C6EF372FE94F82B;
   digest[3] = 0xA54FF53A5F1D36F1;
   digest[4] = 0x510E527FADE682D1;
   digest[5] = 0x9B05688C2B3E6C1F;
   digest[6] = 0x1F83D9ABFB41BD6B;
   digest[7] = 0x5BE0CD19137E2179;
   }

}
