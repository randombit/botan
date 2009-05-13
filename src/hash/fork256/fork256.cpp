/*
* FORK-256
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/fork256.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* FORK-256 Step Function
*/
inline void step(u32bit& A, u32bit& B, u32bit& C, u32bit& D,
                 u32bit& E, u32bit& F, u32bit& G, u32bit& H,
                 u32bit M1, u32bit M2, u32bit D1, u32bit D2)
   {
   u32bit T0, T1;

   A += M1; T0 = A + (rotate_left(A,  7) ^ rotate_left(A, 22));
   A += D1; T1 = A ^ (rotate_left(A, 13) + rotate_left(A, 27));

   B = (B + T0) ^ T1;
   C = (C + rotate_left(T0,  5)) ^ rotate_left(T1,  9);
   D = (D + rotate_left(T0, 17)) ^ rotate_left(T1, 21);

   E += M2; T0 = E ^ (rotate_left(E, 13) + rotate_left(E, 27));
   E += D2; T1 = E + (rotate_left(E,  7) ^ rotate_left(E, 22));

   F = (F + T0) ^ T1;
   G = (G + rotate_left(T0,  9)) ^ rotate_left(T1,  5);
   H = (H + rotate_left(T0, 21)) ^ rotate_left(T1, 17);
   }

}

/*
* FORK-256 Compression Function
*/
void FORK_256::compress_n(const byte input[], u32bit blocks)
   {
   const u32bit DELTA[16] = {
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
      0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
      0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174
   };

   for(u32bit i = 0; i != blocks; ++i)
      {
      u32bit A1, B1, C1, D1, E1, F1, G1, H1;
      u32bit A2, B2, C2, D2, E2, F2, G2, H2;
      u32bit A3, B3, C3, D3, E3, F3, G3, H3;
      u32bit A4, B4, C4, D4, E4, F4, G4, H4;

      A1 = A2 = A3 = A4 = digest[0];
      B1 = B2 = B3 = B4 = digest[1];
      C1 = C2 = C3 = C4 = digest[2];
      D1 = D2 = D3 = D4 = digest[3];
      E1 = E2 = E3 = E4 = digest[4];
      F1 = F2 = F3 = F4 = digest[5];
      G1 = G2 = G3 = G4 = digest[6];
      H1 = H2 = H3 = H4 = digest[7];

      for(u32bit j = 0; j != 16; ++j)
         M[j] = load_be<u32bit>(input, j);
      input += HASH_BLOCK_SIZE;

      step(A1, B1, C1, D1, E1, F1, G1, H1, M[ 0], M[ 1], DELTA[ 0], DELTA[ 1]);
      step(A2, B2, C2, D2, E2, F2, G2, H2, M[14], M[15], DELTA[15], DELTA[14]);
      step(A3, B3, C3, D3, E3, F3, G3, H3, M[ 7], M[ 6], DELTA[ 1], DELTA[ 0]);
      step(A4, B4, C4, D4, E4, F4, G4, H4, M[ 5], M[12], DELTA[14], DELTA[15]);

      step(H1, A1, B1, C1, D1, E1, F1, G1, M[ 2], M[ 3], DELTA[ 2], DELTA[ 3]);
      step(H2, A2, B2, C2, D2, E2, F2, G2, M[11], M[ 9], DELTA[13], DELTA[12]);
      step(H3, A3, B3, C3, D3, E3, F3, G3, M[10], M[14], DELTA[ 3], DELTA[ 2]);
      step(H4, A4, B4, C4, D4, E4, F4, G4, M[ 1], M[ 8], DELTA[12], DELTA[13]);

      step(G1, H1, A1, B1, C1, D1, E1, F1, M[ 4], M[ 5], DELTA[ 4], DELTA[ 5]);
      step(G2, H2, A2, B2, C2, D2, E2, F2, M[ 8], M[10], DELTA[11], DELTA[10]);
      step(G3, H3, A3, B3, C3, D3, E3, F3, M[13], M[ 2], DELTA[ 5], DELTA[ 4]);
      step(G4, H4, A4, B4, C4, D4, E4, F4, M[15], M[ 0], DELTA[10], DELTA[11]);

      step(F1, G1, H1, A1, B1, C1, D1, E1, M[ 6], M[ 7], DELTA[ 6], DELTA[ 7]);
      step(F2, G2, H2, A2, B2, C2, D2, E2, M[ 3], M[ 4], DELTA[ 9], DELTA[ 8]);
      step(F3, G3, H3, A3, B3, C3, D3, E3, M[ 9], M[12], DELTA[ 7], DELTA[ 6]);
      step(F4, G4, H4, A4, B4, C4, D4, E4, M[13], M[11], DELTA[ 8], DELTA[ 9]);

      step(E1, F1, G1, H1, A1, B1, C1, D1, M[ 8], M[ 9], DELTA[ 8], DELTA[ 9]);
      step(E2, F2, G2, H2, A2, B2, C2, D2, M[ 2], M[13], DELTA[ 7], DELTA[ 6]);
      step(E3, F3, G3, H3, A3, B3, C3, D3, M[11], M[ 4], DELTA[ 9], DELTA[ 8]);
      step(E4, F4, G4, H4, A4, B4, C4, D4, M[ 3], M[10], DELTA[ 6], DELTA[ 7]);

      step(D1, E1, F1, G1, H1, A1, B1, C1, M[10], M[11], DELTA[10], DELTA[11]);
      step(D2, E2, F2, G2, H2, A2, B2, C2, M[ 0], M[ 5], DELTA[ 5], DELTA[ 4]);
      step(D3, E3, F3, G3, H3, A3, B3, C3, M[15], M[ 8], DELTA[11], DELTA[10]);
      step(D4, E4, F4, G4, H4, A4, B4, C4, M[ 9], M[ 2], DELTA[ 4], DELTA[ 5]);

      step(C1, D1, E1, F1, G1, H1, A1, B1, M[12], M[13], DELTA[12], DELTA[13]);
      step(C2, D2, E2, F2, G2, H2, A2, B2, M[ 6], M[ 7], DELTA[ 3], DELTA[ 2]);
      step(C3, D3, E3, F3, G3, H3, A3, B3, M[ 5], M[ 0], DELTA[13], DELTA[12]);
      step(C4, D4, E4, F4, G4, H4, A4, B4, M[ 7], M[14], DELTA[ 2], DELTA[ 3]);

      step(B1, C1, D1, E1, F1, G1, H1, A1, M[14], M[15], DELTA[14], DELTA[15]);
      step(B2, C2, D2, E2, F2, G2, H2, A2, M[12], M[ 1], DELTA[ 1], DELTA[ 0]);
      step(B3, C3, D3, E3, F3, G3, H3, A3, M[ 1], M[ 3], DELTA[15], DELTA[14]);
      step(B4, C4, D4, E4, F4, G4, H4, A4, M[ 4], M[ 6], DELTA[ 0], DELTA[ 1]);

      digest[0] += (A1 + A2) ^ (A3 + A4);
      digest[1] += (B1 + B2) ^ (B3 + B4);
      digest[2] += (C1 + C2) ^ (C3 + C4);
      digest[3] += (D1 + D2) ^ (D3 + D4);
      digest[4] += (E1 + E2) ^ (E3 + E4);
      digest[5] += (F1 + F2) ^ (F3 + F4);
      digest[6] += (G1 + G2) ^ (G3 + G4);
      digest[7] += (H1 + H2) ^ (H3 + H4);
      }
   }

/*
* Copy out the digest
*/
void FORK_256::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; j += 4)
      store_be(digest[j/4], output + j);
   }

/*
* Clear memory of sensitive data
*/
void FORK_256::clear() throw()
   {
   MDx_HashFunction::clear();
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
