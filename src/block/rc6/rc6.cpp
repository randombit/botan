/*
* RC6
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rc6.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>
#include <algorithm>

namespace Botan {

/*
* RC6 Encryption
*/
void RC6::enc(const byte in[], byte out[]) const
   {
   u32bit A = load_le<u32bit>(in, 0);
   u32bit B = load_le<u32bit>(in, 1);
   u32bit C = load_le<u32bit>(in, 2);
   u32bit D = load_le<u32bit>(in, 3);

   B += S[0]; D += S[1];

   for(u32bit j = 0; j != 20; j += 4)
      {
      u32bit T1, T2;

      T1 = rotate_left(B*(2*B+1), 5);
      T2 = rotate_left(D*(2*D+1), 5);
      A = rotate_left(A ^ T1, T2 % 32) + S[2*j+2];
      C = rotate_left(C ^ T2, T1 % 32) + S[2*j+3];

      T1 = rotate_left(C*(2*C+1), 5);
      T2 = rotate_left(A*(2*A+1), 5);
      B = rotate_left(B ^ T1, T2 % 32) + S[2*j+4];
      D = rotate_left(D ^ T2, T1 % 32) + S[2*j+5];

      T1 = rotate_left(D*(2*D+1), 5);
      T2 = rotate_left(B*(2*B+1), 5);
      C = rotate_left(C ^ T1, T2 % 32) + S[2*j+6];
      A = rotate_left(A ^ T2, T1 % 32) + S[2*j+7];

      T1 = rotate_left(A*(2*A+1), 5);
      T2 = rotate_left(C*(2*C+1), 5);
      D = rotate_left(D ^ T1, T2 % 32) + S[2*j+8];
      B = rotate_left(B ^ T2, T1 % 32) + S[2*j+9];
      }

   A += S[42]; C += S[43];

   store_le(out, A, B, C, D);
   }

/*
* RC6 Decryption
*/
void RC6::dec(const byte in[], byte out[]) const
   {
   u32bit A = load_le<u32bit>(in, 0);
   u32bit B = load_le<u32bit>(in, 1);
   u32bit C = load_le<u32bit>(in, 2);
   u32bit D = load_le<u32bit>(in, 3);

   C -= S[43]; A -= S[42];

   for(u32bit j = 0; j != 20; j += 4)
      {
      u32bit T1, T2;

      T1 = rotate_left(A*(2*A+1), 5);
      T2 = rotate_left(C*(2*C+1), 5);
      B = rotate_right(B - S[41 - 2*j], T1 % 32) ^ T2;
      D = rotate_right(D - S[40 - 2*j], T2 % 32) ^ T1;

      T1 = rotate_left(D*(2*D+1), 5);
      T2 = rotate_left(B*(2*B+1), 5);
      A = rotate_right(A - S[39 - 2*j], T1 % 32) ^ T2;
      C = rotate_right(C - S[38 - 2*j], T2 % 32) ^ T1;

      T1 = rotate_left(C*(2*C+1), 5);
      T2 = rotate_left(A*(2*A+1), 5);
      D = rotate_right(D - S[37 - 2*j], T1 % 32) ^ T2;
      B = rotate_right(B - S[36 - 2*j], T2 % 32) ^ T1;

      T1 = rotate_left(B*(2*B+1), 5);
      T2 = rotate_left(D*(2*D+1), 5);
      C = rotate_right(C - S[35 - 2*j], T1 % 32) ^ T2;
      A = rotate_right(A - S[34 - 2*j], T2 % 32) ^ T1;
      }

   D -= S[1]; B -= S[0];

   store_le(out, A, B, C, D);
   }

/*
* RC6 Key Schedule
*/
void RC6::key_schedule(const byte key[], u32bit length)
   {
   const u32bit WORD_KEYLENGTH = (((length - 1) / 4) + 1),
                MIX_ROUNDS     = 3*std::max(WORD_KEYLENGTH, S.size());
   S[0] = 0xB7E15163;
   for(u32bit j = 1; j != S.size(); ++j)
      S[j] = S[j-1] + 0x9E3779B9;

   SecureBuffer<u32bit, 8> K;
   for(s32bit j = length-1; j >= 0; --j)
      K[j/4] = (K[j/4] << 8) + key[j];
   for(u32bit j = 0, A = 0, B = 0; j != MIX_ROUNDS; ++j)
      {
      A = rotate_left(S[j % S.size()] + A + B, 3);
      B = rotate_left(K[j % WORD_KEYLENGTH] + A + B, (A + B) % 32);
      S[j % S.size()] = A;
      K[j % WORD_KEYLENGTH] = B;
      }
   }

}
