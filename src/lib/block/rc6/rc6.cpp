/*
* RC6
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/rc6.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* RC6 Encryption
*/
void RC6::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_le<u32bit>(in, 0);
      u32bit B = load_le<u32bit>(in, 1);
      u32bit C = load_le<u32bit>(in, 2);
      u32bit D = load_le<u32bit>(in, 3);

      B += S[0]; D += S[1];

      for(size_t j = 0; j != 20; j += 4)
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

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* RC6 Decryption
*/
void RC6::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   for(size_t i = 0; i != blocks; ++i)
      {
      u32bit A = load_le<u32bit>(in, 0);
      u32bit B = load_le<u32bit>(in, 1);
      u32bit C = load_le<u32bit>(in, 2);
      u32bit D = load_le<u32bit>(in, 3);

      C -= S[43]; A -= S[42];

      for(size_t j = 0; j != 20; j += 4)
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

      in += BLOCK_SIZE;
      out += BLOCK_SIZE;
      }
   }

/*
* RC6 Key Schedule
*/
void RC6::key_schedule(const byte key[], size_t length)
   {
   S.resize(44);

   const size_t WORD_KEYLENGTH = (((length - 1) / 4) + 1);
   const size_t MIX_ROUNDS     = 3 * std::max(WORD_KEYLENGTH, S.size());

   S[0] = 0xB7E15163;
   for(size_t i = 1; i != S.size(); ++i)
      S[i] = S[i-1] + 0x9E3779B9;

   secure_vector<u32bit> K(8);

   for(s32bit i = length-1; i >= 0; --i)
      K[i/4] = (K[i/4] << 8) + key[i];

   u32bit A = 0, B = 0;
   for(size_t i = 0; i != MIX_ROUNDS; ++i)
      {
      A = rotate_left(S[i % S.size()] + A + B, 3);
      B = rotate_left(K[i % WORD_KEYLENGTH] + A + B, (A + B) % 32);
      S[i % S.size()] = A;
      K[i % WORD_KEYLENGTH] = B;
      }
   }

void RC6::clear()
   {
   zap(S);
   }

}
