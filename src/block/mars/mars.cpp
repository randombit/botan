/*
* MARS
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/mars.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* Generate a mask for runs of bits
*/
u32bit gen_mask(u32bit input)
   {
   u32bit mask = 0;

   for(u32bit j = 2; j != 31; ++j)
      {
      u32bit region = (input >> (j-1)) & 0x07;

      if(region == 0x00 || region == 0x07)
         {
         u32bit low = (j < 9) ? 0 : (j - 9);
         u32bit high = (j < 23) ? j : 23;

         for(u32bit k = low; k != high; ++k)
            {
            u32bit value = (input >> k) & 0x3FF;

            if(value == 0 || value == 0x3FF)
               {
               mask |= 1 << j;
               break;
               }
            }
         }
      }

   return mask;
   }

}

/*
* MARS Encryption
*/
void MARS::enc(const byte in[], byte out[]) const
   {
   u32bit A = load_le<u32bit>(in, 0) + EK[0];
   u32bit B = load_le<u32bit>(in, 1) + EK[1];
   u32bit C = load_le<u32bit>(in, 2) + EK[2];
   u32bit D = load_le<u32bit>(in, 3) + EK[3];

   forward_mix(A, B, C, D);

   encrypt_round(A, B, C, D,  0);
   encrypt_round(B, C, D, A,  1);
   encrypt_round(C, D, A, B,  2);
   encrypt_round(D, A, B, C,  3);
   encrypt_round(A, B, C, D,  4);
   encrypt_round(B, C, D, A,  5);
   encrypt_round(C, D, A, B,  6);
   encrypt_round(D, A, B, C,  7);

   encrypt_round(A, D, C, B,  8);
   encrypt_round(B, A, D, C,  9);
   encrypt_round(C, B, A, D, 10);
   encrypt_round(D, C, B, A, 11);
   encrypt_round(A, D, C, B, 12);
   encrypt_round(B, A, D, C, 13);
   encrypt_round(C, B, A, D, 14);
   encrypt_round(D, C, B, A, 15);

   reverse_mix(A, B, C, D);

   A -= EK[36]; B -= EK[37]; C -= EK[38]; D -= EK[39];

   store_le(out, A, B, C, D);
   }

/*
* MARS Decryption
*/
void MARS::dec(const byte in[], byte out[]) const
   {
   u32bit A = load_le<u32bit>(in, 3) + EK[39];
   u32bit B = load_le<u32bit>(in, 2) + EK[38];
   u32bit C = load_le<u32bit>(in, 1) + EK[37];
   u32bit D = load_le<u32bit>(in, 0) + EK[36];

   forward_mix(A, B, C, D);

   decrypt_round(A, B, C, D, 15);
   decrypt_round(B, C, D, A, 14);
   decrypt_round(C, D, A, B, 13);
   decrypt_round(D, A, B, C, 12);
   decrypt_round(A, B, C, D, 11);
   decrypt_round(B, C, D, A, 10);
   decrypt_round(C, D, A, B,  9);
   decrypt_round(D, A, B, C,  8);

   decrypt_round(A, D, C, B,  7);
   decrypt_round(B, A, D, C,  6);
   decrypt_round(C, B, A, D,  5);
   decrypt_round(D, C, B, A,  4);
   decrypt_round(A, D, C, B,  3);
   decrypt_round(B, A, D, C,  2);
   decrypt_round(C, B, A, D,  1);
   decrypt_round(D, C, B, A,  0);

   reverse_mix(A, B, C, D);

   A -= EK[3]; B -= EK[2]; C -= EK[1]; D -= EK[0];

   store_le(out, D, C, B, A);
   }

/*
* MARS Forward Mixing Operation
*/
void MARS::forward_mix(u32bit& A, u32bit& B, u32bit& C, u32bit& D)
   {
   for(u32bit j = 0; j != 2; ++j)
      {
      B ^= SBOX[get_byte(3, A)]; B += SBOX[get_byte(2, A) + 256];
      C += SBOX[get_byte(1, A)]; D ^= SBOX[get_byte(0, A) + 256];
      A = rotate_right(A, 24) + D;

      C ^= SBOX[get_byte(3, B)]; C += SBOX[get_byte(2, B) + 256];
      D += SBOX[get_byte(1, B)]; A ^= SBOX[get_byte(0, B) + 256];
      B = rotate_right(B, 24) + C;

      D ^= SBOX[get_byte(3, C)]; D += SBOX[get_byte(2, C) + 256];
      A += SBOX[get_byte(1, C)]; B ^= SBOX[get_byte(0, C) + 256];
      C = rotate_right(C, 24);

      A ^= SBOX[get_byte(3, D)]; A += SBOX[get_byte(2, D) + 256];
      B += SBOX[get_byte(1, D)]; C ^= SBOX[get_byte(0, D) + 256];
      D = rotate_right(D, 24);
      }
   }

/*
* MARS Reverse Mixing Operation
*/
void MARS::reverse_mix(u32bit& A, u32bit& B, u32bit& C, u32bit& D)
   {
   for(u32bit j = 0; j != 2; ++j)
      {
      B ^= SBOX[get_byte(3, A) + 256]; C -= SBOX[get_byte(0, A)];
      D -= SBOX[get_byte(1, A) + 256]; D ^= SBOX[get_byte(2, A)];
      A = rotate_left(A, 24);

      C ^= SBOX[get_byte(3, B) + 256]; D -= SBOX[get_byte(0, B)];
      A -= SBOX[get_byte(1, B) + 256]; A ^= SBOX[get_byte(2, B)];
      C -= (B = rotate_left(B, 24));

      D ^= SBOX[get_byte(3, C) + 256]; A -= SBOX[get_byte(0, C)];
      B -= SBOX[get_byte(1, C) + 256]; B ^= SBOX[get_byte(2, C)];
      C = rotate_left(C, 24);
      D -= A;

      A ^= SBOX[get_byte(3, D) + 256]; B -= SBOX[get_byte(0, D)];
      C -= SBOX[get_byte(1, D) + 256]; C ^= SBOX[get_byte(2, D)];
      D = rotate_left(D, 24);
      }
   }

/*
* MARS Encryption Round
*/
void MARS::encrypt_round(u32bit& A, u32bit& B, u32bit& C, u32bit& D,
                         u32bit round) const
   {
   u32bit X, Y, Z;
   X  = A + EK[2*round + 4];
   A  = rotate_left(A, 13);
   Y  = A * EK[2*round + 5];
   Z  = SBOX[X % 512];
   Y  = rotate_left(Y, 5);
   Z ^= Y;
   C += rotate_left(X, Y % 32);
   Y  = rotate_left(Y, 5);
   Z ^= Y;
   D ^= Y;
   B += rotate_left(Z, Y % 32);
   }

/*
* MARS Decryption Round
*/
void MARS::decrypt_round(u32bit& A, u32bit& B, u32bit& C, u32bit& D,
                         u32bit round) const
   {
   u32bit X, Y, Z;
   Y  = A * EK[2*round + 5];
   A  = rotate_right(A, 13);
   X  = A + EK[2*round + 4];
   Z  = SBOX[X % 512];
   Y  = rotate_left(Y, 5);
   Z ^= Y;
   C -= rotate_left(X, Y % 32);
   Y  = rotate_left(Y, 5);
   Z ^= Y;
   D ^= Y;
   B -= rotate_left(Z, Y % 32);
   }

/*
* MARS Key Schedule
*/
void MARS::key_schedule(const byte key[], u32bit length)
   {
   SecureBuffer<u32bit, 15> T;
   for(u32bit j = 0; j != length / 4; ++j)
      T[j] = load_le<u32bit>(key, j);
   T[length / 4] = length / 4;

   for(u32bit j = 0; j != 4; ++j)
      {
      T[ 0] ^= rotate_left(T[ 8] ^ T[13], 3) ^ (j     );
      T[ 1] ^= rotate_left(T[ 9] ^ T[14], 3) ^ (j +  4);
      T[ 2] ^= rotate_left(T[10] ^ T[ 0], 3) ^ (j +  8);
      T[ 3] ^= rotate_left(T[11] ^ T[ 1], 3) ^ (j + 12);
      T[ 4] ^= rotate_left(T[12] ^ T[ 2], 3) ^ (j + 16);
      T[ 5] ^= rotate_left(T[13] ^ T[ 3], 3) ^ (j + 20);
      T[ 6] ^= rotate_left(T[14] ^ T[ 4], 3) ^ (j + 24);
      T[ 7] ^= rotate_left(T[ 0] ^ T[ 5], 3) ^ (j + 28);
      T[ 8] ^= rotate_left(T[ 1] ^ T[ 6], 3) ^ (j + 32);
      T[ 9] ^= rotate_left(T[ 2] ^ T[ 7], 3) ^ (j + 36);
      T[10] ^= rotate_left(T[ 3] ^ T[ 8], 3) ^ (j + 40);
      T[11] ^= rotate_left(T[ 4] ^ T[ 9], 3) ^ (j + 44);
      T[12] ^= rotate_left(T[ 5] ^ T[10], 3) ^ (j + 48);
      T[13] ^= rotate_left(T[ 6] ^ T[11], 3) ^ (j + 52);
      T[14] ^= rotate_left(T[ 7] ^ T[12], 3) ^ (j + 56);

      for(u32bit k = 0; k != 4; ++k)
         {
         T[ 0] = rotate_left(T[ 0] + SBOX[T[14] % 512], 9);
         T[ 1] = rotate_left(T[ 1] + SBOX[T[ 0] % 512], 9);
         T[ 2] = rotate_left(T[ 2] + SBOX[T[ 1] % 512], 9);
         T[ 3] = rotate_left(T[ 3] + SBOX[T[ 2] % 512], 9);
         T[ 4] = rotate_left(T[ 4] + SBOX[T[ 3] % 512], 9);
         T[ 5] = rotate_left(T[ 5] + SBOX[T[ 4] % 512], 9);
         T[ 6] = rotate_left(T[ 6] + SBOX[T[ 5] % 512], 9);
         T[ 7] = rotate_left(T[ 7] + SBOX[T[ 6] % 512], 9);
         T[ 8] = rotate_left(T[ 8] + SBOX[T[ 7] % 512], 9);
         T[ 9] = rotate_left(T[ 9] + SBOX[T[ 8] % 512], 9);
         T[10] = rotate_left(T[10] + SBOX[T[ 9] % 512], 9);
         T[11] = rotate_left(T[11] + SBOX[T[10] % 512], 9);
         T[12] = rotate_left(T[12] + SBOX[T[11] % 512], 9);
         T[13] = rotate_left(T[13] + SBOX[T[12] % 512], 9);
         T[14] = rotate_left(T[14] + SBOX[T[13] % 512], 9);
         }

      EK[10*j + 0] = T[ 0]; EK[10*j + 1] = T[ 4]; EK[10*j + 2] = T[ 8];
      EK[10*j + 3] = T[12]; EK[10*j + 4] = T[ 1]; EK[10*j + 5] = T[ 5];
      EK[10*j + 6] = T[ 9]; EK[10*j + 7] = T[13]; EK[10*j + 8] = T[ 2];
      EK[10*j + 9] = T[ 6];
      }

   for(u32bit j = 5; j != 37; j += 2)
      {
      u32bit key3 = EK[j] & 3;
      EK[j] |= 3;
      EK[j] ^= rotate_left(SBOX[265 + key3], EK[j-1] % 32) & gen_mask(EK[j]);
      }
   }

}
