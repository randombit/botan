/*
* Noekeon
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/noekeon.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>

namespace Botan {

namespace {

/*
* Noekeon's Theta Operation
*/
inline void theta(u32bit& A0, u32bit& A1,
                  u32bit& A2, u32bit& A3,
                  const u32bit EK[4])
   {
   u32bit T = A0 ^ A2;
   T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
   A1 ^= T;
   A3 ^= T;

   A0 ^= EK[0];
   A1 ^= EK[1];
   A2 ^= EK[2];
   A3 ^= EK[3];

   T = A1 ^ A3;
   T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
   A0 ^= T;
   A2 ^= T;
   }

/*
* Theta With Null Key
*/
inline void theta(u32bit& A0, u32bit& A1,
                  u32bit& A2, u32bit& A3)
   {
   u32bit T = A0 ^ A2;
   T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
   A1 ^= T;
   A3 ^= T;

   T = A1 ^ A3;
   T ^= rotate_left(T, 8) ^ rotate_right(T, 8);
   A0 ^= T;
   A2 ^= T;
   }

/*
* Noekeon's Gamma S-Box Layer
*/
inline void gamma(u32bit& A0, u32bit& A1, u32bit& A2, u32bit& A3)
   {
   A1 ^= ~A3 & ~A2;
   A0 ^= A2 & A1;

   u32bit T = A3;
   A3 = A0;
   A0 = T;

   A2 ^= A0 ^ A1 ^ A3;

   A1 ^= ~A3 & ~A2;
   A0 ^= A2 & A1;
   }

}

/*
* Noekeon Round Constants
*/
const byte Noekeon::RC[] = {
   0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
   0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
   0xD4 };

/*
* Noekeon Encryption
*/
void Noekeon::enc(const byte in[], byte out[]) const
   {
   u32bit A0 = load_be<u32bit>(in, 0);
   u32bit A1 = load_be<u32bit>(in, 1);
   u32bit A2 = load_be<u32bit>(in, 2);
   u32bit A3 = load_be<u32bit>(in, 3);

   for(u32bit j = 0; j != 16; ++j)
      {
      A0 ^= RC[j];
      theta(A0, A1, A2, A3, EK);

      A1 = rotate_left(A1, 1);
      A2 = rotate_left(A2, 5);
      A3 = rotate_left(A3, 2);

      gamma(A0, A1, A2, A3);

      A1 = rotate_right(A1, 1);
      A2 = rotate_right(A2, 5);
      A3 = rotate_right(A3, 2);
      }

   A0 ^= RC[16];
   theta(A0, A1, A2, A3, EK);

   store_be(out, A0, A1, A2, A3);
   }

/*
* Noekeon Encryption
*/
void Noekeon::dec(const byte in[], byte out[]) const
   {
   u32bit A0 = load_be<u32bit>(in, 0);
   u32bit A1 = load_be<u32bit>(in, 1);
   u32bit A2 = load_be<u32bit>(in, 2);
   u32bit A3 = load_be<u32bit>(in, 3);

   for(u32bit j = 16; j != 0; --j)
      {
      theta(A0, A1, A2, A3, DK);
      A0 ^= RC[j];

      A1 = rotate_left(A1, 1);
      A2 = rotate_left(A2, 5);
      A3 = rotate_left(A3, 2);

      gamma(A0, A1, A2, A3);

      A1 = rotate_right(A1, 1);
      A2 = rotate_right(A2, 5);
      A3 = rotate_right(A3, 2);
      }

   theta(A0, A1, A2, A3, DK);
   A0 ^= RC[0];

   store_be(out, A0, A1, A2, A3);
   }

/*
* Noekeon Key Schedule
*/
void Noekeon::key_schedule(const byte key[], u32bit)
   {
   u32bit A0 = load_be<u32bit>(key, 0);
   u32bit A1 = load_be<u32bit>(key, 1);
   u32bit A2 = load_be<u32bit>(key, 2);
   u32bit A3 = load_be<u32bit>(key, 3);

   for(u32bit j = 0; j != 16; ++j)
      {
      A0 ^= RC[j];
      theta(A0, A1, A2, A3);

      A1 = rotate_left(A1, 1);
      A2 = rotate_left(A2, 5);
      A3 = rotate_left(A3, 2);

      gamma(A0, A1, A2, A3);

      A1 = rotate_right(A1, 1);
      A2 = rotate_right(A2, 5);
      A3 = rotate_right(A3, 2);
      }

   A0 ^= RC[16];

   DK[0] = A0;
   DK[1] = A1;
   DK[2] = A2;
   DK[3] = A3;

   theta(A0, A1, A2, A3);

   EK[0] = A0;
   EK[1] = A1;
   EK[2] = A2;
   EK[3] = A3;
   }

/*
* Clear memory of sensitive data
*/
void Noekeon::clear() throw()
   {
   EK.clear();
   DK.clear();
   }

}
