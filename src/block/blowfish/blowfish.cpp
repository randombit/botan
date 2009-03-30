/*
* Blowfish
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/blowfish.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* Blowfish Encryption
*/
void Blowfish::enc(const byte in[], byte out[]) const
   {
   const u32bit* S1 = S + 0;
   const u32bit* S2 = S + 256;
   const u32bit* S3 = S + 512;
   const u32bit* S4 = S + 768;

   u32bit L = load_be<u32bit>(in, 0);
   u32bit R = load_be<u32bit>(in, 1);

   for(u32bit j = 0; j != 16; j += 2)
      {
      L ^= P[j];
      R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
             S3[get_byte(2, L)]) + S4[get_byte(3, L)];

      R ^= P[j+1];
      L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
             S3[get_byte(2, R)]) + S4[get_byte(3, R)];
      }

   L ^= P[16]; R ^= P[17];

   store_be(out, R, L);
   }

/*
* Blowfish Decryption
*/
void Blowfish::dec(const byte in[], byte out[]) const
   {
   const u32bit* S1 = S + 0;
   const u32bit* S2 = S + 256;
   const u32bit* S3 = S + 512;
   const u32bit* S4 = S + 768;

   u32bit L = load_be<u32bit>(in, 0);
   u32bit R = load_be<u32bit>(in, 1);

   for(u32bit j = 17; j != 1; j -= 2)
      {
      L ^= P[j];
      R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
             S3[get_byte(2, L)]) + S4[get_byte(3, L)];

      R ^= P[j-1];
      L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
             S3[get_byte(2, R)]) + S4[get_byte(3, R)];
      }

   L ^= P[1]; R ^= P[0];

   store_be(out, R, L);
   }

/*
* Blowfish Key Schedule
*/
void Blowfish::key_schedule(const byte key[], u32bit length)
   {
   clear();

   for(u32bit j = 0, k = 0; j != 18; ++j, k += 4)
      P[j] ^= make_u32bit(key[(k  ) % length], key[(k+1) % length],
                          key[(k+2) % length], key[(k+3) % length]);

   u32bit L = 0, R = 0;
   generate_sbox(P,  18,  L, R);
   generate_sbox(S, 1024, L, R);
   }

/*
* Generate one of the Sboxes
*/
void Blowfish::generate_sbox(u32bit Box[], u32bit size,
                             u32bit& L, u32bit& R) const
   {
   const u32bit* S1 = S + 0;
   const u32bit* S2 = S + 256;
   const u32bit* S3 = S + 512;
   const u32bit* S4 = S + 768;

   for(u32bit j = 0; j != size; j += 2)
      {
      for(u32bit k = 0; k != 16; k += 2)
         {
         L ^= P[k];
         R ^= ((S1[get_byte(0, L)]  + S2[get_byte(1, L)]) ^
                S3[get_byte(2, L)]) + S4[get_byte(3, L)];

         R ^= P[k+1];
         L ^= ((S1[get_byte(0, R)]  + S2[get_byte(1, R)]) ^
                S3[get_byte(2, R)]) + S4[get_byte(3, R)];
         }

      u32bit T = R; R = L ^ P[16]; L = T ^ P[17];
      Box[j] = L; Box[j+1] = R;
      }
   }

/*
* Clear memory of sensitive data
*/
void Blowfish::clear() throw()
   {
   P.copy(P_INIT, 18);
   S.copy(S_INIT, 1024);
   }

}
