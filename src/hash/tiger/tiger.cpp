/*
* Tiger
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/tiger.h>
#include <botan/exceptn.h>
#include <botan/loadstor.h>
#include <botan/parsing.h>

namespace Botan {

/*
* Tiger Compression Function
*/
void Tiger::compress_n(const byte input[], u32bit blocks)
   {
   u64bit A = digest[0], B = digest[1], C = digest[2];

   for(u32bit i = 0; i != blocks; ++i)
      {
      for(u32bit j = 0; j != 8; ++j)
         X[j] = load_le<u64bit>(input, j);
      input += HASH_BLOCK_SIZE;

      pass(A, B, C, X, 5); mix(X);
      pass(C, A, B, X, 7); mix(X);
      pass(B, C, A, X, 9);

      for(u32bit j = 3; j != PASS; ++j)
         {
         mix(X);
         pass(A, B, C, X, 9);
         u64bit T = A; A = C; C = B; B = T;
         }

      A = (digest[0] ^= A);
      B = digest[1] = B - digest[1];
      C = (digest[2] += C);
      }
   }

/*
* Copy out the digest
*/
void Tiger::copy_out(byte output[])
   {
   for(u32bit j = 0; j != OUTPUT_LENGTH; ++j)
      output[j] = get_byte(7 - (j % 8), digest[j/8]);
   }

/*
* Tiger Pass
*/
void Tiger::pass(u64bit& A, u64bit& B, u64bit& C, u64bit X[8], byte mul)
   {
   C ^= X[0];
   A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
        SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
   B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
        SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
   B *= mul;

   A ^= X[1];
   B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
        SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
   C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
        SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
   C *= mul;

   B ^= X[2];
   C -= SBOX1[get_byte(7, B)] ^ SBOX2[get_byte(5, B)] ^
        SBOX3[get_byte(3, B)] ^ SBOX4[get_byte(1, B)];
   A += SBOX1[get_byte(0, B)] ^ SBOX2[get_byte(2, B)] ^
        SBOX3[get_byte(4, B)] ^ SBOX4[get_byte(6, B)];
   A *= mul;

   C ^= X[3];
   A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
        SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
   B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
        SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
   B *= mul;

   A ^= X[4];
   B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
        SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
   C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
        SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
   C *= mul;

   B ^= X[5];
   C -= SBOX1[get_byte(7, B)] ^ SBOX2[get_byte(5, B)] ^
        SBOX3[get_byte(3, B)] ^ SBOX4[get_byte(1, B)];
   A += SBOX1[get_byte(0, B)] ^ SBOX2[get_byte(2, B)] ^
        SBOX3[get_byte(4, B)] ^ SBOX4[get_byte(6, B)];
   A *= mul;

   C ^= X[6];
   A -= SBOX1[get_byte(7, C)] ^ SBOX2[get_byte(5, C)] ^
        SBOX3[get_byte(3, C)] ^ SBOX4[get_byte(1, C)];
   B += SBOX1[get_byte(0, C)] ^ SBOX2[get_byte(2, C)] ^
        SBOX3[get_byte(4, C)] ^ SBOX4[get_byte(6, C)];
   B *= mul;

   A ^= X[7];
   B -= SBOX1[get_byte(7, A)] ^ SBOX2[get_byte(5, A)] ^
        SBOX3[get_byte(3, A)] ^ SBOX4[get_byte(1, A)];
   C += SBOX1[get_byte(0, A)] ^ SBOX2[get_byte(2, A)] ^
        SBOX3[get_byte(4, A)] ^ SBOX4[get_byte(6, A)];
   C *= mul;
   }

/*
* Tiger Mixing Function
*/
void Tiger::mix(u64bit X[8])
   {
   X[0] -= X[7] ^ 0xA5A5A5A5A5A5A5A5; X[1] ^= X[0];
   X[2] += X[1]; X[3] -= X[2] ^ ((~X[1]) << 19); X[4] ^= X[3];
   X[5] += X[4]; X[6] -= X[5] ^ ((~X[4]) >> 23); X[7] ^= X[6];
   X[0] += X[7]; X[1] -= X[0] ^ ((~X[7]) << 19); X[2] ^= X[1];
   X[3] += X[2]; X[4] -= X[3] ^ ((~X[2]) >> 23); X[5] ^= X[4];
   X[6] += X[5]; X[7] -= X[6] ^ 0x0123456789ABCDEF;
   }

/*
* Clear memory of sensitive data
*/
void Tiger::clear() throw()
   {
   MDx_HashFunction::clear();
   X.clear();
   digest[0] = 0x0123456789ABCDEF;
   digest[1] = 0xFEDCBA9876543210;
   digest[2] = 0xF096A5B4C3B2E187;
   }

/*
* Return the name of this type
*/
std::string Tiger::name() const
   {
   return "Tiger(" + to_string(OUTPUT_LENGTH) + "," + to_string(PASS) + ")";
   }

/*
* Tiger Constructor
*/
Tiger::Tiger(u32bit hashlen, u32bit pass) :
   MDx_HashFunction(hashlen, 64, false, false), PASS(pass)
   {
   if(OUTPUT_LENGTH != 16 && OUTPUT_LENGTH != 20 && OUTPUT_LENGTH != 24)
      throw Invalid_Argument("Tiger: Illegal hash output size: " +
                             to_string(OUTPUT_LENGTH));
   if(PASS < 3)
      throw Invalid_Argument("Tiger: Invalid number of passes: "
                             + to_string(PASS));
   clear();
   }

}
