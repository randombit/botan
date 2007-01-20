/*************************************************
* Twofish Source File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/twofish.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* Twofish Encryption                             *
*************************************************/
void Twofish::enc(const byte in[], byte out[]) const
   {
   u32bit A = make_u32bit(in[ 3], in[ 2], in[ 1], in[ 0]),
          B = make_u32bit(in[ 7], in[ 6], in[ 5], in[ 4]),
          C = make_u32bit(in[11], in[10], in[ 9], in[ 8]),
          D = make_u32bit(in[15], in[14], in[13], in[12]);

   A ^= round_key[0]; B ^= round_key[1]; C ^= round_key[2]; D ^= round_key[3];

   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit X, Y;

      X = SBox0[get_byte(3, A)] ^ SBox1[get_byte(2, A)] ^
          SBox2[get_byte(1, A)] ^ SBox3[get_byte(0, A)];
      Y = SBox0[get_byte(0, B)] ^ SBox1[get_byte(3, B)] ^
          SBox2[get_byte(2, B)] ^ SBox3[get_byte(1, B)];
      X += Y;
      Y += X + round_key[2*j + 9];
      X += round_key[2*j + 8];

      C = rotate_right(C ^ X, 1);
      D = rotate_left(D, 1) ^ Y;

      X = SBox0[get_byte(3, C)] ^ SBox1[get_byte(2, C)] ^
          SBox2[get_byte(1, C)] ^ SBox3[get_byte(0, C)];
      Y = SBox0[get_byte(0, D)] ^ SBox1[get_byte(3, D)] ^
          SBox2[get_byte(2, D)] ^ SBox3[get_byte(1, D)];
      X += Y;
      Y += X + round_key[2*j + 11];
      X += round_key[2*j + 10];

      A = rotate_right(A ^ X, 1);
      B = rotate_left(B, 1) ^ Y;
      }

   C ^= round_key[4]; D ^= round_key[5]; A ^= round_key[6]; B ^= round_key[7];

   out[ 0] = get_byte(3, C); out[ 1] = get_byte(2, C);
   out[ 2] = get_byte(1, C); out[ 3] = get_byte(0, C);
   out[ 4] = get_byte(3, D); out[ 5] = get_byte(2, D);
   out[ 6] = get_byte(1, D); out[ 7] = get_byte(0, D);
   out[ 8] = get_byte(3, A); out[ 9] = get_byte(2, A);
   out[10] = get_byte(1, A); out[11] = get_byte(0, A);
   out[12] = get_byte(3, B); out[13] = get_byte(2, B);
   out[14] = get_byte(1, B); out[15] = get_byte(0, B);
   }

/*************************************************
* Twofish Decryption                             *
*************************************************/
void Twofish::dec(const byte in[], byte out[]) const
   {
   u32bit A = make_u32bit(in[ 3], in[ 2], in[ 1], in[ 0]),
          B = make_u32bit(in[ 7], in[ 6], in[ 5], in[ 4]),
          C = make_u32bit(in[11], in[10], in[ 9], in[ 8]),
          D = make_u32bit(in[15], in[14], in[13], in[12]);

   A ^= round_key[4]; B ^= round_key[5]; C ^= round_key[6]; D ^= round_key[7];

   for(u32bit j = 0; j != 16; j += 2)
      {
      u32bit X, Y;

      X = SBox0[get_byte(3, A)] ^ SBox1[get_byte(2, A)] ^
          SBox2[get_byte(1, A)] ^ SBox3[get_byte(0, A)];
      Y = SBox0[get_byte(0, B)] ^ SBox1[get_byte(3, B)] ^
          SBox2[get_byte(2, B)] ^ SBox3[get_byte(1, B)];
      X += Y;
      Y += X + round_key[39 - 2*j];
      X += round_key[38 - 2*j];

      C = rotate_left(C, 1) ^ X;
      D = rotate_right(D ^ Y, 1);

      X = SBox0[get_byte(3, C)] ^ SBox1[get_byte(2, C)] ^
          SBox2[get_byte(1, C)] ^ SBox3[get_byte(0, C)];
      Y = SBox0[get_byte(0, D)] ^ SBox1[get_byte(3, D)] ^
          SBox2[get_byte(2, D)] ^ SBox3[get_byte(1, D)];
      X += Y;
      Y += X + round_key[37 - 2*j];
      X += round_key[36 - 2*j];

      A = rotate_left(A, 1) ^ X;
      B = rotate_right(B ^ Y, 1);
      }

   C ^= round_key[0]; D ^= round_key[1]; A ^= round_key[2]; B ^= round_key[3];

   out[ 0] = get_byte(3, C); out[ 1] = get_byte(2, C);
   out[ 2] = get_byte(1, C); out[ 3] = get_byte(0, C);
   out[ 4] = get_byte(3, D); out[ 5] = get_byte(2, D);
   out[ 6] = get_byte(1, D); out[ 7] = get_byte(0, D);
   out[ 8] = get_byte(3, A); out[ 9] = get_byte(2, A);
   out[10] = get_byte(1, A); out[11] = get_byte(0, A);
   out[12] = get_byte(3, B); out[13] = get_byte(2, B);
   out[14] = get_byte(1, B); out[15] = get_byte(0, B);
   }

/*************************************************
* Twofish Key Schedule                           *
*************************************************/
void Twofish::key(const byte key[], u32bit length)
   {
   SecureBuffer<byte, 16> S;

   for(u32bit j = 0; j != length; ++j)
      rs_mul(S + 4*(j/8), key[j], j);

   if(length == 16)
      {
      for(u32bit j = 0; j != 256; ++j)
         {
         SBox0[j] = MDS0[Q0[Q0[j]^S[ 0]]^S[ 4]];
         SBox1[j] = MDS1[Q0[Q1[j]^S[ 1]]^S[ 5]];
         SBox2[j] = MDS2[Q1[Q0[j]^S[ 2]]^S[ 6]];
         SBox3[j] = MDS3[Q1[Q1[j]^S[ 3]]^S[ 7]];
         }
      for(u32bit j = 0; j != 40; j += 2)
         {
         u32bit X = MDS0[Q0[Q0[j  ]^key[ 8]]^key[ 0]] ^
                    MDS1[Q0[Q1[j  ]^key[ 9]]^key[ 1]] ^
                    MDS2[Q1[Q0[j  ]^key[10]]^key[ 2]] ^
                    MDS3[Q1[Q1[j  ]^key[11]]^key[ 3]];
         u32bit Y = MDS0[Q0[Q0[j+1]^key[12]]^key[ 4]] ^
                    MDS1[Q0[Q1[j+1]^key[13]]^key[ 5]] ^
                    MDS2[Q1[Q0[j+1]^key[14]]^key[ 6]] ^
                    MDS3[Q1[Q1[j+1]^key[15]]^key[ 7]];
         Y = rotate_left(Y, 8); X += Y; Y += X;
         round_key[j] = X; round_key[j+1] = rotate_left(Y, 9);
         }
      }
   else if(length == 24)
      {
      for(u32bit j = 0; j != 256; ++j)
         {
         SBox0[j] = MDS0[Q0[Q0[Q1[j]^S[ 0]]^S[ 4]]^S[ 8]];
         SBox1[j] = MDS1[Q0[Q1[Q1[j]^S[ 1]]^S[ 5]]^S[ 9]];
         SBox2[j] = MDS2[Q1[Q0[Q0[j]^S[ 2]]^S[ 6]]^S[10]];
         SBox3[j] = MDS3[Q1[Q1[Q0[j]^S[ 3]]^S[ 7]]^S[11]];
         }
      for(u32bit j = 0; j != 40; j += 2)
         {
         u32bit X = MDS0[Q0[Q0[Q1[j  ]^key[16]]^key[ 8]]^key[ 0]] ^
                    MDS1[Q0[Q1[Q1[j  ]^key[17]]^key[ 9]]^key[ 1]] ^
                    MDS2[Q1[Q0[Q0[j  ]^key[18]]^key[10]]^key[ 2]] ^
                    MDS3[Q1[Q1[Q0[j  ]^key[19]]^key[11]]^key[ 3]];
         u32bit Y = MDS0[Q0[Q0[Q1[j+1]^key[20]]^key[12]]^key[ 4]] ^
                    MDS1[Q0[Q1[Q1[j+1]^key[21]]^key[13]]^key[ 5]] ^
                    MDS2[Q1[Q0[Q0[j+1]^key[22]]^key[14]]^key[ 6]] ^
                    MDS3[Q1[Q1[Q0[j+1]^key[23]]^key[15]]^key[ 7]];
         Y = rotate_left(Y, 8); X += Y; Y += X;
         round_key[j] = X; round_key[j+1] = rotate_left(Y, 9);
         }
      }
   else if(length == 32)
      {
      for(u32bit j = 0; j != 256; ++j)
         {
         SBox0[j] = MDS0[Q0[Q0[Q1[Q1[j]^S[ 0]]^S[ 4]]^S[ 8]]^S[12]];
         SBox1[j] = MDS1[Q0[Q1[Q1[Q0[j]^S[ 1]]^S[ 5]]^S[ 9]]^S[13]];
         SBox2[j] = MDS2[Q1[Q0[Q0[Q0[j]^S[ 2]]^S[ 6]]^S[10]]^S[14]];
         SBox3[j] = MDS3[Q1[Q1[Q0[Q1[j]^S[ 3]]^S[ 7]]^S[11]]^S[15]];
         }
      for(u32bit j = 0; j != 40; j += 2)
         {
         u32bit X = MDS0[Q0[Q0[Q1[Q1[j  ]^key[24]]^key[16]]^key[ 8]]^key[ 0]] ^
                    MDS1[Q0[Q1[Q1[Q0[j  ]^key[25]]^key[17]]^key[ 9]]^key[ 1]] ^
                    MDS2[Q1[Q0[Q0[Q0[j  ]^key[26]]^key[18]]^key[10]]^key[ 2]] ^
                    MDS3[Q1[Q1[Q0[Q1[j  ]^key[27]]^key[19]]^key[11]]^key[ 3]];
         u32bit Y = MDS0[Q0[Q0[Q1[Q1[j+1]^key[28]]^key[20]]^key[12]]^key[ 4]] ^
                    MDS1[Q0[Q1[Q1[Q0[j+1]^key[29]]^key[21]]^key[13]]^key[ 5]] ^
                    MDS2[Q1[Q0[Q0[Q0[j+1]^key[30]]^key[22]]^key[14]]^key[ 6]] ^
                    MDS3[Q1[Q1[Q0[Q1[j+1]^key[31]]^key[23]]^key[15]]^key[ 7]];
         Y = rotate_left(Y, 8); X += Y; Y += X;
         round_key[j] = X; round_key[j+1] = rotate_left(Y, 9);
         }
      }
   }

/*************************************************
* Do one column of the RS matrix multiplcation   *
*************************************************/
void Twofish::rs_mul(byte S[4], byte key, u32bit offset)
   {
   if(key)
      {
      byte X = POLY_TO_EXP[key - 1];

      byte RS1 = RS[(4*offset  ) % 32];
      byte RS2 = RS[(4*offset+1) % 32];
      byte RS3 = RS[(4*offset+2) % 32];
      byte RS4 = RS[(4*offset+3) % 32];

      S[0] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS1 - 1]) % 255];
      S[1] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS2 - 1]) % 255];
      S[2] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS3 - 1]) % 255];
      S[3] ^= EXP_TO_POLY[(X + POLY_TO_EXP[RS4 - 1]) % 255];
      }
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void Twofish::clear() throw()
   {
   SBox0.clear();
   SBox1.clear();
   SBox2.clear();
   SBox3.clear();
   round_key.clear();
   }

}
