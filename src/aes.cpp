/*************************************************
* AES Source File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/aes.h>
#include <botan/bit_ops.h>

namespace Botan {

/*************************************************
* AES Encryption                                 *
*************************************************/
void AES::enc(const byte in[], byte out[]) const
   {
   const u32bit* TE0 = TE;
   const u32bit* TE1 = TE + 256;
   const u32bit* TE2 = TE + 512;
   const u32bit* TE3 = TE + 768;

   u32bit T0, T1, T2, T3, B0, B1, B2, B3;
   B0 = TE0[in[ 0] ^ ME[ 0]] ^ TE1[in[ 5] ^ ME[ 5]] ^
        TE2[in[10] ^ ME[10]] ^ TE3[in[15] ^ ME[15]] ^ EK[0];
   B1 = TE0[in[ 4] ^ ME[ 4]] ^ TE1[in[ 9] ^ ME[ 9]] ^
        TE2[in[14] ^ ME[14]] ^ TE3[in[ 3] ^ ME[ 3]] ^ EK[1];
   B2 = TE0[in[ 8] ^ ME[ 8]] ^ TE1[in[13] ^ ME[13]] ^
        TE2[in[ 2] ^ ME[ 2]] ^ TE3[in[ 7] ^ ME[ 7]] ^ EK[2];
   B3 = TE0[in[12] ^ ME[12]] ^ TE1[in[ 1] ^ ME[ 1]] ^
        TE2[in[ 6] ^ ME[ 6]] ^ TE3[in[11] ^ ME[11]] ^ EK[3];
   for(u32bit j = 1; j != ROUNDS - 1; j += 2)
      {
      T0 = TE0[get_byte(0, B0)] ^ TE1[get_byte(1, B1)] ^
           TE2[get_byte(2, B2)] ^ TE3[get_byte(3, B3)] ^ EK[4*j+0];
      T1 = TE0[get_byte(0, B1)] ^ TE1[get_byte(1, B2)] ^
           TE2[get_byte(2, B3)] ^ TE3[get_byte(3, B0)] ^ EK[4*j+1];
      T2 = TE0[get_byte(0, B2)] ^ TE1[get_byte(1, B3)] ^
           TE2[get_byte(2, B0)] ^ TE3[get_byte(3, B1)] ^ EK[4*j+2];
      T3 = TE0[get_byte(0, B3)] ^ TE1[get_byte(1, B0)] ^
           TE2[get_byte(2, B1)] ^ TE3[get_byte(3, B2)] ^ EK[4*j+3];
      B0 = TE0[get_byte(0, T0)] ^ TE1[get_byte(1, T1)] ^
           TE2[get_byte(2, T2)] ^ TE3[get_byte(3, T3)] ^ EK[4*j+4];
      B1 = TE0[get_byte(0, T1)] ^ TE1[get_byte(1, T2)] ^
           TE2[get_byte(2, T3)] ^ TE3[get_byte(3, T0)] ^ EK[4*j+5];
      B2 = TE0[get_byte(0, T2)] ^ TE1[get_byte(1, T3)] ^
           TE2[get_byte(2, T0)] ^ TE3[get_byte(3, T1)] ^ EK[4*j+6];
      B3 = TE0[get_byte(0, T3)] ^ TE1[get_byte(1, T0)] ^
           TE2[get_byte(2, T1)] ^ TE3[get_byte(3, T2)] ^ EK[4*j+7];
      }
   out[ 0] = SE[get_byte(0, B0)] ^ ME[16];
   out[ 1] = SE[get_byte(1, B1)] ^ ME[17];
   out[ 2] = SE[get_byte(2, B2)] ^ ME[18];
   out[ 3] = SE[get_byte(3, B3)] ^ ME[19];
   out[ 4] = SE[get_byte(0, B1)] ^ ME[20];
   out[ 5] = SE[get_byte(1, B2)] ^ ME[21];
   out[ 6] = SE[get_byte(2, B3)] ^ ME[22];
   out[ 7] = SE[get_byte(3, B0)] ^ ME[23];
   out[ 8] = SE[get_byte(0, B2)] ^ ME[24];
   out[ 9] = SE[get_byte(1, B3)] ^ ME[25];
   out[10] = SE[get_byte(2, B0)] ^ ME[26];
   out[11] = SE[get_byte(3, B1)] ^ ME[27];
   out[12] = SE[get_byte(0, B3)] ^ ME[28];
   out[13] = SE[get_byte(1, B0)] ^ ME[29];
   out[14] = SE[get_byte(2, B1)] ^ ME[30];
   out[15] = SE[get_byte(3, B2)] ^ ME[31];
   }

/*************************************************
* AES Decryption                                 *
*************************************************/
void AES::dec(const byte in[], byte out[]) const
   {
   const u32bit* TD0 = TD;
   const u32bit* TD1 = TD + 256;
   const u32bit* TD2 = TD + 512;
   const u32bit* TD3 = TD + 768;

   u32bit T0, T1, T2, T3, B0, B1, B2, B3;
   B0 = TD0[in[ 0] ^ MD[ 0]] ^ TD1[in[13] ^ MD[13]] ^
        TD2[in[10] ^ MD[10]] ^ TD3[in[ 7] ^ MD[ 7]] ^ DK[0];
   B1 = TD0[in[ 4] ^ MD[ 4]] ^ TD1[in[ 1] ^ MD[ 1]] ^
        TD2[in[14] ^ MD[14]] ^ TD3[in[11] ^ MD[11]] ^ DK[1];
   B2 = TD0[in[ 8] ^ MD[ 8]] ^ TD1[in[ 5] ^ MD[ 5]] ^
        TD2[in[ 2] ^ MD[ 2]] ^ TD3[in[15] ^ MD[15]] ^ DK[2];
   B3 = TD0[in[12] ^ MD[12]] ^ TD1[in[ 9] ^ MD[ 9]] ^
        TD2[in[ 6] ^ MD[ 6]] ^ TD3[in[ 3] ^ MD[ 3]] ^ DK[3];
   for(u32bit j = 1; j != ROUNDS - 1; j += 2)
      {
      T0 = TD0[get_byte(0, B0)] ^ TD1[get_byte(1, B3)] ^
           TD2[get_byte(2, B2)] ^ TD3[get_byte(3, B1)] ^ DK[4*j+0];
      T1 = TD0[get_byte(0, B1)] ^ TD1[get_byte(1, B0)] ^
           TD2[get_byte(2, B3)] ^ TD3[get_byte(3, B2)] ^ DK[4*j+1];
      T2 = TD0[get_byte(0, B2)] ^ TD1[get_byte(1, B1)] ^
           TD2[get_byte(2, B0)] ^ TD3[get_byte(3, B3)] ^ DK[4*j+2];
      T3 = TD0[get_byte(0, B3)] ^ TD1[get_byte(1, B2)] ^
           TD2[get_byte(2, B1)] ^ TD3[get_byte(3, B0)] ^ DK[4*j+3];
      B0 = TD0[get_byte(0, T0)] ^ TD1[get_byte(1, T3)] ^
           TD2[get_byte(2, T2)] ^ TD3[get_byte(3, T1)] ^ DK[4*j+4];
      B1 = TD0[get_byte(0, T1)] ^ TD1[get_byte(1, T0)] ^
           TD2[get_byte(2, T3)] ^ TD3[get_byte(3, T2)] ^ DK[4*j+5];
      B2 = TD0[get_byte(0, T2)] ^ TD1[get_byte(1, T1)] ^
           TD2[get_byte(2, T0)] ^ TD3[get_byte(3, T3)] ^ DK[4*j+6];
      B3 = TD0[get_byte(0, T3)] ^ TD1[get_byte(1, T2)] ^
           TD2[get_byte(2, T1)] ^ TD3[get_byte(3, T0)] ^ DK[4*j+7];
      }
   out[ 0] = SD[get_byte(0, B0)] ^ MD[16];
   out[ 1] = SD[get_byte(1, B3)] ^ MD[17];
   out[ 2] = SD[get_byte(2, B2)] ^ MD[18];
   out[ 3] = SD[get_byte(3, B1)] ^ MD[19];
   out[ 4] = SD[get_byte(0, B1)] ^ MD[20];
   out[ 5] = SD[get_byte(1, B0)] ^ MD[21];
   out[ 6] = SD[get_byte(2, B3)] ^ MD[22];
   out[ 7] = SD[get_byte(3, B2)] ^ MD[23];
   out[ 8] = SD[get_byte(0, B2)] ^ MD[24];
   out[ 9] = SD[get_byte(1, B1)] ^ MD[25];
   out[10] = SD[get_byte(2, B0)] ^ MD[26];
   out[11] = SD[get_byte(3, B3)] ^ MD[27];
   out[12] = SD[get_byte(0, B3)] ^ MD[28];
   out[13] = SD[get_byte(1, B2)] ^ MD[29];
   out[14] = SD[get_byte(2, B1)] ^ MD[30];
   out[15] = SD[get_byte(3, B0)] ^ MD[31];
   }

/*************************************************
* AES Key Schedule                               *
*************************************************/
void AES::key(const byte key[], u32bit length)
   {
   static const u32bit RC[10] = {
      0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
      0x40000000, 0x80000000, 0x1B000000, 0x36000000 };
   ROUNDS = (length / 4) + 6;

   SecureBuffer<u32bit, 64> XEK, XDK;

   const u32bit X = length / 4;
   for(u32bit j = 0; j != X; ++j)
      XEK[j] = make_u32bit(key[4*j], key[4*j+1], key[4*j+2], key[4*j+3]);
   for(u32bit j = X; j < 4*(ROUNDS+1); j += X)
      {
      XEK[j] = XEK[j-X] ^ S(rotate_left(XEK[j-1], 8)) ^ RC[(j-X)/X];
      for(u32bit k = 1; k != X; ++k)
         {
         if(X == 8 && k == 4)
            XEK[j+k] = XEK[j+k-X] ^ S(XEK[j+k-1]);
         else
            XEK[j+k] = XEK[j+k-X] ^ XEK[j+k-1];
         }
      }

   for(u32bit j = 0; j != 4*(ROUNDS+1); j += 4)
      {
      XDK[j  ] = XEK[4*ROUNDS-j  ];
      XDK[j+1] = XEK[4*ROUNDS-j+1];
      XDK[j+2] = XEK[4*ROUNDS-j+2];
      XDK[j+3] = XEK[4*ROUNDS-j+3];
      }

   for(u32bit j = 4; j != length + 24; ++j)
      XDK[j] = TD[SE[get_byte(0, XDK[j])] +   0] ^
               TD[SE[get_byte(1, XDK[j])] + 256] ^
               TD[SE[get_byte(2, XDK[j])] + 512] ^
               TD[SE[get_byte(3, XDK[j])] + 768];

   for(u32bit j = 0; j != 4; ++j)
      for(u32bit k = 0; k != 4; ++k)
         {
         ME[4*j+k   ] = get_byte(k, XEK[j]);
         ME[4*j+k+16] = get_byte(k, XEK[j+4*ROUNDS]);
         MD[4*j+k   ] = get_byte(k, XDK[j]);
         MD[4*j+k+16] = get_byte(k, XEK[j]);
         }

   EK.copy(XEK + 4, length + 20);
   DK.copy(XDK + 4, length + 20);
   }

/*************************************************
* AES Byte Substitution                          *
*************************************************/
u32bit AES::S(u32bit input)
   {
   return make_u32bit(SE[get_byte(0, input)], SE[get_byte(1, input)],
                      SE[get_byte(2, input)], SE[get_byte(3, input)]);
   }

/*************************************************
* AES Constructor                                *
*************************************************/
AES::AES(u32bit key_size) : BlockCipher(16, key_size)
   {
   if(key_size != 16 && key_size != 24 && key_size != 32)
      throw Invalid_Key_Length(name(), key_size);
   ROUNDS = (key_size / 4) + 6;
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void AES::clear() throw()
   {
   EK.clear();
   DK.clear();
   ME.clear();
   MD.clear();
   }

}
