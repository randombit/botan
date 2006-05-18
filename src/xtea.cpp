/*************************************************
* XTEA Source File                               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/xtea.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>

namespace Botan {

/*************************************************
* XTEA Encryption                                *
*************************************************/
void XTEA::enc(const byte in[], byte out[]) const
   {
   u32bit left  = make_u32bit(in[0], in[1], in[2], in[3]),
          right = make_u32bit(in[4], in[5], in[6], in[7]);
   for(u32bit j = 0; j != 32; ++j)
      {
      left  += (((right << 4) ^ (right >> 5)) + right) ^ EK[2*j];
      right += (((left  << 4) ^ (left  >> 5)) +  left) ^ EK[2*j+1];
      }
   out[0] = get_byte(0, left);  out[1] = get_byte(1, left);
   out[2] = get_byte(2, left);  out[3] = get_byte(3, left);
   out[4] = get_byte(0, right); out[5] = get_byte(1, right);
   out[6] = get_byte(2, right); out[7] = get_byte(3, right);
   }

/*************************************************
* XTEA Decryption                                *
*************************************************/
void XTEA::dec(const byte in[], byte out[]) const
   {
   u32bit left  = make_u32bit(in[0], in[1], in[2], in[3]),
          right = make_u32bit(in[4], in[5], in[6], in[7]);
   for(u32bit j = 32; j > 0; --j)
      {
      right -= (((left  << 4) ^ (left  >> 5)) +  left) ^ EK[2*j - 1];
      left  -= (((right << 4) ^ (right >> 5)) + right) ^ EK[2*j - 2];
      }
   out[0] = get_byte(0, left);  out[1] = get_byte(1, left);
   out[2] = get_byte(2, left);  out[3] = get_byte(3, left);
   out[4] = get_byte(0, right); out[5] = get_byte(1, right);
   out[6] = get_byte(2, right); out[7] = get_byte(3, right);
   }

/*************************************************
* XTEA Key Schedule                              *
*************************************************/
void XTEA::key(const byte key[], u32bit)
   {
   static const u32bit DELTAS[64] = {
      0x00000000, 0x9E3779B9, 0x9E3779B9, 0x3C6EF372, 0x3C6EF372, 0xDAA66D2B,
      0xDAA66D2B, 0x78DDE6E4, 0x78DDE6E4, 0x1715609D, 0x1715609D, 0xB54CDA56,
      0xB54CDA56, 0x5384540F, 0x5384540F, 0xF1BBCDC8, 0xF1BBCDC8, 0x8FF34781,
      0x8FF34781, 0x2E2AC13A, 0x2E2AC13A, 0xCC623AF3, 0xCC623AF3, 0x6A99B4AC,
      0x6A99B4AC, 0x08D12E65, 0x08D12E65, 0xA708A81E, 0xA708A81E, 0x454021D7,
      0x454021D7, 0xE3779B90, 0xE3779B90, 0x81AF1549, 0x81AF1549, 0x1FE68F02,
      0x1FE68F02, 0xBE1E08BB, 0xBE1E08BB, 0x5C558274, 0x5C558274, 0xFA8CFC2D,
      0xFA8CFC2D, 0x98C475E6, 0x98C475E6, 0x36FBEF9F, 0x36FBEF9F, 0xD5336958,
      0xD5336958, 0x736AE311, 0x736AE311, 0x11A25CCA, 0x11A25CCA, 0xAFD9D683,
      0xAFD9D683, 0x4E11503C, 0x4E11503C, 0xEC48C9F5, 0xEC48C9F5, 0x8A8043AE,
      0x8A8043AE, 0x28B7BD67, 0x28B7BD67, 0xC6EF3720 };

   static const byte KEY_INDEX[64] = {
      0x00, 0x03, 0x01, 0x02, 0x02, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01, 0x03,
      0x02, 0x02, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x02, 0x03, 0x03, 0x02,
      0x00, 0x01, 0x01, 0x01, 0x02, 0x00, 0x03, 0x03, 0x00, 0x02, 0x01, 0x01,
      0x02, 0x01, 0x03, 0x00, 0x00, 0x03, 0x01, 0x02, 0x02, 0x01, 0x03, 0x01,
      0x00, 0x00, 0x01, 0x03, 0x02, 0x02, 0x03, 0x02, 0x00, 0x01, 0x01, 0x00,
      0x02, 0x03, 0x03, 0x02 };

   SecureBuffer<u32bit, 4> UK;
   for(u32bit j = 0; j != 4; ++j)
      UK[j] = make_u32bit(key[4*j], key[4*j+1], key[4*j+2], key[4*j+3]);
   for(u32bit j = 0; j != 64; ++j)
      EK[j] = DELTAS[j] + UK[KEY_INDEX[j]];
   }

}
