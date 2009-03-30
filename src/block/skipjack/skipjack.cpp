/*
* Skipjack
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/skipjack.h>
#include <botan/loadstor.h>

namespace Botan {

/*
* Skipjack Encryption
*/
void Skipjack::enc(const byte in[], byte out[]) const
   {
   u16bit W1 = load_le<u16bit>(in, 3);
   u16bit W2 = load_le<u16bit>(in, 2);
   u16bit W3 = load_le<u16bit>(in, 1);
   u16bit W4 = load_le<u16bit>(in, 0);

   step_A(W1,W4, 1); step_A(W4,W3, 2); step_A(W3,W2, 3); step_A(W2,W1, 4);
   step_A(W1,W4, 5); step_A(W4,W3, 6); step_A(W3,W2, 7); step_A(W2,W1, 8);

   step_B(W1,W2, 9); step_B(W4,W1,10); step_B(W3,W4,11); step_B(W2,W3,12);
   step_B(W1,W2,13); step_B(W4,W1,14); step_B(W3,W4,15); step_B(W2,W3,16);

   step_A(W1,W4,17); step_A(W4,W3,18); step_A(W3,W2,19); step_A(W2,W1,20);
   step_A(W1,W4,21); step_A(W4,W3,22); step_A(W3,W2,23); step_A(W2,W1,24);

   step_B(W1,W2,25); step_B(W4,W1,26); step_B(W3,W4,27); step_B(W2,W3,28);
   step_B(W1,W2,29); step_B(W4,W1,30); step_B(W3,W4,31); step_B(W2,W3,32);

   store_le(out, W4, W3, W2, W1);
   }

/*
* Skipjack Decryption
*/
void Skipjack::dec(const byte in[], byte out[]) const
   {
   u16bit W1 = load_le<u16bit>(in, 3);
   u16bit W2 = load_le<u16bit>(in, 2);
   u16bit W3 = load_le<u16bit>(in, 1);
   u16bit W4 = load_le<u16bit>(in, 0);

   step_Bi(W2,W3,32); step_Bi(W3,W4,31); step_Bi(W4,W1,30); step_Bi(W1,W2,29);
   step_Bi(W2,W3,28); step_Bi(W3,W4,27); step_Bi(W4,W1,26); step_Bi(W1,W2,25);

   step_Ai(W1,W2,24); step_Ai(W2,W3,23); step_Ai(W3,W4,22); step_Ai(W4,W1,21);
   step_Ai(W1,W2,20); step_Ai(W2,W3,19); step_Ai(W3,W4,18); step_Ai(W4,W1,17);

   step_Bi(W2,W3,16); step_Bi(W3,W4,15); step_Bi(W4,W1,14); step_Bi(W1,W2,13);
   step_Bi(W2,W3,12); step_Bi(W3,W4,11); step_Bi(W4,W1,10); step_Bi(W1,W2, 9);

   step_Ai(W1,W2, 8); step_Ai(W2,W3, 7); step_Ai(W3,W4, 6); step_Ai(W4,W1, 5);
   step_Ai(W1,W2, 4); step_Ai(W2,W3, 3); step_Ai(W3,W4, 2); step_Ai(W4,W1, 1);

   store_le(out, W4, W3, W2, W1);
   }

/*
* Skipjack Stepping Rule 'A'
*/
void Skipjack::step_A(u16bit& W1, u16bit& W4, u32bit round) const
   {
   byte G1 = get_byte(0, W1), G2 = get_byte(1, W1), G3;
   G3 = FTABLE[(4 * round - 4) % 10][G2] ^ G1;
   G1 = FTABLE[(4 * round - 3) % 10][G3] ^ G2;
   G2 = FTABLE[(4 * round - 2) % 10][G1] ^ G3;
   G3 = FTABLE[(4 * round - 1) % 10][G2] ^ G1;
   W1 =  make_u16bit(G2, G3);
   W4 ^= W1 ^ round;
   }

/*
* Skipjack Stepping Rule 'B'
*/
void Skipjack::step_B(u16bit& W1, u16bit& W2, u32bit round) const
   {
   W2 ^= W1 ^ round;
   byte G1 = get_byte(0, W1), G2 = get_byte(1, W1), G3;
   G3 = FTABLE[(4 * round - 4) % 10][G2] ^ G1;
   G1 = FTABLE[(4 * round - 3) % 10][G3] ^ G2;
   G2 = FTABLE[(4 * round - 2) % 10][G1] ^ G3;
   G3 = FTABLE[(4 * round - 1) % 10][G2] ^ G1;
   W1 =  make_u16bit(G2, G3);
   }

/*
* Skipjack Invserse Stepping Rule 'A'
*/
void Skipjack::step_Ai(u16bit& W1, u16bit& W2, u32bit round) const
   {
   W1 ^= W2 ^ round;
   byte G1 = get_byte(1, W2), G2 = get_byte(0, W2), G3;
   G3 = FTABLE[(4 * round - 1) % 10][G2] ^ G1;
   G1 = FTABLE[(4 * round - 2) % 10][G3] ^ G2;
   G2 = FTABLE[(4 * round - 3) % 10][G1] ^ G3;
   G3 = FTABLE[(4 * round - 4) % 10][G2] ^ G1;
   W2 = make_u16bit(G3, G2);
   }

/*
* Skipjack Invserse Stepping Rule 'B'
*/
void Skipjack::step_Bi(u16bit& W2, u16bit& W3, u32bit round) const
   {
   byte G1 = get_byte(1, W2), G2 = get_byte(0, W2), G3;
   G3 = FTABLE[(4 * round - 1) % 10][G2] ^ G1;
   G1 = FTABLE[(4 * round - 2) % 10][G3] ^ G2;
   G2 = FTABLE[(4 * round - 3) % 10][G1] ^ G3;
   G3 = FTABLE[(4 * round - 4) % 10][G2] ^ G1;
   W2 = make_u16bit(G3, G2);
   W3 ^= W2 ^ round;
   }

/*
* Skipjack Key Schedule
*/
void Skipjack::key_schedule(const byte key[], u32bit)
   {
   static const byte F[256] = {
      0xA3, 0xD7, 0x09, 0x83, 0xF8, 0x48, 0xF6, 0xF4, 0xB3, 0x21, 0x15, 0x78,
      0x99, 0xB1, 0xAF, 0xF9, 0xE7, 0x2D, 0x4D, 0x8A, 0xCE, 0x4C, 0xCA, 0x2E,
      0x52, 0x95, 0xD9, 0x1E, 0x4E, 0x38, 0x44, 0x28, 0x0A, 0xDF, 0x02, 0xA0,
      0x17, 0xF1, 0x60, 0x68, 0x12, 0xB7, 0x7A, 0xC3, 0xE9, 0xFA, 0x3D, 0x53,
      0x96, 0x84, 0x6B, 0xBA, 0xF2, 0x63, 0x9A, 0x19, 0x7C, 0xAE, 0xE5, 0xF5,
      0xF7, 0x16, 0x6A, 0xA2, 0x39, 0xB6, 0x7B, 0x0F, 0xC1, 0x93, 0x81, 0x1B,
      0xEE, 0xB4, 0x1A, 0xEA, 0xD0, 0x91, 0x2F, 0xB8, 0x55, 0xB9, 0xDA, 0x85,
      0x3F, 0x41, 0xBF, 0xE0, 0x5A, 0x58, 0x80, 0x5F, 0x66, 0x0B, 0xD8, 0x90,
      0x35, 0xD5, 0xC0, 0xA7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56,
      0x6D, 0x98, 0x9B, 0x76, 0x97, 0xFC, 0xB2, 0xC2, 0xB0, 0xFE, 0xDB, 0x20,
      0xE1, 0xEB, 0xD6, 0xE4, 0xDD, 0x47, 0x4A, 0x1D, 0x42, 0xED, 0x9E, 0x6E,
      0x49, 0x3C, 0xCD, 0x43, 0x27, 0xD2, 0x07, 0xD4, 0xDE, 0xC7, 0x67, 0x18,
      0x89, 0xCB, 0x30, 0x1F, 0x8D, 0xC6, 0x8F, 0xAA, 0xC8, 0x74, 0xDC, 0xC9,
      0x5D, 0x5C, 0x31, 0xA4, 0x70, 0x88, 0x61, 0x2C, 0x9F, 0x0D, 0x2B, 0x87,
      0x50, 0x82, 0x54, 0x64, 0x26, 0x7D, 0x03, 0x40, 0x34, 0x4B, 0x1C, 0x73,
      0xD1, 0xC4, 0xFD, 0x3B, 0xCC, 0xFB, 0x7F, 0xAB, 0xE6, 0x3E, 0x5B, 0xA5,
      0xAD, 0x04, 0x23, 0x9C, 0x14, 0x51, 0x22, 0xF0, 0x29, 0x79, 0x71, 0x7E,
      0xFF, 0x8C, 0x0E, 0xE2, 0x0C, 0xEF, 0xBC, 0x72, 0x75, 0x6F, 0x37, 0xA1,
      0xEC, 0xD3, 0x8E, 0x62, 0x8B, 0x86, 0x10, 0xE8, 0x08, 0x77, 0x11, 0xBE,
      0x92, 0x4F, 0x24, 0xC5, 0x32, 0x36, 0x9D, 0xCF, 0xF3, 0xA6, 0xBB, 0xAC,
      0x5E, 0x6C, 0xA9, 0x13, 0x57, 0x25, 0xB5, 0xE3, 0xBD, 0xA8, 0x3A, 0x01,
      0x05, 0x59, 0x2A, 0x46 };

   for(u32bit j = 0; j != 10; ++j)
      for(u32bit k = 0; k != 256; ++k)
         FTABLE[j][k] = F[k ^ key[9-j]];
   }

/*
* Clear memory of sensitive data
*/
void Skipjack::clear() throw()
   {
   for(u32bit j = 0; j != 10; ++j)
      FTABLE[j].clear();
   }

}
