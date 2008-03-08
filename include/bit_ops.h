/*************************************************
* Bit/Word Operations Header File                *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_BIT_OPS_H__
#define BOTAN_BIT_OPS_H__

#include <botan/types.h>

namespace Botan {

/*************************************************
* Word Rotation Functions                        *
*************************************************/
template<typename T> inline T rotate_left(T input, u32bit rot)
   {
   return static_cast<T>((input << rot) | (input >> (8*sizeof(T)-rot)));;
   }

template<typename T> inline T rotate_right(T input, u32bit rot)
   {
   return static_cast<T>((input >> rot) | (input << (8*sizeof(T)-rot)));
   }

/*************************************************
* Byte Swapping Functions                        *
*************************************************/
inline u16bit reverse_bytes(u16bit input)
   {
   return rotate_left(input, 8);
   }

inline u32bit reverse_bytes(u32bit input)
   {
   input = ((input & 0xFF00FF00) >> 8) | ((input & 0x00FF00FF) << 8);
   return rotate_left(input, 16);
   }

inline u64bit reverse_bytes(u64bit input)
   {
   return rotate_left(static_cast<u32bit>(input      ), 16) |
          rotate_left(static_cast<u32bit>(input >> 32), 16);
   }

/*************************************************
* Array XOR                                      *
*************************************************/
void xor_buf(byte[], const byte[], u32bit);
void xor_buf(byte[], const byte[], const byte[], u32bit);

/*************************************************
* Simple Bit Manipulation                        *
*************************************************/
bool power_of_2(u64bit);
u32bit high_bit(u64bit);
u32bit low_bit(u64bit);
u32bit significant_bytes(u64bit);
u32bit hamming_weight(u64bit);

}

#endif
