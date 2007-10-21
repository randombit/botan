/*************************************************
* Bit/Word Operations Header File                *
* (C) 1999-2007 The Botan Project                *
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
* Byteswap                                       *
*************************************************/
u16bit reverse_bytes(u16bit);
u32bit reverse_bytes(u32bit);
u64bit reverse_bytes(u64bit);

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
