/*************************************************
* Bit/Word Operations Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_BIT_OPS_H__
#define BOTAN_BIT_OPS_H__

#include <botan/types.h>

namespace Botan {

/*************************************************
* Rotation Functions                             *
*************************************************/
template<typename T> inline T rotate_left(T input, u32bit rot)
   { return (T)((input << rot) | (input >> (8*sizeof(T)-rot))); }

template<typename T> inline T rotate_right(T input, u32bit rot)
   { return (T)((input >> rot) | (input << (8*sizeof(T)-rot))); }

/*************************************************
* Byte Extraction Function                       *
*************************************************/
template<typename T> inline byte get_byte(u32bit byte_num, T input)
   { return (byte)(input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3)); }

/*************************************************
* Byte to Word Conversions                       *
*************************************************/
inline u16bit make_u16bit(byte input0, byte input1)
   { return (u16bit)(((u16bit)input0 << 8) | input1); }

inline u32bit make_u32bit(byte input0, byte input1, byte input2, byte input3)
   { return (u32bit)(((u32bit)input0 << 24) | ((u32bit)input1 << 16) |
                     ((u32bit)input2 <<  8) | input3); }

inline u64bit make_u64bit(byte input0, byte input1, byte input2, byte input3,
                          byte input4, byte input5, byte input6, byte input7)
   {
   return (u64bit)(((u64bit)input0 << 56) | ((u64bit)input1 << 48) |
                   ((u64bit)input2 << 40) | ((u64bit)input3 << 32) |
                   ((u64bit)input4 << 24) | ((u64bit)input5 << 16) |
                   ((u64bit)input6 <<  8) | input7);
   }

/*************************************************
* XOR Functions                                  *
*************************************************/
void xor_buf(byte[], const byte[], u32bit);
void xor_buf(byte[], const byte[], const byte[], u32bit);

/*************************************************
* Misc Utility Functions                         *
*************************************************/
bool power_of_2(u64bit);
u32bit high_bit(u64bit);
u32bit low_bit(u64bit);
u32bit significant_bytes(u64bit);
u32bit hamming_weight(u64bit);

}

#endif
