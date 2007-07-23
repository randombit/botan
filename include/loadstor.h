/*************************************************
* Load/Store Operators Header File               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_LOAD_STORE_H__
#define BOTAN_LOAD_STORE_H__

#include <botan/types.h>

namespace Botan {

/*************************************************
* Byte Extraction Function                       *
*************************************************/
template<typename T> inline byte get_byte(u32bit byte_num, T input)
   {
   return (input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3));
   }

/*************************************************
* Byte to Word Conversions                       *
*************************************************/
inline u16bit make_u16bit(byte i0, byte i1)
   {
   return ((static_cast<u16bit>(i0) << 8) | i1);
   }

inline u32bit make_u32bit(byte i0, byte i1, byte i2, byte i3)
   {
   return ((static_cast<u32bit>(i0) << 24) |
           (static_cast<u32bit>(i1) << 16) |
           (static_cast<u32bit>(i2) <<  8) |
           (static_cast<u32bit>(i3)));
   }

inline u64bit make_u64bit(byte i0, byte i1, byte i2, byte i3,
                          byte i4, byte i5, byte i6, byte i7)
    {
   return ((static_cast<u64bit>(i0) << 56) |
           (static_cast<u64bit>(i1) << 48) |
           (static_cast<u64bit>(i2) << 40) |
           (static_cast<u64bit>(i3) << 32) |
           (static_cast<u64bit>(i4) << 24) |
           (static_cast<u64bit>(i5) << 16) |
           (static_cast<u64bit>(i6) <<  8) |
           (static_cast<u64bit>(i7)));
    }

/*************************************************
* Endian-Specific Word Loading Operations        *
*************************************************/
template<typename T>
inline T load_be(const byte in[], u32bit off)
   {
   in += off * sizeof(T);
   T out = 0;
   for(u32bit j = 0; j != sizeof(T); j++)
      out = (out << 8) | in[j];
   return out;
   }

template<typename T>
inline T load_le(const byte in[], u32bit off)
   {
   in += off * sizeof(T);
   T out = 0;
   for(u32bit j = 0; j != sizeof(T); j++)
      out = (out << 8) | in[sizeof(T)-1-j];
   return out;
   }

template<>
inline u32bit load_be<u32bit>(const byte in[], u32bit off)
   {
   in += off * sizeof(u32bit);
   return make_u32bit(in[0], in[1], in[2], in[3]);
   }

template<>
inline u32bit load_le<u32bit>(const byte in[], u32bit off)
   {
   in += off * sizeof(u32bit);
   return make_u32bit(in[3], in[2], in[1], in[0]);
   }

template<>
inline u64bit load_be<u64bit>(const byte in[], u32bit off)
   {
   in += off * sizeof(u64bit);
   return make_u64bit(in[0], in[1], in[2], in[3],
                      in[4], in[5], in[6], in[7]);
   }

template<>
inline u64bit load_le<u64bit>(const byte in[], u32bit off)
   {
   in += off * sizeof(u64bit);
   return make_u64bit(in[7], in[6], in[5], in[4],
                      in[3], in[2], in[1], in[0]);
   }

/*************************************************
* Endian-Specific Word Storing Operations        *
*************************************************/
inline void store_be(u16bit in, byte out[2])
   {
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   }

inline void store_le(u16bit in, byte out[2])
   {
   out[0] = get_byte(1, in);
   out[1] = get_byte(0, in);
   }

inline void store_be(u32bit in, byte out[4])
   {
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
   }

inline void store_le(u32bit in, byte out[4])
   {
   out[0] = get_byte(3, in);
   out[1] = get_byte(2, in);
   out[2] = get_byte(1, in);
   out[3] = get_byte(0, in);
   }

inline void store_be(u64bit in, byte out[8])
   {
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
   out[4] = get_byte(4, in);
   out[5] = get_byte(5, in);
   out[6] = get_byte(6, in);
   out[7] = get_byte(7, in);
   }

inline void store_le(u64bit in, byte out[8])
   {
   out[0] = get_byte(7, in);
   out[1] = get_byte(6, in);
   out[2] = get_byte(5, in);
   out[3] = get_byte(4, in);
   out[4] = get_byte(3, in);
   out[5] = get_byte(2, in);
   out[6] = get_byte(1, in);
   out[7] = get_byte(0, in);
   }

template<typename T>
inline void store_le(byte out[], T a, T b)
   {
   store_le(a, out + (0 * sizeof(T)));
   store_le(b, out + (1 * sizeof(T)));
   }

template<typename T>
inline void store_be(byte out[], T a, T b)
   {
   store_be(a, out + (0 * sizeof(T)));
   store_be(b, out + (1 * sizeof(T)));
   }

template<typename T>
inline void store_le(byte out[], T a, T b, T c, T d)
   {
   store_le(a, out + (0 * sizeof(T)));
   store_le(b, out + (1 * sizeof(T)));
   store_le(c, out + (2 * sizeof(T)));
   store_le(d, out + (3 * sizeof(T)));
   }

template<typename T>
inline void store_be(byte out[], T a, T b, T c, T d)
   {
   store_be(a, out + (0 * sizeof(T)));
   store_be(b, out + (1 * sizeof(T)));
   store_be(c, out + (2 * sizeof(T)));
   store_be(d, out + (3 * sizeof(T)));
   }

}

#endif
