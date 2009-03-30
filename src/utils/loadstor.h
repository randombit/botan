/*
* Load/Store Operators
* (C) 1999-2007 Jack Lloyd
*     2007 Yves Jerschow
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LOAD_STORE_H__
#define BOTAN_LOAD_STORE_H__

#include <botan/types.h>
#include <botan/bswap.h>
#include <botan/rotate.h>

#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK

#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)

#define BOTAN_ENDIAN_N2B(x) (x)
#define BOTAN_ENDIAN_B2N(x) (x)

#define BOTAN_ENDIAN_N2L(x) reverse_bytes(x)
#define BOTAN_ENDIAN_L2N(x) reverse_bytes(x)

#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)

#define BOTAN_ENDIAN_N2L(x) (x)
#define BOTAN_ENDIAN_L2N(x) (x)

#define BOTAN_ENDIAN_N2B(x) reverse_bytes(x)
#define BOTAN_ENDIAN_B2N(x) reverse_bytes(x)

#endif

#endif

namespace Botan {

/*
* Byte Extraction Function
*/
template<typename T> inline byte get_byte(u32bit byte_num, T input)
   {
   return (input >> ((sizeof(T)-1-(byte_num&(sizeof(T)-1))) << 3));
   }

/*
* Byte to Word Conversions
*/
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

/*
* Endian-Specific Word Loading Operations
*/
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
inline u16bit load_be<u16bit>(const byte in[], u32bit off)
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   return BOTAN_ENDIAN_N2B(*(reinterpret_cast<const u16bit*>(in) + off));
#else
   in += off * sizeof(u16bit);
   return make_u16bit(in[0], in[1]);
#endif
   }

template<>
inline u16bit load_le<u16bit>(const byte in[], u32bit off)
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   return BOTAN_ENDIAN_N2L(*(reinterpret_cast<const u16bit*>(in) + off));
#else
   in += off * sizeof(u16bit);
   return make_u16bit(in[1], in[0]);
#endif
   }

template<>
inline u32bit load_be<u32bit>(const byte in[], u32bit off)
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   return BOTAN_ENDIAN_N2B(*(reinterpret_cast<const u32bit*>(in) + off));
#else
   in += off * sizeof(u32bit);
   return make_u32bit(in[0], in[1], in[2], in[3]);
#endif
   }

template<>
inline u32bit load_le<u32bit>(const byte in[], u32bit off)
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   return BOTAN_ENDIAN_N2L(*(reinterpret_cast<const u32bit*>(in) + off));
#else
   in += off * sizeof(u32bit);
   return make_u32bit(in[3], in[2], in[1], in[0]);
#endif
   }

template<>
inline u64bit load_be<u64bit>(const byte in[], u32bit off)
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   return BOTAN_ENDIAN_N2B(*(reinterpret_cast<const u64bit*>(in) + off));
#else
   in += off * sizeof(u64bit);
   return make_u64bit(in[0], in[1], in[2], in[3],
                      in[4], in[5], in[6], in[7]);
#endif
   }

template<>
inline u64bit load_le<u64bit>(const byte in[], u32bit off)
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   return BOTAN_ENDIAN_N2L(*(reinterpret_cast<const u64bit*>(in) + off));
#else
   in += off * sizeof(u64bit);
   return make_u64bit(in[7], in[6], in[5], in[4],
                      in[3], in[2], in[1], in[0]);
#endif
   }

/*
* Endian-Specific Word Storing Operations
*/
inline void store_be(u16bit in, byte out[2])
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   *reinterpret_cast<u16bit*>(out) = BOTAN_ENDIAN_B2N(in);
#else
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
#endif
   }

inline void store_le(u16bit in, byte out[2])
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   *reinterpret_cast<u16bit*>(out) = BOTAN_ENDIAN_L2N(in);
#else
   out[0] = get_byte(1, in);
   out[1] = get_byte(0, in);
#endif
   }

inline void store_be(u32bit in, byte out[4])
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   *reinterpret_cast<u32bit*>(out) = BOTAN_ENDIAN_B2N(in);
#else
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
#endif
   }

inline void store_le(u32bit in, byte out[4])
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   *reinterpret_cast<u32bit*>(out) = BOTAN_ENDIAN_L2N(in);
#else
   out[0] = get_byte(3, in);
   out[1] = get_byte(2, in);
   out[2] = get_byte(1, in);
   out[3] = get_byte(0, in);
#endif
   }

inline void store_be(u64bit in, byte out[8])
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   *reinterpret_cast<u64bit*>(out) = BOTAN_ENDIAN_B2N(in);
#else
   out[0] = get_byte(0, in);
   out[1] = get_byte(1, in);
   out[2] = get_byte(2, in);
   out[3] = get_byte(3, in);
   out[4] = get_byte(4, in);
   out[5] = get_byte(5, in);
   out[6] = get_byte(6, in);
   out[7] = get_byte(7, in);
#endif
   }

inline void store_le(u64bit in, byte out[8])
   {
#if BOTAN_TARGET_UNALIGNED_LOADSTOR_OK
   *reinterpret_cast<u64bit*>(out) = BOTAN_ENDIAN_L2N(in);
#else
   out[0] = get_byte(7, in);
   out[1] = get_byte(6, in);
   out[2] = get_byte(5, in);
   out[3] = get_byte(4, in);
   out[4] = get_byte(3, in);
   out[5] = get_byte(2, in);
   out[6] = get_byte(1, in);
   out[7] = get_byte(0, in);
#endif
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
