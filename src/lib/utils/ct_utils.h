/*
* Functions for constant time operations on data and testing of
* constant time annotations using ctgrind.
*
* For more information about constant time programming see
* Wagner, Molnar, et al "The Program Counter Security Model"
*
* (C) 2010 Falko Strenzke
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TIMING_ATTACK_CM_H__
#define BOTAN_TIMING_ATTACK_CM_H__

#include <botan/types.h>
#include <vector>

#if defined(BOTAN_USE_CTGRIND)

// These are external symbols from libctgrind.so
extern "C" void ct_poison(const void* address, size_t length);
extern "C" void ct_unpoison(const void* address, size_t length);

#endif

namespace Botan {

#if defined(BOTAN_USE_CTGRIND)

#define BOTAN_CONST_TIME_POISON(p, l) ct_poison(p, l)
#define BOTAN_CONST_TIME_UNPOISON(p, l) ct_unpoison(p, l)

#else

#define BOTAN_CONST_TIME_POISON(p, l)
#define BOTAN_CONST_TIME_UNPOISON(p, l)

#endif

/*
* Constant time operations for 32 bit values:
* mask, select, zero, equals, min, max
*/

/*
* Expand to a mask used for other operations
* @param in an integer
* @return 0 if in == 0 else 0xFFFFFFFF
*/

inline uint32_t ct_expand_mask_32(uint32_t x)
   {
   uint32_t r = x;
   r |= r >> 1;
   r |= r >> 2;
   r |= r >> 4;
   r |= r >> 8;
   r |= r >> 16;
   r &= 1;
   r = ~(r - 1);
   return r;
   }

inline uint32_t ct_select_mask_32(uint32_t mask, uint32_t a, uint32_t b)
   {
   return (a & mask) | (b & ~mask);
   }

inline uint32_t ct_select_cond_32(bool cond, uint32_t a, uint32_t b)
   {
   return ct_select_mask_32(ct_expand_mask_32(static_cast<uint32_t>(cond)), a, b);
   }

inline uint32_t ct_get_high_bit_32(uint32_t x)
   {
   return (x >> (8 * sizeof(x) - 1));
   }

/*
* If x is zero, return 0xFFFF...
* Otherwise returns zero
*/
inline uint32_t ct_is_zero_32(uint32_t x)
   {
   return ct_expand_mask_32(ct_get_high_bit_32(~x & (x-1)));
   }

inline uint32_t ct_is_equal_32(uint32_t x, uint32_t y)
   {
   return ct_is_zero_32(x ^ y);
   }

/**
* Branch-free maximum
* Note: assumes twos-complement signed representation
* @param a an integer
* @param b an integer
* @return max(a,b)
*/
inline uint32_t ct_max_32(uint32_t a, uint32_t b)
   {
   const uint32_t s = b - a;
   return ct_select_cond_32(ct_get_high_bit_32(s), a, b);
   }

/**
* Branch-free minimum
* Note: assumes twos-complement signed representation
* @param a an integer
* @param b an integer
* @return min(a,b)
*/
inline uint32_t ct_min_32(uint32_t a, uint32_t b)
   {
   const uint32_t s = b - a;
   return ct_select_cond_32(ct_get_high_bit_32(s), b, a);
   }

/*
* Constant time operations for 16 bit values:
* mask, select, zero, equals
*/
inline uint16_t ct_expand_mask_16(uint16_t x)
   {
   uint16_t r = x;
   r |= r >> 1;
   r |= r >> 2;
   r |= r >> 4;
   r |= r >> 8;
   r &= 1;
   r = ~(r - 1);
   return r;
   }

inline uint16_t ct_select_mask_16(uint16_t mask, uint16_t a, uint16_t b)
   {
   return (a & mask) | (b & ~mask);
   }

inline uint16_t ct_select_cond_16(bool cond, uint16_t a, uint16_t b)
   {
   return ct_select_mask_16(ct_expand_mask_16(static_cast<uint16_t>(cond)), a, b);
   }

inline uint16_t ct_get_high_bit_16(uint16_t x)
   {
   return (x >> (8 * sizeof(x) - 1));
   }

inline uint16_t ct_is_zero_16(uint16_t x)
   {
   //uint16_t z = x & (x - 1)
   //return ct_expand_mask_16((~x & (x-1))
   return ct_expand_mask_16(ct_get_high_bit_16(~x & (x-1)));
   }

inline uint16_t ct_is_equal_16(uint16_t x, uint16_t y)
   {
   return ct_is_zero_16(x ^ y);
   }

/*
* Constant time operations for 8 bit values:
* mask, select, zero, equals
*/

inline uint8_t ct_expand_mask_8(uint8_t x)
   {
   uint8_t r = x;
   r |= r >> 4;
   r |= r >> 2;
   r |= r >> 1;
   r &= 1;
   r = ~(r - 1);
   return r;
   }

inline uint8_t ct_select_mask_8(uint8_t mask, uint8_t a, uint8_t b)
   {
   return (a & mask) | (b & ~mask);
   }

inline uint8_t ct_select_cond_8(bool cond, uint8_t a, uint8_t b)
   {
   return ct_select_mask_8(ct_expand_mask_8(static_cast<uint8_t>(cond)), a, b);
   }

inline uint8_t ct_get_high_bit_8(uint8_t x)
   {
   return (x >> (8 * sizeof(x) - 1));
   }

inline uint8_t ct_is_zero_8(uint8_t x)
   {
   return ct_expand_mask_8(ct_get_high_bit_8(~x & (x-1)));
   }

inline uint8_t ct_is_equal_8(uint8_t x, uint8_t y)
   {
   return ct_is_zero_8(x ^ y);
   }

}

#endif
