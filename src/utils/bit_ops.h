/*
* Bit/Word Operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BIT_OPS_H__
#define BOTAN_BIT_OPS_H__

#include <botan/types.h>

namespace Botan {

/*
* Return true iff arg is 2**n for some n > 0
* T should be an unsigned integer type
*/
template<typename T>
inline bool power_of_2(T arg)
   {
   return ((arg != 0 && arg != 1) && ((arg & (arg-1)) == 0));
   }

/*
* Return the index of the highest set bit
* T is an unsigned integer type
*/
template<typename T>
inline u32bit high_bit(T n)
   {
   for(u32bit i = 8*sizeof(T); i > 0; --i)
      if((n >> (i - 1)) & 0x01)
         return i;
   return 0;
   }

/*
* Return the index of the lowest set bit
*/
template<typename T>
inline u32bit low_bit(T n)
   {
   for(u32bit i = 0; i != 8*sizeof(T); ++i)
      if((n >> i) & 0x01)
         return (i + 1);
   return 0;
   }

/*
* Return the number of significant bytes in n
*/
template<typename T>
inline u32bit significant_bytes(T n)
   {
   for(u32bit j = 0; j != sizeof(T); ++j)
      if(get_byte(j, n))
         return sizeof(T)-j;
   return 0;
   }

/*
* Return the Hamming weight of n
*/
template<typename T>
inline u32bit hamming_weight(T n)
   {
   const byte NIBBLE_WEIGHTS[] = {
      0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4 };

   u32bit weight = 0;
   for(u32bit i = 0; i != 2*sizeof(T); ++i)
      weight += NIBBLE_WEIGHTS[(n >> (4*i)) & 0x0F];
   return weight;
   }

/*
* Count the trailing zero bits in n
*/
template<typename T>
inline u32bit ctz(T n)
   {
   for(u32bit i = 0; i != 8*sizeof(T); ++i)
      if((n >> i) & 0x01)
         return i;
   return 8*sizeof(T);
   }

}

#endif
