/*
* A minimal 128-bit integer type for curve25519-donna
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CURVE25519_DONNA128_H__
#define BOTAN_CURVE25519_DONNA128_H__

#include <botan/mul128.h>

namespace Botan {

class donna128
   {
   public:
      donna128(u64bit ll = 0, u64bit hh = 0) { l = ll; h = hh; }

      donna128(const donna128&) = default;
      donna128& operator=(const donna128&) = default;

      friend donna128 operator>>(const donna128& x, size_t shift)
         {
         donna128 z = x;
         const u64bit carry = z.h << (64 - shift);
         z.h = (z.h >> shift);
         z.l = (z.l >> shift) | carry;
         return z;
         }

      friend donna128 operator<<(const donna128& x, size_t shift)
         {
         donna128 z = x;
         const u64bit carry = z.l >> (64 - shift);
         z.l = (z.l << shift);
         z.h = (z.h << shift) | carry;
         return z;
         }

      friend u64bit operator&(const donna128& x, u64bit mask)
         {
         return x.l & mask;
         }

      u64bit operator&=(u64bit mask)
         {
         h = 0;
         l &= mask;
         return l;
         }

      donna128& operator+=(const donna128& x)
         {
         l += x.l;
         h += (l < x.l);
         h += x.h;
         return *this;
         }

      donna128& operator+=(u64bit x)
         {
         l += x;
         h += (l < x);
         return *this;
         }

      u64bit lo() const { return l; }
      u64bit hi() const { return h; }
   private:
      u64bit h = 0, l = 0;
   };

inline donna128 operator*(const donna128& x, u64bit y)
   {
   BOTAN_ASSERT(x.hi() == 0, "High 64 bits of donna128 set to zero during multiply");

   u64bit lo = 0, hi = 0;
   mul64x64_128(x.lo(), y, &lo, &hi);
   return donna128(lo, hi);
   }

inline donna128 operator+(const donna128& x, const donna128& y)
   {
   donna128 z = x;
   z += y;
   return z;
   }

inline donna128 operator+(const donna128& x, u64bit y)
   {
   donna128 z = x;
   z += y;
   return z;
   }

inline donna128 operator|(const donna128& x, const donna128& y)
   {
   return donna128(x.lo() | y.lo(), x.hi() | y.hi());
   }

inline u64bit carry_shift(const donna128& a, size_t shift)
   {
   return (a >> shift).lo();
   }

inline u64bit combine_lower(const donna128 a, size_t s1,
                            const donna128 b, size_t s2)
   {
   donna128 z = (a >> s1) | (b << s2);
   return z.lo();
   }

}

#endif
