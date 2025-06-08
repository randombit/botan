/*
* A minimal 128-bit integer type for curve25519-donna
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CURVE25519_DONNA128_H_
#define BOTAN_CURVE25519_DONNA128_H_

#include <botan/internal/ct_utils.h>
#include <botan/internal/mul128.h>
#include <type_traits>

namespace Botan {

class donna128 final {
   public:
      constexpr donna128(uint64_t ll = 0, uint64_t hh = 0) {
         l = ll;
         h = hh;
      }

      donna128(const donna128&) = default;
      donna128& operator=(const donna128&) = default;

      template <typename T>
      constexpr friend donna128 operator>>(const donna128& x, T shift) {
         donna128 z = x;

         if(shift > 64) {
            z.l = z.h >> (shift - 64);
            z.h = 0;
         } else if(shift == 64) {
            z.l = z.h;
            z.h = 0;
         } else if(shift > 0) {
            const uint64_t carry = z.h << static_cast<size_t>(64 - shift);
            z.h >>= shift;
            z.l >>= shift;
            z.l |= carry;
         }

         return z;
      }

      template <typename T>
      constexpr friend donna128 operator<<(const donna128& x, T shift) {
         donna128 z = x;
         if(shift > 64) {
            z.h = z.l << (shift - 64);
            z.l = 0;
         } else if(shift == 64) {
            z.h = z.l;
            z.l = 0;
         } else if(shift > 0) {
            const uint64_t carry = z.l >> static_cast<size_t>(64 - shift);
            z.l = (z.l << shift);
            z.h = (z.h << shift) | carry;
         }

         return z;
      }

      constexpr friend uint64_t operator&(const donna128& x, uint64_t mask) { return x.l & mask; }

      constexpr uint64_t operator&=(uint64_t mask) {
         h = 0;
         l &= mask;
         return l;
      }

      constexpr donna128& operator+=(const donna128& x) {
         l += x.l;
         h += x.h;

         const uint64_t carry = CT::Mask<uint64_t>::is_lt(l, x.l).if_set_return(1);
         h += carry;
         return *this;
      }

      constexpr donna128& operator+=(uint64_t x) {
         l += x;
         const uint64_t carry = CT::Mask<uint64_t>::is_lt(l, x).if_set_return(1);
         h += carry;
         return *this;
      }

      constexpr uint64_t lo() const { return l; }

      constexpr uint64_t hi() const { return h; }

      constexpr operator uint64_t() const { return l; }

   private:
      uint64_t h = 0, l = 0;
};

template <std::unsigned_integral T>
constexpr inline donna128 operator*(const donna128& x, T y) {
   BOTAN_ARG_CHECK(x.hi() == 0, "High 64 bits of donna128 set to zero during multiply");

   uint64_t lo = 0, hi = 0;
   mul64x64_128(x.lo(), static_cast<uint64_t>(y), &lo, &hi);
   return donna128(lo, hi);
}

template <std::unsigned_integral T>
constexpr inline donna128 operator*(T y, const donna128& x) {
   return x * y;
}

constexpr inline donna128 operator+(const donna128& x, const donna128& y) {
   donna128 z = x;
   z += y;
   return z;
}

constexpr inline donna128 operator+(const donna128& x, uint64_t y) {
   donna128 z = x;
   z += y;
   return z;
}

constexpr inline donna128 operator|(const donna128& x, const donna128& y) {
   return donna128(x.lo() | y.lo(), x.hi() | y.hi());
}

constexpr inline donna128 operator|(const donna128& x, uint64_t y) {
   return donna128(x.lo() | y, x.hi());
}

constexpr inline uint64_t carry_shift(const donna128& a, size_t shift) {
   return (a >> shift).lo();
}

constexpr inline uint64_t combine_lower(const donna128& a, size_t s1, const donna128& b, size_t s2) {
   donna128 z = (a >> s1) | (b << s2);
   return z.lo();
}

#if defined(BOTAN_TARGET_HAS_NATIVE_UINT128)
inline uint64_t carry_shift(const uint128_t a, size_t shift) {
   return static_cast<uint64_t>(a >> shift);
}

inline uint64_t combine_lower(const uint128_t a, size_t s1, const uint128_t b, size_t s2) {
   return static_cast<uint64_t>((a >> s1) | (b << s2));
}
#endif

}  // namespace Botan

#endif
