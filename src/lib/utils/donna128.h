/*
* A minimal 128-bit integer type
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DONNA128_H_
#define BOTAN_DONNA128_H_

#include <botan/internal/ct_utils.h>
#include <botan/internal/mul128.h>
#include <concepts>

namespace Botan {

class donna128 final {
   public:
      constexpr explicit donna128(uint64_t l = 0, uint64_t h = 0) : m_lo(l), m_hi(h) {}

      template <typename T>
      constexpr friend donna128 operator>>(const donna128& x, T shift) {
         donna128 z = x;

         if(shift > 64) {
            z.m_lo = z.m_hi >> (shift - 64);
            z.m_hi = 0;
         } else if(shift == 64) {
            z.m_lo = z.m_hi;
            z.m_hi = 0;
         } else if(shift > 0) {
            const uint64_t carry = z.m_hi << static_cast<size_t>(64 - shift);
            z.m_hi >>= shift;
            z.m_lo >>= shift;
            z.m_lo |= carry;
         }

         return z;
      }

      template <typename T>
      constexpr friend donna128 operator<<(const donna128& x, T shift) {
         donna128 z = x;
         if(shift > 64) {
            z.m_hi = z.m_lo << (shift - 64);
            z.m_lo = 0;
         } else if(shift == 64) {
            z.m_hi = z.m_lo;
            z.m_lo = 0;
         } else if(shift > 0) {
            const uint64_t carry = z.m_lo >> static_cast<size_t>(64 - shift);
            z.m_lo = (z.m_lo << shift);
            z.m_hi = (z.m_hi << shift) | carry;
         }

         return z;
      }

      constexpr friend uint64_t operator&(const donna128& x, uint64_t mask) { return x.m_lo & mask; }

      constexpr uint64_t operator&=(uint64_t mask) {
         m_hi = 0;
         m_lo &= mask;
         return m_lo;
      }

      constexpr donna128& operator+=(const donna128& x) {
         m_lo += x.m_lo;
         m_hi += x.m_hi;

         const uint64_t carry = CT::Mask<uint64_t>::is_lt(m_lo, x.m_lo).if_set_return(1);
         m_hi += carry;
         return *this;
      }

      constexpr donna128& operator+=(uint64_t x) {
         m_lo += x;
         const uint64_t carry = CT::Mask<uint64_t>::is_lt(m_lo, x).if_set_return(1);
         m_hi += carry;
         return *this;
      }

      constexpr uint64_t lo() const { return m_lo; }

      constexpr uint64_t hi() const { return m_hi; }

      constexpr explicit operator uint64_t() const { return lo(); }

   private:
      uint64_t m_lo = 0;
      uint64_t m_hi = 0;
};

template <std::integral T>
constexpr inline donna128 operator*(const donna128& x, T y) {
   BOTAN_ARG_CHECK(x.hi() == 0, "High 64 bits of donna128 set to zero during multiply");

   uint64_t lo = 0, hi = 0;
   mul64x64_128(x.lo(), static_cast<uint64_t>(y), &lo, &hi);
   return donna128(lo, hi);
}

template <std::integral T>
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
