/*
* Functions for constant time operations on data and testing of
* constant time annotations using valgrind.
*
* For more information about constant time programming see
* Wagner, Molnar, et al "The Program Counter Security Model"
*
* (C) 2010 Falko Strenzke
* (C) 2015,2016,2018,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_CT_UTILS_H_
#define BOTAN_CT_UTILS_H_

#include <botan/secmem.h>
#include <botan/internal/bit_ops.h>
#include <type_traits>
#include <vector>

#if defined(BOTAN_HAS_VALGRIND)
   #include <valgrind/memcheck.h>
#endif

namespace Botan::CT {

/**
* Use valgrind to mark the contents of memory as being undefined.
* Valgrind will accept operations which manipulate undefined values,
* but will warn if an undefined value is used to decided a conditional
* jump or a load/store address. So if we poison all of our inputs we
* can confirm that the operations in question are truly const time
* when compiled by whatever compiler is in use.
*
* Even better, the VALGRIND_MAKE_MEM_* macros work even when the
* program is not run under valgrind (though with a few cycles of
* overhead, which is unfortunate in final binaries as these
* annotations tend to be used in fairly important loops).
*
* This approach was first used in ctgrind (https://github.com/agl/ctgrind)
* but calling the valgrind mecheck API directly works just as well and
* doesn't require a custom patched valgrind.
*/
template <typename T>
constexpr inline void poison(const T* p, size_t n) {
#if defined(BOTAN_HAS_VALGRIND)
   if(!std::is_constant_evaluated()) {
      VALGRIND_MAKE_MEM_UNDEFINED(p, n * sizeof(T));
   }
#endif

   BOTAN_UNUSED(p, n);
}

template <typename T>
constexpr inline void unpoison(const T* p, size_t n) {
#if defined(BOTAN_HAS_VALGRIND)
   if(!std::is_constant_evaluated()) {
      VALGRIND_MAKE_MEM_DEFINED(p, n * sizeof(T));
   }
#endif

   BOTAN_UNUSED(p, n);
}

template <typename T>
constexpr inline void unpoison(T& p) {
#if defined(BOTAN_HAS_VALGRIND)
   if(!std::is_constant_evaluated()) {
      VALGRIND_MAKE_MEM_DEFINED(&p, sizeof(T));
   }
#endif

   BOTAN_UNUSED(p);
}

/**
* This function returns its argument, but (if called in a non-constexpr context)
* attempts to prevent the compiler from reasoning about the value or the possible
* range of values. Such optimizations have a way of breaking constant time code.
*/
template <typename T>
constexpr inline T value_barrier(T x) {
   if(!std::is_constant_evaluated()) {
      /*
      * For compilers without inline asm, is there something else we can do?
      *
      * For instance we could potentially launder the value through a
      * `volatile T` or `volatile T*`. This would require some experimentation.
      *
      * GCC has an attribute noipa which disables interprocedural analysis, which
      * might be useful here. However Clang does not currently support this attribute.
      *
      * We may want a "stronger" statement such as
      *     asm volatile("" : "+r,m"(x) : : "memory);
      * (see https://theunixzoo.co.uk/blog/2021-10-14-preventing-optimisations.html)
      * however the current approach seems sufficient with current compilers,
      * and is minimally damaging with regards to degrading code generation.
      */
#if defined(BOTAN_USE_GCC_INLINE_ASM)
      asm("" : "+r"(x) : /* no input */);
#endif
      return x;
   } else {
      return x;
   }
}

/**
* A Choice is used for constant-time conditionals.
*
* Internally it always is either |0| (all 0 bits) or |1| (all 1 bits)
* and measures are taken to block compilers from reasoning about the
* expected value of a Choice.
*/
class Choice final {
   public:
      /**
      * If v == 0 return an unset (false) Choice, otherwise a set Choice
      */
      template <typename T>
         requires std::unsigned_integral<T> && (!std::same_as<bool, T>)
      constexpr static Choice from_int(T v) {
         // Mask of T that is either |0| or |1|
         const T v_is_0 = ct_is_zero<T>(value_barrier<T>(v));

         // We want the mask to be set if v != 0 so we must check that
         // v_is_0 is itself zero.
         //
         // Also sizeof(T) may not equal sizeof(uint32_t) so we must
         // use ct_is_zero<uint32_t>. It's ok to either truncate or
         // zero extend v_is_0 to 32 bits since we know it is |0| or |1|
         // so even just the low bit is sufficient.
         return Choice(ct_is_zero<uint32_t>(static_cast<uint32_t>(v_is_0)));
      }

      constexpr static Choice yes() { return Choice(static_cast<uint32_t>(-1)); }

      constexpr static Choice no() { return Choice(0); }

      constexpr Choice operator!() const { return Choice(~value()); }

      constexpr Choice operator&&(const Choice& other) const { return Choice(value() & other.value()); }

      constexpr Choice operator||(const Choice& other) const { return Choice(value() | other.value()); }

      constexpr Choice operator!=(const Choice& other) const { return Choice(value() ^ other.value()); }

      /**
      * Unsafe conversion to bool
      *
      * This conversion itself is (probably) constant time, but once the
      * choice is reduced to a simple bool, it's entirely possible for the
      * compiler to perform range analysis on the values, since there are just
      * the two. As a consequence even if the caller is not using this in an
      * obviously branchy way (`if(choice.as_bool()) ...`) a smart compiler
      * may introduce branches depending on the value.
      */
      constexpr bool as_bool() const { return m_value != 0; }

      /// Return the masked value
      constexpr uint32_t value() const { return value_barrier(m_value); }

      constexpr Choice(const Choice& other) = default;
      constexpr Choice(Choice&& other) = default;
      constexpr Choice& operator=(const Choice& other) noexcept = default;
      constexpr Choice& operator=(Choice&& other) noexcept = default;

   private:
      constexpr explicit Choice(uint32_t v) : m_value(v) {}

      uint32_t m_value;
};

/**
* A Mask type used for constant-time operations. A Mask<T> always has value
* either |0| (all bits cleared) or |1| (all bits set). All operations in a Mask<T>
* are intended to compile to code which does not contain conditional jumps.
* This must be verified with tooling (eg binary disassembly or using valgrind)
* since you never know what a compiler might do.
*/
template <typename T>
class Mask final {
   public:
      static_assert(std::is_unsigned<T>::value && !std::is_same<bool, T>::value,
                    "Only unsigned integer types are supported by CT::Mask");

      Mask(const Mask<T>& other) = default;
      Mask<T>& operator=(const Mask<T>& other) = default;

      /**
      * Derive a Mask from a Mask of a larger type
      */
      template <typename U>
      constexpr Mask(Mask<U> o) : m_mask(static_cast<T>(o.value())) {
         static_assert(sizeof(U) > sizeof(T), "sizes ok");
      }

      /**
      * Return a Mask<T> of |1| (all bits set)
      */
      static constexpr Mask<T> set() { return Mask<T>(static_cast<T>(~0)); }

      /**
      * Return a Mask<T> of |0| (all bits cleared)
      */
      static constexpr Mask<T> cleared() { return Mask<T>(0); }

      /**
      * Return a Mask<T> which is set if v is != 0
      */
      static constexpr Mask<T> expand(T v) { return ~Mask<T>::is_zero(value_barrier<T>(v)); }

      /**
      * Return a Mask<T> which is set if choice is set
      */
      static constexpr Mask<T> from_choice(Choice c) {
         if constexpr(sizeof(T) <= sizeof(uint32_t)) {
            // Take advantage of the fact that Choice's mask is always
            // either |0| or |1|
            return Mask<T>(static_cast<T>(c.value()));
         } else {
            return ~Mask<T>::is_zero(c.value());
         }
      }

      /**
      * Return a Mask<T> which is set if the top bit of v is set
      */
      static constexpr Mask<T> expand_top_bit(T v) { return Mask<T>(Botan::expand_top_bit<T>(value_barrier<T>(v))); }

      /**
      * Return a Mask<T> which is set if m is set
      */
      template <typename U>
      static constexpr Mask<T> expand(Mask<U> m) {
         static_assert(sizeof(U) < sizeof(T), "sizes ok");
         return ~Mask<T>::is_zero(m.value());
      }

      /**
      * Return a Mask<T> which is set if v is == 0 or cleared otherwise
      */
      static constexpr Mask<T> is_zero(T x) { return Mask<T>(ct_is_zero<T>(value_barrier<T>(x))); }

      /**
      * Return a Mask<T> which is set if x == y
      */
      static constexpr Mask<T> is_equal(T x, T y) {
         const T diff = value_barrier(x) ^ value_barrier(y);
         return Mask<T>::is_zero(diff);
      }

      /**
      * Return a Mask<T> which is set if x < y
      */
      static constexpr Mask<T> is_lt(T x, T y) {
         T u = x ^ ((x ^ y) | ((x - y) ^ x));
         return Mask<T>::expand_top_bit(u);
      }

      /**
      * Return a Mask<T> which is set if x > y
      */
      static constexpr Mask<T> is_gt(T x, T y) { return Mask<T>::is_lt(y, x); }

      /**
      * Return a Mask<T> which is set if x <= y
      */
      static constexpr Mask<T> is_lte(T x, T y) { return ~Mask<T>::is_gt(x, y); }

      /**
      * Return a Mask<T> which is set if x >= y
      */
      static constexpr Mask<T> is_gte(T x, T y) { return ~Mask<T>::is_lt(x, y); }

      static constexpr Mask<T> is_within_range(T v, T l, T u) {
         //return Mask<T>::is_gte(v, l) & Mask<T>::is_lte(v, u);

         const T v_lt_l = v ^ ((v ^ l) | ((v - l) ^ v));
         const T v_gt_u = u ^ ((u ^ v) | ((u - v) ^ u));
         const T either = value_barrier(v_lt_l) | value_barrier(v_gt_u);
         return ~Mask<T>::expand_top_bit(either);
      }

      static constexpr Mask<T> is_any_of(T v, std::initializer_list<T> accepted) {
         T accept = 0;

         for(auto a : accepted) {
            const T diff = a ^ v;
            const T eq_zero = value_barrier<T>(~diff & (diff - 1));
            accept |= eq_zero;
         }

         return Mask<T>::expand_top_bit(accept);
      }

      /**
      * AND-combine two masks
      */
      Mask<T>& operator&=(Mask<T> o) {
         m_mask &= o.value();
         return (*this);
      }

      /**
      * XOR-combine two masks
      */
      Mask<T>& operator^=(Mask<T> o) {
         m_mask ^= o.value();
         return (*this);
      }

      /**
      * OR-combine two masks
      */
      Mask<T>& operator|=(Mask<T> o) {
         m_mask |= o.value();
         return (*this);
      }

      /**
      * AND-combine two masks
      */
      friend Mask<T> operator&(Mask<T> x, Mask<T> y) { return Mask<T>(x.value() & y.value()); }

      /**
      * XOR-combine two masks
      */
      friend Mask<T> operator^(Mask<T> x, Mask<T> y) { return Mask<T>(x.value() ^ y.value()); }

      /**
      * OR-combine two masks
      */
      friend Mask<T> operator|(Mask<T> x, Mask<T> y) { return Mask<T>(x.value() | y.value()); }

      /**
      * Negate this mask
      */
      constexpr Mask<T> operator~() const { return Mask<T>(~value()); }

      /**
      * Return x if the mask is set, or otherwise zero
      */
      constexpr T if_set_return(T x) const { return value() & x; }

      /**
      * Return x if the mask is cleared, or otherwise zero
      */
      constexpr T if_not_set_return(T x) const { return ~value() & x; }

      /**
      * If this mask is set, return x, otherwise return y
      */
      constexpr T select(T x, T y) const { return choose(value(), x, y); }

      constexpr T select_and_unpoison(T x, T y) const {
         T r = this->select(x, y);
         CT::unpoison(r);
         return r;
      }

      /**
      * If this mask is set, return x, otherwise return y
      */
      Mask<T> select_mask(Mask<T> x, Mask<T> y) const { return Mask<T>(select(x.value(), y.value())); }

      /**
      * Conditionally set output to x or y, depending on if mask is set or
      * cleared (resp)
      */
      constexpr void select_n(T output[], const T x[], const T y[], size_t len) const {
         for(size_t i = 0; i != len; ++i) {
            output[i] = this->select(x[i], y[i]);
         }
      }

      /**
      * If this mask is set, zero out buf, otherwise do nothing
      */
      constexpr void if_set_zero_out(T buf[], size_t elems) {
         for(size_t i = 0; i != elems; ++i) {
            buf[i] = this->if_not_set_return(buf[i]);
         }
      }

      /**
      * Return the value of the mask, unpoisoned
      */
      constexpr T unpoisoned_value() const {
         T r = value();
         CT::unpoison(r);
         return r;
      }

      /**
      * Unsafe conversion to bool
      *
      * This conversion itself is (probably) constant time, but once the
      * mask is reduced to a simple bool, it's entirely possible for the
      * compiler to perform range analysis on the values, since there are just
      * the two. As a consequence even if the caller is not using this in an
      * obviously branchy way (`if(mask.as_bool()) ...`) a smart compiler
      * may introduce branches depending on the value.
      */
      constexpr bool as_bool() const { return unpoisoned_value() != 0; }

      /**
      * Return a Choice based on this mask
      */
      constexpr CT::Choice as_choice() const { return CT::Choice::from_int(unpoisoned_value()); }

      /**
      * Return the underlying value of the mask
      */
      constexpr T value() const { return value_barrier<T>(m_mask); }

   private:
      constexpr Mask(T m) : m_mask(m) {}

      T m_mask;
};

template <typename T>
constexpr inline Mask<T> conditional_copy_mem(Mask<T> mask, T* to, const T* from0, const T* from1, size_t elems) {
   mask.select_n(to, from0, from1, elems);
   return mask;
}

template <typename T>
constexpr inline Mask<T> conditional_copy_mem(T cnd, T* to, const T* from0, const T* from1, size_t elems) {
   const auto mask = CT::Mask<T>::expand(cnd);
   return CT::conditional_copy_mem(mask, to, from0, from1, elems);
}

template <typename T>
constexpr inline Mask<T> conditional_assign_mem(T cnd, T* sink, const T* src, size_t elems) {
   const auto mask = CT::Mask<T>::expand(cnd);
   mask.select_n(sink, src, sink, elems);
   return mask;
}

template <typename T>
constexpr inline Mask<T> conditional_assign_mem(Choice cnd, T* sink, const T* src, size_t elems) {
   const auto mask = CT::Mask<T>::from_choice(cnd);
   mask.select_n(sink, src, sink, elems);
   return mask;
}

template <typename T>
constexpr inline void conditional_swap(bool cnd, T& x, T& y) {
   const auto swap = CT::Mask<T>::expand(cnd);

   T t0 = swap.select(y, x);
   T t1 = swap.select(x, y);
   x = t0;
   y = t1;
}

template <typename T>
constexpr inline void conditional_swap_ptr(bool cnd, T& x, T& y) {
   uintptr_t xp = reinterpret_cast<uintptr_t>(x);
   uintptr_t yp = reinterpret_cast<uintptr_t>(y);

   conditional_swap<uintptr_t>(cnd, xp, yp);

   x = reinterpret_cast<T>(xp);
   y = reinterpret_cast<T>(yp);
}

template <typename T>
constexpr inline CT::Mask<T> all_zeros(const T elem[], size_t len) {
   T sum = 0;
   for(size_t i = 0; i != len; ++i) {
      sum |= elem[i];
   }
   return CT::Mask<T>::is_zero(sum);
}

/**
* Compare two arrays of equal size and return a Mask indicating if
* they are equal or not. The mask is set if they are identical.
*/
template <typename T>
constexpr inline CT::Mask<T> is_equal(const T x[], const T y[], size_t len) {
   if(std::is_constant_evaluated()) {
      T difference = 0;

      for(size_t i = 0; i != len; ++i) {
         difference = difference | (x[i] ^ y[i]);
      }

      return CT::Mask<T>::is_zero(difference);
   } else {
      volatile T difference = 0;

      for(size_t i = 0; i != len; ++i) {
         difference = difference | (x[i] ^ y[i]);
      }

      return CT::Mask<T>::is_zero(difference);
   }
}

/**
* Compare two arrays of equal size and return a Mask indicating if
* they are equal or not. The mask is set if they differ.
*/
template <typename T>
constexpr inline CT::Mask<T> is_not_equal(const T x[], const T y[], size_t len) {
   return ~CT::is_equal(x, y, len);
}

/**
* If bad_input is unset, return input[offset:input_length] copied to new
* buffer. If bad_input is set, return an empty vector. In all cases, the capacity
* of the vector is equal to input_length
*
* This function attempts to avoid leaking the following:
*  - if bad_input was set or not
*  - the value of offset
*  - the values in input[]
*
* This function leaks the value of input_length
*/
BOTAN_TEST_API
secure_vector<uint8_t> copy_output(CT::Mask<uint8_t> bad_input,
                                   const uint8_t input[],
                                   size_t input_length,
                                   size_t offset);

secure_vector<uint8_t> strip_leading_zeros(const uint8_t in[], size_t length);

inline secure_vector<uint8_t> strip_leading_zeros(const secure_vector<uint8_t>& in) {
   return strip_leading_zeros(in.data(), in.size());
}

}  // namespace Botan::CT

#endif
