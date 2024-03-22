/*
* Safe(r) Integer Handling
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_SAFE_INT_H_
#define BOTAN_UTILS_SAFE_INT_H_

#include <botan/concepts.h>
#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <optional>
#include <string_view>

#if defined(_MSC_VER)
   #include <intsafe.h>
#endif

namespace Botan {

class Integer_Overflow_Detected final : public Exception {
   public:
      Integer_Overflow_Detected(std::string_view file, int line) :
            Exception(fmt("Integer overflow detected at {}:{}", file, line)) {}

      ErrorType error_type() const noexcept override { return ErrorType::InternalError; }
};

inline size_t checked_add(size_t x, size_t y, const char* file, int line) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_add_overflow)
   size_t z;
   if(__builtin_add_overflow(x, y, &z)) [[unlikely]]
#elif defined(_MSC_VER)
   size_t z;
   if(SizeTAdd(x, y, &z) != S_OK) [[unlikely]]
#else
   size_t z = x + y;
   if(z < x) [[unlikely]]
#endif
   {
      throw Integer_Overflow_Detected(file, line);
   }
   return z;
}

inline std::optional<size_t> checked_mul(size_t x, size_t y) {
#if BOTAN_COMPILER_HAS_BUILTIN(__builtin_add_overflow)
   size_t z;
   if(__builtin_mul_overflow(x, y, &z)) [[unlikely]]
#elif defined(_MSC_VER)
   size_t z;
   if(SizeTMult(x, y, &z) != S_OK) [[unlikely]]
#else
   size_t z = x * y;
   if(y && z / y != x) [[unlikely]]
#endif
   {
      return std::nullopt;
   }
   return z;
}

namespace detail {

template <typename T>
concept int_or_strong_type = std::integral<T> || concepts::integral_strong_type<T>;

template <int_or_strong_type T>
struct unwrap_type {};

template <int_or_strong_type T>
   requires std::integral<T>
struct unwrap_type<T> {
      using type = T;
};

template <int_or_strong_type T>
   requires concepts::integral_strong_type<T>
struct unwrap_type<T> {
      using type = typename T::wrapped_type;
};

template <int_or_strong_type T>
using unwrap_type_t = typename unwrap_type<T>::type;

template <int_or_strong_type T>
constexpr auto unwrap(T t) -> unwrap_type_t<T> {
   if constexpr(std::integral<T>) {
      return t;
   } else {
      return t.get();
   }
}

template <int_or_strong_type T>
constexpr auto wrap(unwrap_type_t<T> t) -> T {
   if constexpr(std::integral<T>) {
      return t;
   } else {
      return T(t);
   }
}

}  // namespace detail

template <detail::int_or_strong_type RT, typename ExceptionType, detail::int_or_strong_type AT>
constexpr RT checked_cast_to_or_throw(AT i, std::string_view error_msg_on_fail) {
   const auto unwrapped_input = detail::unwrap(i);
   using unwrapped_input_type = detail::unwrap_type_t<AT>;
   using unwrapped_result_type = detail::unwrap_type_t<RT>;

   const auto unwrapped_result = static_cast<unwrapped_result_type>(unwrapped_input);
   if(unwrapped_input != static_cast<unwrapped_input_type>(unwrapped_result)) [[unlikely]] {
      throw ExceptionType(error_msg_on_fail);
   }

   return detail::wrap<RT>(unwrapped_result);
}

template <detail::int_or_strong_type RT, detail::int_or_strong_type AT>
constexpr RT checked_cast_to(AT i) {
   return checked_cast_to_or_throw<RT, Internal_Error>(i, "Error during integer conversion");
}

#define BOTAN_CHECKED_ADD(x, y) checked_add(x, y, __FILE__, __LINE__)
#define BOTAN_CHECKED_MUL(x, y) checked_mul(x, y)

}  // namespace Botan

#endif
