/*
* Safe(r) Integer Handling
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_SAFE_INT_H_
#define BOTAN_UTILS_SAFE_INT_H_

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

template <typename RT, typename AT>
RT checked_cast_to(AT i) {
   RT c = static_cast<RT>(i);
   if(i != static_cast<AT>(c)) {
      throw Internal_Error("Error during integer conversion");
   }
   return c;
}

#define BOTAN_CHECKED_ADD(x, y) checked_add(x, y, __FILE__, __LINE__)
#define BOTAN_CHECKED_MUL(x, y) checked_mul(x, y)

}  // namespace Botan

#endif
