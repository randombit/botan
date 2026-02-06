/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MEM_UTILS_H_
#define BOTAN_MEM_UTILS_H_

#include <botan/types.h>
#include <concepts>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

namespace Botan {

/**
* Zeroize memory contents in a way that a compiler should not elide,
* using some system specific technique.
*
* Use this function to scrub memory just before deallocating it, or on
* a stack buffer before returning from the function.
*
* @param ptr a pointer to memory to scrub
* @param n the number of bytes pointed to by ptr
*/
BOTAN_TEST_API void secure_zeroize_buffer(void* ptr, size_t n);

/**
 * @param buf a pointer to the start of the region
 * @param n the number of elements in buf
 */
template <std::unsigned_integral T>
inline void zeroize_buffer(T buf[], size_t n) {
   if(n > 0) {
      std::memset(buf, 0, sizeof(T) * n);
   }
}

template <std::unsigned_integral T>
inline void unchecked_copy_memory(T* out, const T* in, size_t n) {
   if(in != nullptr && out != nullptr && n > 0) {
      std::memmove(out, in, sizeof(T) * n);
   }
}

/**
* Return true if any of the provided arguments are null
*/
template <typename... Ptrs>
bool any_null_pointers(Ptrs... ptr) {
   static_assert((... && std::is_pointer_v<Ptrs>), "All arguments must be pointers");
   return (... || (ptr == nullptr));
}

inline std::span<const uint8_t> as_span_of_bytes(const char* s, size_t len) {
   const uint8_t* b = reinterpret_cast<const uint8_t*>(s);
   return std::span{b, len};
}

inline std::span<const uint8_t> as_span_of_bytes(const std::string& s) {
   return as_span_of_bytes(s.data(), s.size());
}

inline std::span<const uint8_t> as_span_of_bytes(std::string_view s) {
   return as_span_of_bytes(s.data(), s.size());
}

inline std::span<const uint8_t> cstr_as_span_of_bytes(const char* s) {
   return as_span_of_bytes(s, std::strlen(s));
}

inline std::string bytes_to_string(std::span<const uint8_t> bytes) {
   return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

}  // namespace Botan

#endif
