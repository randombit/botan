/*
* (C) 2025 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MEM_UTILS_H_
#define BOTAN_MEM_UTILS_H_

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace Botan {

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
