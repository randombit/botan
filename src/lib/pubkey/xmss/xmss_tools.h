/*
 * XMSS Tools
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#ifndef BOTAN_XMSS_TOOLS_H_
#define BOTAN_XMSS_TOOLS_H_

#include <botan/secmem.h>
#include <algorithm>
#include <bit>
#include <concepts>
#include <iterator>

namespace Botan {

/**
* Concatenates the byte representation in big-endian order of any
* integral value to a secure_vector.
*
* @param target Vector to concatenate the byte representation of the
*               integral value to.
* @param src integral value to concatenate.
**/
template <std::unsigned_integral T>
void xmss_concat(secure_vector<uint8_t>& target, const T& src) {
   const uint8_t* src_bytes = reinterpret_cast<const uint8_t*>(&src);
   if constexpr(std::endian::native == std::endian::little) {
      std::reverse_copy(src_bytes, src_bytes + sizeof(src), std::back_inserter(target));
   } else {
      std::copy(src_bytes, src_bytes + sizeof(src), std::back_inserter(target));
   }
}

/**
* Concatenates the last n bytes of the byte representation in big-endian
* order of any integral value to a to a secure_vector.
*
* @param target Vector to concatenate the byte representation of the
*               integral value to.
* @param src Integral value to concatenate.
* @param len number of bytes to concatenate. This value must be smaller
*            or equal to the size of type T.
**/
template <std::unsigned_integral T>
void xmss_concat(secure_vector<uint8_t>& target, const T& src, size_t len) {
   const size_t c = static_cast<size_t>(std::min(len, sizeof(src)));
   if(len > sizeof(src)) {
      target.resize(target.size() + len - sizeof(src), 0);
   }

   const uint8_t* src_bytes = reinterpret_cast<const uint8_t*>(&src);
   if constexpr(std::endian::native == std::endian::little) {
      std::reverse_copy(src_bytes, src_bytes + c, std::back_inserter(target));
   } else {
      std::copy(src_bytes + sizeof(src) - c, src_bytes + sizeof(src), std::back_inserter(target));
   }
}

}  // namespace Botan

#endif
