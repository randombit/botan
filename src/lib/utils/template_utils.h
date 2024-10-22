/*
* STL Utility Functions
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEMPLATE_UTILS_H_
#define BOTAN_TEMPLATE_UTILS_H_

#include <algorithm>

namespace Botan {

/*
 * @brief Helper class to pass literal strings to C++ templates
 */
template <size_t N>
class StringLiteral {
   public:
      constexpr StringLiteral(const char (&str)[N]) { std::copy_n(str, N, value); }

      char value[N];  // NOLINT(misc-non-private-member-variables-in-classes)
};

}  // namespace Botan

#endif
