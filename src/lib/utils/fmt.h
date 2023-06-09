/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTIL_FMT_H_
#define BOTAN_UTIL_FMT_H_

#include <botan/types.h>
#include <locale>
#include <sstream>
#include <string>
#include <string_view>

namespace Botan {

namespace fmt_detail {

inline void do_fmt(std::ostringstream& oss, std::string_view format) {
   oss << format;
}

template <typename T, typename... Ts>
void do_fmt(std::ostringstream& oss, std::string_view format, const T& val, const Ts&... rest) {
   size_t i = 0;

   while(i < format.size()) {
      if(format[i] == '{' && (format.size() > (i + 1)) && format.at(i + 1) == '}') {
         oss << val;
         return do_fmt(oss, format.substr(i + 2), rest...);
      } else {
         oss << format[i];
      }

      i += 1;
   }
}

}  // namespace fmt_detail

/**
* Simple formatter utility.
*
* Should be replaced with std::format once that's available on all our
* supported compilers.
*
* '{}' markers in the format string are replaced by the arguments.
* Unlike std::format, there is no support for escaping or for any kind
* of conversion flags.
*/
template <typename... T>
std::string fmt(std::string_view format, const T&... args) {
   std::ostringstream oss;
   oss.imbue(std::locale::classic());
   fmt_detail::do_fmt(oss, format, args...);
   return oss.str();
}

}  // namespace Botan

#endif
