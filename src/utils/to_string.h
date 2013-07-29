/*
* to_string implementation for Android
* (C) 2013 Ilya Lyubimov
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_TO_STRING_H__
#define BOTAN_TO_STRING_H__

#include <string>

#ifdef __ANDROID__
#include <sstream>
#endif

namespace Botan {

template<typename T>
inline std::string to_string(T value)
   {
#ifdef __ANDROID__
   std::ostringstream stream;
   stream << value;
   return stream.str();
#else
   return std::to_string(value);
#endif
   }

}

#endif
