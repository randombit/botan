/*
* Runtime assertion checking
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ASSERTION_CHECKING_H__
#define BOTAN_ASSERTION_CHECKING_H__

namespace Botan {

void assertion_failure(const char* expr_str,
                       const char* msg,
                       const char* func,
                       const char* file,
                       int line);

#define BOTAN_ASSERT(expr, msg)                           \
   do {                                                   \
      if(!(expr))                                         \
         Botan::assertion_failure(#expr,                  \
                                  msg,                    \
                                  BOTAN_ASSERT_FUNCTION,  \
                                  __FILE__,               \
                                  __LINE__);              \
   } while(0)

#define BOTAN_ASSERT_EQUAL(value1, value2, msg)           \
   do {                                                   \
     if(value1 != value2)                                 \
         Botan::assertion_failure(#value1 " == " #value2, \
                                  msg,                    \
                                  BOTAN_ASSERT_FUNCTION,  \
                                  __FILE__,               \
                                  __LINE__);              \
   } while(0)

/*
* Unfortunately getting the function name from the preprocessor
* isn't standard in C++98 (C++0x uses C99's __func__)
*/
#if defined(BOTAN_BUILD_COMPILER_IS_GCC) || \
    defined(BOTAN_BUILD_COMPILER_IS_CLANG) || \
    defined(BOTAN_BUILD_COMPILER_IS_INTEL)

  #define BOTAN_ASSERT_FUNCTION __PRETTY_FUNCTION__

#elif defined(BOTAN_BUILD_COMPILER_IS_MSVC)

  #define BOTAN_ASSERT_FUNCTION __FUNCTION__

#else
  #define BOTAN_ASSERT_FUNCTION ((const char*)0)
#endif

}

#endif
