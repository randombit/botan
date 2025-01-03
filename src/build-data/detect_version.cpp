/*
* This file is preprocessed to produce output that is examined by
* configure.py to determine the compilers version number.
*/

#if defined(_MSC_VER)

/*
   _MSC_VER Defined as an integer literal that encodes the major and
   minor number elements of the compiler's version number. The major
   number is the first element of the period-delimited version number
   and the minor number is the second element. For example, if the
   version number of the Visual C++ compiler is 17.00.51106.1, the
   _MSC_VER macro evaluates to 1700.
   https://msdn.microsoft.com/en-us/library/b0084kay.aspx
   */
MSVC _MSC_VER

#elif defined(__open_xl__)

XLC __open_xl_version__ __open_xl_release__

#elif defined(__EMSCRIPTEN__)

   #if __has_include(<emscripten/version.h>)
      #include <emscripten/version.h>
   #endif
EMCC __EMSCRIPTEN_major__ __EMSCRIPTEN_minor__

#elif defined(__clang__) && defined(__apple_build_version__)

/*
* Even __apple_build_version__ doesn't always get updated to reflect
* the XCode version, eg XCode 15.4 and XCode 15.3 both define
* __apple_build_version__ to 15000309
*/

   #if __apple_build_version__ >= 16000000
XCODE 16 0
   #elif __apple_build_version__ >= 15000300
XCODE 15 3
   #elif __apple_build_version__ >= 15000000
XCODE 15 0
   #else
/* Some older version that we don't support */
XCODE 0 0
   #endif

#elif defined(__clang__)

CLANG __clang_major__ __clang_minor__

#elif defined(__GNUG__)

GCC __GNUC__ __GNUC_MINOR__

#else

UNKNOWN 0 0

#endif
