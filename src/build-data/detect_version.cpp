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

#elif defined(__ibmxl__)

   XLC __ibmxl_version__ __ibmxl_release__

#elif defined(__EMSCRIPTEN__)

   EMCC __EMSCRIPTEN_major__ __EMSCRIPTEN_minor__

#elif defined(__clang__) && defined(__apple_build_version__)

   /*
   Apple's Clang is a long-term fork of Clang and the version of XCode
   has no correspondence with a specific LLVM Clang version.

   This is a rough map from the XCode Clang to the upstream Clang
   versions. It is not correct, but is sufficient for our purposes.

   Wikipedia has a mapping table from Apple Clang version to underlying
   LLVM version: https://en.wikipedia.org/wiki/Xcode

   We omit any mapping logic for versions before XCode 13 since we no longer
   support those versions. The only reason to detect them is so we can tell that
   the version of Clang is too old and stop configuration immediately.
   */

   #if __clang_major__ < 13
      CLANG __clang_major__ 0
   #elif __clang_major__ == 13
      #if __clang_minor__ < 3
         CLANG 12 0
      #else
         CLANG 13 0
      #endif
   #elif __clang_major__ == 14
      #if __clang_minor__ < 3
         CLANG 14 0
      #else
         CLANG 15 0
      #endif
   #elif __clang_major__ >= 15
      CLANG 15 0
   #endif

#elif defined(__clang__)

   CLANG __clang_major__ __clang_minor__

#elif defined(__GNUG__)

   GCC __GNUC__ __GNUC_MINOR__

#else

   UNKNOWN 0 0

#endif
