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

#elif defined(__clang__) && defined(__apple_build_version__)

   /*
   Map Apple LLVM versions as used in XCode back to standard Clang.
   This is not exact since the versions used in XCode are actually
   forks of Clang and do not coorespond perfectly to standard Clang
   releases. In addition we don't bother mapping very old versions
   (anything before XCode 7 is treated like Clang 3.5, which is the
   oldest version we support) and for "future" versions we simply
   treat them as Clang 4.0, since we don't currenly rely on any
   features not included in 4.0
   */

   #if __clang_major__ >= 9
      CLANG 4 0
   #elif __clang_major__ == 8
      CLANG 3 9
   #elif __clang_major__ == 7 && __clang_minor__ == 3
      CLANG 3 8
   #elif __clang_major__ == 7
      CLANG 3 7
   #else
      CLANG 3 5
   #endif

#elif defined(__clang__)

   CLANG __clang_major__ __clang_minor__

#elif defined(__GNUG__)

   GCC __GNUC__ __GNUC_MINOR__

#else

   UNKNOWN 0 0

#endif
