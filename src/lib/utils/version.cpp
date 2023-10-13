/*
* Version Information
* (C) 1999-2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/version.h>

#include <botan/internal/fmt.h>

namespace Botan {

/*
  These are intentionally compiled rather than inlined, so an
  application running against a shared library can test the true
  version they are running against.
*/

// NOLINTNEXTLINE(*-macro-usage)
#define QUOTE(name) #name
// NOLINTNEXTLINE(*-macro-usage)
#define STR(macro) QUOTE(macro)

const char* short_version_cstr() {
   return STR(BOTAN_VERSION_MAJOR) "." STR(BOTAN_VERSION_MINOR) "." STR(BOTAN_VERSION_PATCH)
#if defined(BOTAN_VERSION_SUFFIX)
      STR(BOTAN_VERSION_SUFFIX)
#endif
         ;
}

const char* version_cstr() {
   /*
   It is intentional that this string is a compile-time constant;
   it makes it much easier to find in binaries.
   */

   return "Botan " STR(BOTAN_VERSION_MAJOR) "." STR(BOTAN_VERSION_MINOR) "." STR(BOTAN_VERSION_PATCH)
#if defined(BOTAN_VERSION_SUFFIX)
      STR(BOTAN_VERSION_SUFFIX)
#endif
         " ("
#if defined(BOTAN_UNSAFE_FUZZER_MODE) || defined(BOTAN_TERMINATE_ON_ASSERTS)
         "UNSAFE "
   #if defined(BOTAN_UNSAFE_FUZZER_MODE)
         "FUZZER MODE "
   #endif
   #if defined(BOTAN_TERMINATE_ON_ASSERTS)
         "TERMINATE ON ASSERTS "
   #endif
         "BUILD "
#endif
      BOTAN_VERSION_RELEASE_TYPE
#if(BOTAN_VERSION_DATESTAMP != 0)
         ", dated " STR(BOTAN_VERSION_DATESTAMP)
#endif
            ", revision " BOTAN_VERSION_VC_REVISION ", distribution " BOTAN_DISTRIBUTION_INFO ")";
}

#undef STR
#undef QUOTE

/*
* Return the version as a string
*/
std::string version_string() {
   return std::string(version_cstr());
}

std::string short_version_string() {
   return std::string(short_version_cstr());
}

uint32_t version_datestamp() {
   return BOTAN_VERSION_DATESTAMP;
}

/*
* Return parts of the version as integers
*/
uint32_t version_major() {
   return BOTAN_VERSION_MAJOR;
}

uint32_t version_minor() {
   return BOTAN_VERSION_MINOR;
}

uint32_t version_patch() {
   return BOTAN_VERSION_PATCH;
}

std::string runtime_version_check(uint32_t major, uint32_t minor, uint32_t patch) {
   if(major != version_major() || minor != version_minor() || patch != version_patch()) {
      return fmt("Warning: linked version ({}) does not match version built against ({}.{}.{})\n",
                 short_version_cstr(),
                 major,
                 minor,
                 patch);
   }

   return "";
}

}  // namespace Botan
