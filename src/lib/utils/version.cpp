/*
* Version Information
* (C) 1999-2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/version.h>
#include <botan/parsing.h>
#include <sstream>

namespace Botan {

/*
  These are intentionally compiled rather than inlined, so an
  application running against a shared library can test the true
  version they are running against.
*/

/*
* Return the version as a string
*/
std::string version_string()
   {
   return std::string(version_cstr());
   }

const char* version_cstr()
   {
#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

   /*
   It is intentional that this string is a compile-time constant;
   it makes it much easier to find in binaries.
   */

   return "Botan " STR(BOTAN_VERSION_MAJOR) "."
                   STR(BOTAN_VERSION_MINOR) "."
                   STR(BOTAN_VERSION_PATCH) " ("
#if defined(BOTAN_UNSAFE_FUZZER_MODE)
                   "UNSAFE FUZZER MODE BUILD "
#endif
                   BOTAN_VERSION_RELEASE_TYPE
#if (BOTAN_VERSION_DATESTAMP != 0)
                   ", dated " STR(BOTAN_VERSION_DATESTAMP)
#endif
                   ", revision " BOTAN_VERSION_VC_REVISION
                   ", distribution " BOTAN_DISTRIBUTION_INFO ")";

#undef STR
#undef QUOTE
   }

u32bit version_datestamp() { return BOTAN_VERSION_DATESTAMP; }

/*
* Return parts of the version as integers
*/
u32bit version_major() { return BOTAN_VERSION_MAJOR; }
u32bit version_minor() { return BOTAN_VERSION_MINOR; }
u32bit version_patch() { return BOTAN_VERSION_PATCH; }

std::string runtime_version_check(u32bit major,
                                  u32bit minor,
                                  u32bit patch)
   {
   std::ostringstream oss;

   if(major != version_major() ||
      minor != version_minor() ||
      patch != version_patch())
      {
      oss << "Warning: linked version ("
          << Botan::version_major() << '.'
          << Botan::version_minor() << '.'
          << Botan::version_patch()
          << ") does not match version built against ("
          << major << '.' << minor << '.' << patch << ")\n";
      }

   return oss.str();
   }

}
