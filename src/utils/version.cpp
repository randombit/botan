/*
* Version Information
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
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
#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

   return "Botan " STR(BOTAN_VERSION_MAJOR) "."
                   STR(BOTAN_VERSION_MINOR) "."
                   STR(BOTAN_VERSION_PATCH) " ("

#if (BOTAN_VERSION_DATESTAMP == 0)
      "unreleased version"
#else
      "released " STR(BOTAN_VERSION_DATESTAMP)
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

}
