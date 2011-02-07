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
   std::ostringstream out;

   out << "Botan " << version_major() << "."
       << version_minor() << "."
       << version_patch() << " (";

   if(BOTAN_VERSION_DATESTAMP == 0)
      out << "unreleased version";
   else
      out << "released " << version_datestamp();

   out << ", distribution " << BOTAN_DISTRIBUTION_INFO << ")";

   return out.str();
   }

u32bit version_datestamp() { return BOTAN_VERSION_DATESTAMP; }

/*
* Return parts of the version as integers
*/
u32bit version_major() { return BOTAN_VERSION_MAJOR; }
u32bit version_minor() { return BOTAN_VERSION_MINOR; }
u32bit version_patch() { return BOTAN_VERSION_PATCH; }

}
