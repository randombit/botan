/*************************************************
* Version Information Source File                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/version.h>
#include <botan/parsing.h>

namespace Botan {

/*************************************************
* Return the version as a string                 *
*************************************************/
std::string version_string()
   {
   return "Botan " + to_string(version_major()) + "." +
                     to_string(version_minor()) + "." +
                     to_string(version_patch());
   }

/*************************************************
* Return parts of the version as integers        *
*************************************************/
u32bit version_major() { return BOTAN_VERSION_MAJOR; }
u32bit version_minor() { return BOTAN_VERSION_MINOR; }
u32bit version_patch() { return BOTAN_VERSION_PATCH; }

}
