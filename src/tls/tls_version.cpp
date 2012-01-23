/*
* TLS Protocol Version Management
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_version.h>
#include <botan/parsing.h>

namespace Botan {

namespace TLS {

std::string Protocol_Version::to_string() const
   {
   const byte maj = major_version();
   const byte min = minor_version();

   // Some very new or very old protocol?
   if(maj != 3)
      return "Protocol " + Botan::to_string(maj) + "." + Botan::to_string(min);

   if(maj == 3 && min == 0)
      return "SSL v3";

   // The TLS v1.[0123...] case
   return "TLS v1." + Botan::to_string(min-1);
   }

}

}
