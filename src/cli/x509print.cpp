/*
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"
#if defined(BOTAN_HAS_X509_CERTIFICATES)
#include <botan/x509cert.h>

namespace {

int x509print(const std::vector<std::string> &args)
   {
   if(args.size() != 2)
      {
      std::cout << "Usage: " << args[0] << " cert.pem" << std::endl;
      return 1;
      }

   X509_Certificate cert(args[1]);

   std::cout << cert.to_string() << std::endl;

   return 0;
   }

REGISTER_APP(x509print);

}

#endif
