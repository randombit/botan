/*
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"
#if defined(BOTAN_HAS_X509_CERTIFICATES)
#include <botan/x509cert.h>

namespace {

int x509print(int argc, char* argv[])
   {
   if(argc < 1)
      {
      std::cout << "Usage: " << argv[0] << " cert.pem\n";
      return 1;
      }

   X509_Certificate cert(argv[1]);

   std::cout << cert.to_string() << "\n";

   return 0;
   }

REGISTER_APP(x509print);

}

#endif
