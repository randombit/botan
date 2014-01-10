#include "apps.h"
#include <botan/x509cert.h>

int x509_main(int argc, char* argv[])
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
