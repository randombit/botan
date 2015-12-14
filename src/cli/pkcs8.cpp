/*
* (C) 2015 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"
#include <iostream>
#include <fstream>
#include <string>
#include <memory>
#include <chrono>

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>
#include <botan/x509_key.h>

using namespace Botan;

namespace {

int pkcs8(const std::vector<std::string> &args)
   {
   OptionParser opts("in=|out=|passin=|passout=|pbe=|pubout");
   opts.parse(args);

   const std::string passin = opts.value_or_else("passin", "");
   const std::string passout = opts.value_or_else("passout", "");
   const std::string pbe = opts.value_or_else("pbe", "");

   if(args.size() < 3)
      {
      opts.help(std::cout, "pkcs8");
      return 1;
      }

   try
      {
      std::ofstream out_key(opts.value("out"));
         
      if (!out_key)
         {
         std::cout << "Couldn't write key" << std::endl;
         return 1;
         }

      AutoSeeded_RNG rng;
      std::unique_ptr<Private_Key> key(PKCS8::load_key(opts.value("in"), rng, passin));
                
      if(opts.is_set("pubout"))
         {
         out_key << X509::PEM_encode(*key);
         }
         else
         {
         if(passout.empty())
            out_key << PKCS8::PEM_encode(*key);
         else
            out_key << PKCS8::PEM_encode(*key, rng, passout, std::chrono::milliseconds(300), pbe);
         }
       }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return 2;
      }

   return 0;
   }

REGISTER_APP(pkcs8);

}

#endif
