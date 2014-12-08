#include "apps.h"
#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <memory>

#if defined(BOTAN_HAS_RSA)
#include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
#include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
#include <botan/ecdsa.h>
#endif

using namespace Botan;

namespace {

std::string dsa_group_for(size_t bits)
   {
   if(bits == 1024)
      return "dsa/jce/1024";
   if(bits == 2048)
      return "dsa/botan/2048";
   if(bits == 3072)
      return "dsa/botan/3072";
   throw std::runtime_error("No registered DSA group for " + std::to_string(bits) + " bits");
   }

Private_Key* gen_key(RandomNumberGenerator& rng, const std::string& algo, size_t bits)
   {
#if defined(BOTAN_HAS_RSA)
   if(algo == "rsa")
      return new RSA_PrivateKey(rng, bits);
#endif

#if defined(BOTAN_HAS_DSA)
   if(algo == "dsa")
      {
      DL_Group grp(dsa_group_for(bits));
      return new DSA_PrivateKey(rng, grp);
      }
#endif

#if defined(BOTAN_HAS_ECDSA)
   if(algo == "ecdsa")
      {
      EC_Group grp("secp" + std::to_string(bits) + "r1");
      return new ECDSA_PrivateKey(rng, grp);
      }
#endif

   throw std::runtime_error("Unknown algorithm " + algo);
   }


int keygen(int argc, char* argv[])
   {
   OptionParser opts("algo=|bits=|passphrase=|pbe=");
   opts.parse(argv);

   const std::string algo = opts.value_or_else("algo", "rsa");
   const size_t bits = opts.int_value_or_else("bits", 1024);
   const std::string pass = opts.value_or_else("passphrase", "");
   const std::string pbe = opts.value_or_else("pbe", "");

   try
      {
      std::ofstream pub("public.pem");
      std::ofstream priv("private.pem");

      if(!priv || !pub)
         {
         std::cout << "Couldn't write output files" << std::endl;
         return 1;
         }

      AutoSeeded_RNG rng;

      std::auto_ptr<Private_Key> key(gen_key(rng, algo, bits));

      pub << X509::PEM_encode(*key);

      if(pass == "")
         priv << PKCS8::PEM_encode(*key);
      else
         priv << PKCS8::PEM_encode(*key, rng, pass, std::chrono::milliseconds(300), pbe);

      std::cout << "Wrote " << bits << " bit " << algo << " key to public.pem / private.pem\n";
      }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }

   return 0;
   }

REGISTER_APP(keygen);

}
