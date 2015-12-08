/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO) && defined(BOTAN_HAS_X509_CERTIFICATES)

#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <memory>
#include <botan/pk_keys.h>
#include <botan/pkcs8.h>

#if defined(BOTAN_HAS_RSA)
#include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
#include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
#include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_CURVE_25519)
#include <botan/curve25519.h>
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

#if defined(BOTAN_HAS_CURVE_25519)
   if(algo == "curve25519")
      return new Curve25519_PrivateKey(rng);
#endif

   throw std::runtime_error("Unknown algorithm " + algo);
   }


int keygen(const std::vector<std::string> &args)
   {
   OptionParser opts("algo=|bits=|passphrase=|pbe=");
   opts.parse(args);

   const std::string algo = opts.value_or_else("algo", "rsa");
   const size_t bits = opts.int_value_or_else("bits", 2048);
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

      std::unique_ptr<Private_Key> key(gen_key(rng, algo, bits));

      pub << X509::PEM_encode(*key);

      if(pass == "")
         priv << PKCS8::PEM_encode(*key);
      else
         priv << PKCS8::PEM_encode(*key, rng, pass, std::chrono::milliseconds(300), pbe);

      std::cout << "Wrote " << bits << " bit " << algo << " key to public.pem / private.pem" << std::endl;
      }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      }

   return 0;
   }

REGISTER_APP(keygen);

}

#endif // BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_HAS_X509_CERTIFICATES
