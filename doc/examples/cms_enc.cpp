#include <botan/botan.h>
#include <botan/cms_enc.h>
using namespace Botan;

#include <iostream>
#include <fstream>
#include <memory>

int main()
   {
   Botan::LibraryInitializer init;

   try {

      X509_Certificate mycert("mycert.pem");
      X509_Certificate mycert2("mycert2.pem");
      X509_Certificate yourcert("yourcert.pem");
      X509_Certificate cacert("cacert.pem");
      X509_Certificate int_ca("int_ca.pem");

      AutoSeeded_RNG rng;

      X509_Store store;
      store.add_cert(mycert);
      store.add_cert(mycert2);
      store.add_cert(yourcert);
      store.add_cert(int_ca);
      store.add_cert(cacert, true);

      const std::string msg = "prioncorp: we don't toy\n";

      CMS_Encoder encoder(msg);

      encoder.compress("Zlib");
      encoder.digest();
      encoder.encrypt(rng, mycert);

      /*
      PKCS8_PrivateKey* mykey = PKCS8::load_key("mykey.pem", rng, "cut");
      encoder.sign(store, *mykey);
      */

      SecureVector<byte> raw = encoder.get_contents();
      std::ofstream out("out.der");

      out.write((const char*)raw.begin(), raw.size());
   }
   catch(std::exception& e)
      {
      std::cerr << e.what() << std::endl;
      }
   return 0;
   }
