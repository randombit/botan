#include "apps.h"

#if defined(BOTAN_HAS_MCELIECE)

#include <botan/mceliece.h>
#include <botan/mceies.h>
#include <botan/pkcs8.h>
#include <fstream>

namespace {

int mce(int argc, char* argv[])
   {
   if(argc < 4)
      {
      std::cout << "Usage: " << argv[0] << " [keygen n t pass|keybits n t|encrypt file key|decrypt file key pass]\n";
      return 1;
      }

   const std::string cmd = argv[1];

   AutoSeeded_RNG rng;

   if(cmd == "keygen")
      {
      const size_t n = std::stol(argv[2]);
      const size_t t = std::stol(argv[3]);
      const std::string pass = argv[4];

      McEliece_PrivateKey pk(rng, n, t);

      bool ok = pk.check_key(rng, true);

      if(!ok)
         {
         std::cout << "Keygen failed self-test\n";
         return 2;
         }

      /*
      secure_vector<byte> priv = PKCS8::BER_encode(pk);
      std::vector<byte> pub = X509::BER_encode(pk);
      std::cout << priv.size()/1024.0 << " " << pub.size()/1024.0 << "\n";
      */

      std::ofstream pub_file("mce.pub");
      pub_file <<  X509::PEM_encode(pk);
      pub_file.close();

      std::ofstream priv_file("mce.priv");
      priv_file << PKCS8::PEM_encode(pk, rng, pass);
      priv_file.close();
      }
   else if(cmd == "keybits")
      {
      const size_t n = std::stol(argv[2]);
      const size_t t = std::stol(argv[3]);
      std::cout << "McEliece key with params (" << n << "," << t << ") has "
                << mceliece_work_factor(n, t) << " bit security\n";
      }
   else if(cmd == "encrypt")
      {
      std::unique_ptr<Public_Key> p8(X509::load_key(argv[3]));
      const McEliece_PublicKey* key = dynamic_cast<McEliece_PublicKey*>(p8.get());

      if(!key)
         {
         throw std::runtime_error("Loading McEliece public key failed");
         }

      const std::string input_path = argv[2];
      std::ifstream in(input_path, std::ios::binary);
      std::string pt((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

      secure_vector<byte> ct = mceies_encrypt(*key,
                                              reinterpret_cast<const byte*>(pt.data()),
                                              pt.size(),
                                              nullptr, 0, rng, "AES-128/GCM");

      std::cout << pt.size() << " -> " << ct.size() << "\n";

      std::ofstream out(std::string(input_path) + ".ct", std::ios::binary);
      out.write(reinterpret_cast<const char*>(ct.data()), ct.size());
      out.close();
      }
   else if(cmd == "decrypt")
      {
      const std::string key_file = argv[3];
      const std::string pass = argv[4];
      std::unique_ptr<Private_Key> p8(PKCS8::load_key(key_file, rng, pass));
      const McEliece_PrivateKey* key = dynamic_cast<McEliece_PrivateKey*>(p8.get());

      if(!key)
         {
         throw std::runtime_error("Loading McEliece private key failed");
         }

      std::ifstream in(argv[2], std::ios::binary);
      std::string ct((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

      secure_vector<byte> pt = mceies_decrypt(*key,
                                              reinterpret_cast<const byte*>(ct.data()),
                                              ct.size(),
                                              nullptr, 0, "AES-128/GCM");

      std::ofstream out("mce.plaintext", std::ios::binary);
      out.write(reinterpret_cast<const char*>(pt.data()), pt.size());
      out.close();
      }
   return 0;
   }

}

REGISTER_APP(mce);

#endif
