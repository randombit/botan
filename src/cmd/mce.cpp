/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_MCELIECE)

#include <botan/mceliece.h>
#include <botan/mceies.h>
#include <botan/pkcs8.h>
#include <fstream>

namespace {

int mce(const std::vector<std::string> &args)
   {
   if(args.size() < 4)
      {
      std::cout << "Usage: " << args[0] << " [keygen n t pass|keybits n t|encrypt file key|decrypt file key pass]"
                << std::endl;
      return 1;
      }

   const std::string cmd = args[1];

   AutoSeeded_RNG rng;

   if(cmd == "keygen")
      {
      const u32bit n = to_u32bit(args[2]);
      const u32bit t = to_u32bit(args[3]);
      const std::string pass = args[4];

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
      const u32bit n = to_u32bit(args[2]);
      const u32bit t = to_u32bit(args[3]);
      std::cout << "McEliece key with params (" << n << "," << t << ") has "
                << mceliece_work_factor(n, t) << " bit security\n";
      }
   else if(cmd == "encrypt")
      {
      std::unique_ptr<Public_Key> p8(X509::load_key(args[3]));
      const McEliece_PublicKey* key = dynamic_cast<McEliece_PublicKey*>(p8.get());

      if(!key)
         {
         throw std::runtime_error("Loading McEliece public key failed");
         }

      const std::string input_path = args[2];
      std::ifstream in(input_path, std::ios::binary);
      std::string pt((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

      secure_vector<byte> ct = mceies_encrypt(*key,
                                              reinterpret_cast<const byte*>(pt.data()),
                                              pt.size(),
                                              nullptr, 0, rng, "AES-128/GCM");

      std::cout << pt.size() << " -> " << ct.size() << std::endl;

      std::ofstream out(std::string(input_path) + ".ct", std::ios::binary);
      out.write(reinterpret_cast<const char*>(ct.data()), ct.size());
      out.close();
      }
   else if(cmd == "decrypt")
      {
      const std::string key_file = args[3];
      const std::string pass = args[4];
      std::unique_ptr<Private_Key> p8(PKCS8::load_key(key_file, rng, pass));
      const McEliece_PrivateKey* key = dynamic_cast<McEliece_PrivateKey*>(p8.get());

      if(!key)
         {
         throw std::runtime_error("Loading McEliece private key failed");
         }

      std::ifstream in(args[2], std::ios::binary);
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
