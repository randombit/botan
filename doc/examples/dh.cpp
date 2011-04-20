#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/pubkey.h>
using namespace Botan;

#include <iostream>
#include <memory>

int main()
   {
   try
      {
      LibraryInitializer init;

      AutoSeeded_RNG rng;

      // Alice and Bob agree on a DH domain to use
      DL_Group shared_domain("modp/ietf/2048");

      // Alice creates a DH key
      DH_PrivateKey private_a(rng, shared_domain);

      // Bob creates a key with a matching group
      DH_PrivateKey private_b(rng, shared_domain);

      // Alice sends to Bob her public key and a session parameter
      MemoryVector<byte> public_a = private_a.public_value();
      const std::string session_param =
         "Alice and Bob's shared session parameter";

      // Bob sends his public key to Alice
      MemoryVector<byte> public_b = private_b.public_value();

      // Now Alice performs the key agreement operation
      PK_Key_Agreement ka_alice(private_a, "KDF2(SHA-256)");
      SymmetricKey alice_key = ka_alice.derive_key(32, public_b, session_param);

      // Bob does the same:
      PK_Key_Agreement ka_bob(private_b, "KDF2(SHA-256)");
      SymmetricKey bob_key = ka_bob.derive_key(32, public_a, session_param);

      if(alice_key == bob_key)
         {
         std::cout << "The two keys matched, everything worked\n";
         std::cout << "The shared key was: " << alice_key.as_string() << "\n";
         }
      else
         {
         std::cout << "The two keys didn't match! Hmmm...\n";
         std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
         std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
         }

      // Now use the shared key for encryption or MACing or whatever
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
