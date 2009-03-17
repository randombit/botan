/*
  A simple DH example

  Written by Jack Lloyd (lloyd@randombit.net), on December 24, 2003

  This file is in the public domain
*/
#include <botan/botan.h>
#include <botan/dh.h>
#include <botan/rng.h>
using namespace Botan;

#include <iostream>
#include <memory>

int main()
   {
   Botan::LibraryInitializer init;
   
   try
      {
      AutoSeeded_RNG rng;

      // Alice creates a DH key and sends (the public part) to Bob
      DH_PrivateKey private_a(rng, DL_Group("modp/ietf/1024"));
      DH_PublicKey public_a = private_a; // Bob gets this

      // Bob creates a key with a matching group
      DH_PrivateKey private_b(rng, public_a.get_domain());

      // Bob sends the key back to Alice
      DH_PublicKey public_b = private_b; // Alice gets this

      // Both of them create a key using their private key and the other's
      // public key
      SymmetricKey alice_key = private_a.derive_key(public_b);
      SymmetricKey bob_key = private_b.derive_key(public_a);

      if(alice_key == bob_key)
         {
         std::cout << "The two keys matched, everything worked\n";
         std::cout << "The shared key was: " << alice_key.as_string() << "\n";
         }
      else
         {
         std::cout << "The two keys didn't match!\n";
         std::cout << "Alice's key was: " << alice_key.as_string() << "\n";
         std::cout << "Bob's key was: " << bob_key.as_string() << "\n";
         }

      // Now Alice and Bob hash the key and use it for something
   }
   catch(std::exception& e)
      {
      std::cout << e.what() << std::endl;
      return 1;
      }
   return 0;
   }
