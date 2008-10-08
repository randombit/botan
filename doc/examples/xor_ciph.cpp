/*
  An implementation of the highly secure (not) XOR cipher. AKA, how to write
  and use your own cipher object. DO NOT make up your own ciphers. Please.

  Written by Jack Lloyd (lloyd@randombit.net) on Feb 17, 2004

  This file is in the public domain
*/
#include <botan/base.h>
#include <botan/init.h>
using namespace Botan;

class XOR_Cipher : public StreamCipher
   {
   public:
      void clear() throw() { mask.destroy(); mask_pos = 0; }

      // what we want to call this cipher
      std::string name() const { return "XOR"; }

      // return a new object of this type
      StreamCipher* clone() const { return new XOR_Cipher; }

      XOR_Cipher() : StreamCipher(1, 32) { mask_pos = 0; }
   private:
      void cipher(const byte[], byte[], u32bit);
      void key(const byte[], u32bit);

      SecureVector<byte> mask;
      u32bit mask_pos;
   };

void XOR_Cipher::cipher(const byte in[], byte out[], u32bit length)
   {
   for(u32bit j = 0; j != length; j++)
      {
      out[j] = in[j] ^ mask[mask_pos];
      mask_pos = (mask_pos + 1) % mask.size();
      }
   }

void XOR_Cipher::key(const byte key[], u32bit length)
   {
   mask.set(key, length);
   }

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>

#include <botan/look_add.h>
#include <botan/lookup.h>
#include <botan/filters.h>
#include <botan/libstate.h>

int main()
   {
   add_algorithm(global_state(), new XOR_Cipher); // make it available to use
   global_state().add_alias("Vernam", "XOR"); // make Vernam an alias for XOR

   // a hex key value
   SymmetricKey key("010203040506070809101112AAFF");

   /*
    Since stream ciphers are typically additive, the encryption and
    decryption ops are the same, so this isn't terribly interesting.

    If this where a block cipher you would have to add a cipher mode and
    padding method, such as "/CBC/PKCS7".
   */
   Pipe enc(get_cipher("XOR", key, ENCRYPTION), new Hex_Encoder);
   Pipe dec(new Hex_Decoder, get_cipher("Vernam", key, DECRYPTION));

   // I think the pigeons are actually asleep at midnight...
   std::string secret = "The pigeon flys at midnight.";

   std::cout << "The secret message is '" << secret << "'" << std::endl;

   enc.process_msg(secret);
   std::string cipher = enc.read_all_as_string();

   std::cout << "The encrypted secret message is " << cipher << std::endl;

   dec.process_msg(cipher);
   secret = dec.read_all_as_string();

   std::cout << "The decrypted secret message is '"
             << secret << "'" << std::endl;

   return 0;
   }
