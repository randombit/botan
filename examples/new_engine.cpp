/*
* Adding an application specific engine
* (C) 2004,2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/stream_cipher.h>
#include <botan/engine.h>

using namespace Botan;

class XOR_Cipher : public StreamCipher
   {
   public:
      void clear() throw() { mask.clear(); mask_pos = 0; }

      // what we want to call this cipher
      std::string name() const { return "XOR"; }

      // return a new object of this type
      StreamCipher* clone() const { return new XOR_Cipher; }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(1, 32);
         }

      XOR_Cipher() : mask_pos(0) {}
   private:
      void cipher(const byte in[], byte out[], size_t length)
         {
         for(size_t j = 0; j != length; j++)
            {
            out[j] = in[j] ^ mask[mask_pos];
            mask_pos = (mask_pos + 1) % mask.size();
            }
         }

      void key_schedule(const byte key[], size_t length)
         {
         mask.resize(length);
         copy_mem(&mask[0], key, length);
         }

      SecureVector<byte> mask;
      u32bit mask_pos;
   };

class Application_Engine : public Engine
   {
   public:
      std::string provider_name() const { return "application"; }

      StreamCipher* find_stream_cipher(const SCAN_Name& request,
                                       Algorithm_Factory&) const
         {
         if(request.algo_name() == "XOR")
            return new XOR_Cipher;
         return 0;
         }
   };

#include <botan/botan.h>
#include <iostream>
#include <string>

int main()
   {

   Botan::LibraryInitializer init;

   global_state().algorithm_factory().add_engine(
      new Application_Engine);

   // a hex key value
   SymmetricKey key("010203040506070809101112AAFF");

   /*
    Since stream ciphers are typically additive, the encryption and
    decryption ops are the same, so this isn't terribly interesting.

    If this where a block cipher you would have to add a cipher mode and
    padding method, such as "/CBC/PKCS7".
   */
   Pipe enc(get_cipher("XOR", key, ENCRYPTION), new Hex_Encoder);
   Pipe dec(new Hex_Decoder, get_cipher("XOR", key, DECRYPTION));

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
