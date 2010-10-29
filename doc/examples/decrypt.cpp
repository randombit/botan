/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
Decrypt files encrypted with the 'encrypt' example application.

I'm being lazy and writing the output to stdout rather than stripping
off the ".enc" suffix and writing it there. So all diagnostics go to
stderr so there is no confusion.
*/

#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <memory>

#include <botan/botan.h>

#if defined(BOTAN_HAS_COMPRESSOR_ZLIB)
  #include <botan/zlib.h>
#endif

using namespace Botan;

SecureVector<byte> b64_decode(const std::string&);

int main(int argc, char* argv[])
   {
   if(argc < 2)
      {
      std::cout << "Usage: " << argv[0] << " [-p passphrase] file\n"
                << "   -p : Use this passphrase to decrypt\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   std::string filename, passphrase;

   for(int j = 1; argv[j] != 0; j++)
      {
      if(std::strcmp(argv[j], "-p") == 0)
         {
         if(argv[j+1])
            {
            passphrase = argv[j+1];
            j++;
            }
         else
            {
            std::cout << "No argument for -p option" << std::endl;
            return 1;
            }
         }
      else
         {
         if(filename != "")
            {
            std::cout << "You can only specify one file at a time\n";
            return 1;
            }
         filename = argv[j];
         }
      }

   if(passphrase == "")
      {
      std::cout << "You have to specify a passphrase!" << std::endl;
      return 1;
      }

   std::ifstream in(filename.c_str());
   if(!in)
      {
      std::cout << "ERROR: couldn't open " << filename << std::endl;
      return 1;
      }

   std::string algo;

   try {
      std::string header, salt_str, mac_str;
      std::getline(in, header);
      std::getline(in, algo);
      std::getline(in, salt_str);
      std::getline(in, mac_str);

      if(header != "-------- ENCRYPTED FILE --------")
         {
         std::cout << "ERROR: File is missing the usual header" << std::endl;
         return 1;
         }

      const BlockCipher* cipher_proto = global_state().algorithm_factory().prototype_block_cipher(algo);

      if(!cipher_proto)
         {
         std::cout << "Don't know about the block cipher \"" << algo << "\"\n";
         return 1;
         }

      const u32bit key_len = cipher_proto->maximum_keylength();
      const u32bit iv_len = cipher_proto->block_size();

      std::auto_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(SHA-1)"));

      const u32bit PBKDF2_ITERATIONS = 8192;

      SecureVector<byte> salt = b64_decode(salt_str);

      SymmetricKey bc_key = pbkdf->derive_key(key_len, "BLK" + passphrase,
                                              &salt[0], salt.size(),
                                              PBKDF2_ITERATIONS);

      InitializationVector iv = pbkdf->derive_key(iv_len, "IVL" + passphrase,
                                                  &salt[0], salt.size(),
                                                  PBKDF2_ITERATIONS);

      SymmetricKey mac_key = pbkdf->derive_key(16, "MAC" + passphrase,
                                               &salt[0], salt.size(),
                                               PBKDF2_ITERATIONS);

      Pipe pipe(new Base64_Decoder,
                get_cipher(algo + "/CBC", bc_key, iv, DECRYPTION),
#ifdef BOTAN_HAS_COMPRESSOR_ZLIB
                new Zlib_Decompression,
#endif
                new Fork(
                   0,
                   new Chain(new MAC_Filter("HMAC(SHA-1)", mac_key),
                             new Base64_Encoder)
                   )
         );

      pipe.start_msg();
      in >> pipe;
      pipe.end_msg();

      std::string our_mac = pipe.read_all_as_string(1);
      if(our_mac != mac_str)
         std::cout << "WARNING: MAC in message failed to verify\n";

      std::cout << pipe.read_all_as_string(0);
   }
   catch(Algorithm_Not_Found)
      {
      std::cout << "Don't know about the block cipher \"" << algo << "\"\n";
      return 1;
      }
   catch(Decoding_Error)
      {
      std::cout << "Bad passphrase or corrupt file\n";
      return 1;
      }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return 1;
      }
   return 0;
   }

SecureVector<byte> b64_decode(const std::string& in)
   {
   Pipe pipe(new Base64_Decoder);
   pipe.process_msg(in);
   return pipe.read_all();
   }
