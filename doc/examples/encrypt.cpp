/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
Encrypt a file using a block cipher in CBC mode. Compresses the plaintext
with Zlib, MACs with HMAC(SHA-1). Stores the block cipher used in the file,
so you don't have to specify it when decrypting.

What a real application would do (and what this example should do), is test for
the presence of the Zlib module, and use it only if it's available. Then add
some marker to the stream so the other side knows whether or not the plaintext
was compressed. Bonus points for supporting multiple compression schemes.

Another flaw is that is stores the entire ciphertext in memory, so if the file
you're encrypting is 1 Gb... you better have a lot of RAM.
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

std::string b64_encode(const SecureVector<byte>&);

int main(int argc, char* argv[])
   {
   if(argc < 2)
      {
      std::cout << "Usage: " << argv[0] << " [-c algo] -p passphrase file\n"
                   "   -p : Use this passphrase to encrypt\n"
                   "   -c : Encrypt with block cipher 'algo' (default 3DES)\n";
      return 1;
      }

   Botan::LibraryInitializer init;

   std::string algo = "TripleDES";
   std::string filename, passphrase;

   // Holy hell, argument processing is a PITA
   for(int j = 1; argv[j] != 0; j++)
      {
      if(std::strcmp(argv[j], "-c") == 0)
         {
         if(argv[j+1])
            {
            algo = argv[j+1];
            j++;
            }
         else
            {
            std::cout << "No argument for -c option" << std::endl;
            return 1;
            }
         }
      else if(std::strcmp(argv[j], "-p") == 0)
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

   std::ifstream in(filename.c_str(), std::ios::binary);
   if(!in)
      {
      std::cout << "ERROR: couldn't open " << filename << std::endl;
      return 1;
      }

   std::string outfile = filename + ".enc";
   std::ofstream out(outfile.c_str());
   if(!out)
      {
      std::cout << "ERROR: couldn't open " << outfile << std::endl;
      return 1;
      }

   try
      {
      const BlockCipher* cipher_proto = global_state().algorithm_factory().prototype_block_cipher(algo);

      if(!cipher_proto)
         {
         std::cout << "Don't know about the block cipher \"" << algo << "\"\n";
         return 1;
         }

      const u32bit key_len = cipher_proto->maximum_keylength();
      const u32bit iv_len = cipher_proto->block_size();

      AutoSeeded_RNG rng;

      std::auto_ptr<PBKDF> pbkdf(get_pbkdf("PBKDF2(SHA-1)"));

      SecureVector<byte> salt(8);
      rng.randomize(&salt[0], salt.size());

      const u32bit PBKDF2_ITERATIONS = 8192;

      SymmetricKey bc_key = pbkdf->derive_key(key_len, "BLK" + passphrase,
                                              &salt[0], salt.size(),
                                              PBKDF2_ITERATIONS);

      InitializationVector iv = pbkdf->derive_key(iv_len, "IVL" + passphrase,
                                                  &salt[0], salt.size(),
                                                  PBKDF2_ITERATIONS);

      SymmetricKey mac_key = pbkdf->derive_key(16, "MAC" + passphrase,
                                               &salt[0], salt.size(),
                                               PBKDF2_ITERATIONS);

      // Just to be all fancy we even write a (simple) header.
      out << "-------- ENCRYPTED FILE --------" << std::endl;
      out << algo << std::endl;
      out << b64_encode(salt) << std::endl;

      Pipe pipe(new Fork(
                   new Chain(new MAC_Filter("HMAC(SHA-1)", mac_key),
                             new Base64_Encoder
                      ),
                   new Chain(
#ifdef BOTAN_HAS_COMPRESSOR_ZLIB
                             new Zlib_Compression,
#endif
                             get_cipher(algo + "/CBC", bc_key, iv, ENCRYPTION),
                             new Base64_Encoder(true)
                      )
                   )
         );

      pipe.start_msg();
      in >> pipe;
      pipe.end_msg();

      out << pipe.read_all_as_string(0) << std::endl;
      out << pipe.read_all_as_string(1);

      }
   catch(Algorithm_Not_Found)
      {
      std::cout << "Don't know about the block cipher \"" << algo << "\"\n";
      return 1;
      }
   catch(std::exception& e)
      {
      std::cout << "Exception caught: " << e.what() << std::endl;
      return 1;
      }
   return 0;
   }

std::string b64_encode(const SecureVector<byte>& in)
   {
   Pipe pipe(new Base64_Encoder);
   pipe.process_msg(in);
   return pipe.read_all_as_string();
   }
