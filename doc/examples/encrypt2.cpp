/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/botan.h>
#include <botan/pbkdf2.h>
#include <botan/hmac.h>
#include <botan/sha160.h>

#include <fstream>

using namespace Botan;

int main()
   {
   Botan::LibraryInitializer init;

   AutoSeeded_RNG rng;

   std::string passphrase = "secret";

   std::ifstream infile("readme.txt");
   std::ofstream outfile("readme.txt.enc");

   PKCS5_PBKDF2 pbkdf2(new HMAC(new SHA_160));

   const u32bit PBKDF2_ITERATIONS = 8192;

   SecureVector<byte> salt(8);
   rng.randomize(&salt[0], salt.size());

   SecureVector<byte> master_key = pbkdf2.derive_key(48, passphrase,
                                                     &salt[0], salt.size(),
                                                     PBKDF2_ITERATIONS).bits_of();

   KDF* kdf = get_kdf("KDF2(SHA-1)");

   SymmetricKey key = kdf->derive_key(20, master_key, "cipher key");

   SymmetricKey mac_key = kdf->derive_key(20, master_key, "hmac key");

   InitializationVector iv = kdf->derive_key(8, master_key, "cipher iv");

   Pipe pipe(new Fork(
                new Chain(
                   get_cipher("Blowfish/CBC/PKCS7", key, iv, ENCRYPTION),
                   new Base64_Encoder,
                   new DataSink_Stream(outfile)
                   ),
                new Chain(
                   new MAC_Filter("HMAC(SHA-1)", mac_key),
                   new Hex_Encoder)
                )
      );

   outfile.write((const char*)salt.begin(), salt.size());

   pipe.start_msg();
   infile >> pipe;
   pipe.end_msg();

   SecureVector<byte> hmac = pipe.read_all(1);
   outfile.write((const char*)hmac.begin(), hmac.size());
   }
