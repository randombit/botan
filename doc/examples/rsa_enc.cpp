/*
* (C) 2002 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

/*
  Grab an RSA public key from the file given as an argument, grab a message
  from another file, and encrypt the message.

  Algorithms used:
    RSA with EME1(SHA-1) padding to encrypt the master key
    CAST-128 in CBC mode with PKCS#7 padding to encrypt the message.
    HMAC with SHA-1 is used to authenticate the message

  The keys+IV used are derived from the master key (the thing that's encrypted
  with RSA) using KDF2(SHA-1). The 3 outputs of KDF2 are parameterized by P,
  where P is "CAST", "IV" or "MAC", in order to make each key/IV unique.

  The format is:
     1) First line is the master key, encrypted with the recipients public key
        using EME1(SHA-1), and then base64 encoded.
     2) Second line is the first 96 bits (12 bytes) of the HMAC(SHA-1) of
        the _plaintext_
     3) Following lines are base64 encoded ciphertext (CAST-128 as described),
        each broken after ~72 characters.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <memory>

#include <botan/botan.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
using namespace Botan;

std::string b64_encode(const SecureVector<byte>&);
SymmetricKey derive_key(const std::string&, const SymmetricKey&, u32bit);

int main(int argc, char* argv[])
   {
   if(argc != 3)
      {
      std::cout << "Usage: " << argv[0] << " keyfile messagefile" << std::endl;
      return 1;
      }

   std::ifstream message(argv[2], std::ios::binary);
   if(!message)
      {
      std::cout << "Couldn't read the message file." << std::endl;
      return 1;
      }

   Botan::LibraryInitializer init;

   std::string output_name(argv[2]);
   output_name += ".enc";
   std::ofstream ciphertext(output_name.c_str());
   if(!ciphertext)
      {
      std::cout << "Couldn't write the ciphertext to " << output_name
           << std::endl;
      return 1;
      }

   try {
      std::auto_ptr<X509_PublicKey> key(X509::load_key(argv[1]));
      RSA_PublicKey* rsakey = dynamic_cast<RSA_PublicKey*>(key.get());
      if(!rsakey)
         {
         std::cout << "The loaded key is not a RSA key!\n";
         return 1;
         }

      AutoSeeded_RNG rng;

      PK_Encryptor_EME encryptor(*rsakey, "EME1(SHA-1)");

      /* Generate the master key (the other keys are derived from this)

         Basically, make the key as large as can be encrypted by this key, up
         to a limit of 256 bits. For 512 bit keys, the master key will be >160
         bits. A >600 bit key will use the full 256 bit master key.

         In theory, this is not enough, because we derive 16+16+8=40 bytes of
         secrets (if you include the IV) using the master key, so they are not
         statistically indepedent. Practically speaking I don't think this is
         a problem.
      */
      SymmetricKey masterkey(rng,
                             std::min<size_t>(32,
                                              encryptor.maximum_input_size()));

      SymmetricKey cast_key = derive_key("CAST", masterkey, 16);
      SymmetricKey mac_key  = derive_key("MAC",  masterkey, 16);
      SymmetricKey iv       = derive_key("IV",   masterkey, 8);

      SecureVector<byte> encrypted_key =
         encryptor.encrypt(masterkey.bits_of(), rng);

      ciphertext << b64_encode(encrypted_key) << std::endl;

      Pipe pipe(new Fork(
                   new Chain(
                      get_cipher("CAST-128/CBC/PKCS7", cast_key, iv,
                                 ENCRYPTION),
                      new Base64_Encoder(true) // true == do linebreaking
                      ),
                   new Chain(
                      new MAC_Filter("HMAC(SHA-1)", mac_key, 12),
                      new Base64_Encoder
                      )
                   )
         );

      pipe.start_msg();
      message >> pipe;
      pipe.end_msg();

      /* Write the MAC as the second line. That way we can pull it off right
         from the start, and feed the rest of the file right into a pipe on the
         decrypting end.
      */

      ciphertext << pipe.read_all_as_string(1) << std::endl;
      ciphertext << pipe.read_all_as_string(0);
   }
   catch(std::exception& e)
      {
      std::cout << "Exception: " << e.what() << std::endl;
      }
   return 0;
   }

std::string b64_encode(const SecureVector<byte>& in)
   {
   Pipe pipe(new Base64_Encoder);
   pipe.process_msg(in);
   return pipe.read_all_as_string();
   }

SymmetricKey derive_key(const std::string& param,
                        const SymmetricKey& masterkey,
                        u32bit outputlength)
   {
   std::auto_ptr<KDF> kdf(get_kdf("KDF2(SHA-1)"));
   return kdf->derive_key(outputlength, masterkey.bits_of(), param);
   }
