#include <botan/pkcs8.h>
#include <botan/hex.h>
#include <botan/pk_keys.h>
#include <botan/pubkey.h>
#include <botan/auto_rng.h>
#include <botan/rng.h>

#include <iostream>

int main (int argc, char* argv[])
   {
   if(argc!=2)
      return 1;
   std::string plaintext("Your great-grandfather gave this watch to your granddad for good luck. Unfortunately, Dane's luck wasn't as good as his old man's.");
   std::vector<uint8_t> pt(plaintext.data(),plaintext.data()+plaintext.length());
   std::unique_ptr<Botan::RandomNumberGenerator> rng(new Botan::AutoSeeded_RNG);

   //load keypair
   Botan::DataSource_Stream in(argv[1]);
   std::unique_ptr<Botan::Private_Key> kp(Botan::PKCS8::load_key(in));

   //encrypt with pk
   Botan::PK_Encryptor_EME enc(*kp,*rng.get(), "EME1(SHA-256)");
   std::vector<uint8_t> ct = enc.encrypt(pt,*rng.get());

   //decrypt with sk
   Botan::PK_Decryptor_EME dec(*kp,*rng.get(), "EME1(SHA-256)");
   std::cout << std::endl << "enc: " << Botan::hex_encode(ct) << std::endl << "dec: "<< Botan::hex_encode(dec.decrypt(ct));

   return 0;
   }
