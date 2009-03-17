#include <botan/botan.h>
#include <botan/pkcs8.h>
#include <botan/cms_dec.h>
using namespace Botan;

#include <iostream>
#include <memory>

int main(int argc, char* argv[])
   {
   if(argc != 2)
      {
      printf("Usage: %s <filename>\n", argv[0]);
      return 1;
      }

   Botan::LibraryInitializer init;

   try {
      AutoSeeded_RNG rng;

      X509_Certificate mycert("mycert.pem");
      PKCS8_PrivateKey* mykey = PKCS8::load_key("mykey.pem", rng, "cut");

      X509_Certificate yourcert("yourcert.pem");
      X509_Certificate cacert("cacert.pem");
      X509_Certificate int_ca("int_ca.pem");

      X509_Store store;
      store.add_cert(mycert);
      store.add_cert(yourcert);
      store.add_cert(cacert, true);
      store.add_cert(int_ca);

      DataSource_Stream message(argv[1]);

      User_Interface ui;

      CMS_Decoder decoder(message, store, ui, mykey);

      while(decoder.layer_type() != CMS_Decoder::DATA)
         {
         CMS_Decoder::Status status = decoder.layer_status();
         CMS_Decoder::Content_Type content = decoder.layer_type();

         if(status == CMS_Decoder::FAILURE)
            {
            std::cout << "Failure reading CMS data" << std::endl;
            break;
            }

         if(content == CMS_Decoder::DIGESTED)
            {
            std::cout << "Digested data, hash = " << decoder.layer_info()
                      << std::endl;
            std::cout << "Hash is "
                      << ((status == CMS_Decoder::GOOD) ? "good" : "bad")
                      << std::endl;
            }

         if(content == CMS_Decoder::SIGNED)
            {
            // how to handle multiple signers? they can all exist within a
            // single level...

            std::cout << "Signed by " << decoder.layer_info() << std::endl;
            //std::cout << "Sign time: " << decoder.xxx() << std::endl;
            std::cout << "Signature is ";
            if(status == CMS_Decoder::GOOD)
               std::cout << "valid";
            else if(status == CMS_Decoder::BAD)
               std::cout << "bad";
            else if(status == CMS_Decoder::NO_KEY)
               std::cout << "(cannot check, no known cert)";
            std::cout << std::endl;
            }
         if(content == CMS_Decoder::ENVELOPED ||
            content == CMS_Decoder::COMPRESSED ||
            content == CMS_Decoder::AUTHENTICATED)
            {
            if(content == CMS_Decoder::ENVELOPED)
               std::cout << "Enveloped";
            if(content == CMS_Decoder::COMPRESSED)
               std::cout << "Compressed";
            if(content == CMS_Decoder::AUTHENTICATED)
               std::cout << "MACed";

            std::cout << ", algo = " << decoder.layer_info() << std::endl;

            if(content == CMS_Decoder::AUTHENTICATED)
               {
               std::cout << "MAC status is ";
               if(status == CMS_Decoder::GOOD)
                  std::cout << "valid";
               else if(status == CMS_Decoder::BAD)
                  std::cout << "bad";
               else if(status == CMS_Decoder::NO_KEY)
                  std::cout << "(cannot check, no key)";
               std::cout << std::endl;
               }
            }
         decoder.next_layer();
         }

      if(decoder.layer_type() == CMS_Decoder::DATA)
         std::cout << "Message is \"" << decoder.get_data()
                   << '"' << std::endl;
      else
         std::cout << "No data anywhere?" << std::endl;
   }
   catch(std::exception& e)
      {
      std::cerr << e.what() << std::endl;
      }
   return 0;
   }
