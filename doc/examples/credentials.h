
#ifndef EXAMPLE_CREDENTIALS_MANAGER_H__
#define EXAMPLE_CREDENTIALS_MANAGER_H__

#include <botan/credentials_manager.h>

class Credentials_Manager_Simple : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager_Simple(Botan::RandomNumberGenerator& rng) : rng(rng) {}

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::string& cert_key_type,
         const std::string& type,
         const std::string& context)
         {
         std::vector<Botan::X509_Certificate> certs;

         if(type == "tls-server")
            {
            const std::string hostname = (context == "" ? "localhost" : context);

            Botan::X509_Certificate cert(hostname + ".crt");
            Botan::Private_Key* key = Botan::PKCS8::load_key(hostname + ".key", rng);

            certs_and_keys[cert] = key;
            certs.push_back(cert);
            }
         else if(type == "tls-client")
            {
            Botan::X509_Certificate cert("user-rsa.crt");
            Botan::Private_Key* key = Botan::PKCS8::load_key("user-rsa.key", rng);

            certs_and_keys[cert] = key;
            certs.push_back(cert);
            }

         return certs;
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
                                          const std::string& type,
                                          const std::string& context)
         {
         return certs_and_keys[cert];
         }

   private:
      Botan::RandomNumberGenerator& rng;
      std::map<Botan::X509_Certificate, Botan::Private_Key*> certs_and_keys;
   };

#endif
