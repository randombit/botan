
#ifndef EXAMPLE_CREDENTIALS_MANAGER_H__
#define EXAMPLE_CREDENTIALS_MANAGER_H__

#include <botan/credentials_manager.h>

bool value_exists(const std::vector<std::string>& vec,
                  const std::string& val)
   {
   for(size_t i = 0; i != vec.size(); ++i)
      if(vec[i] == val)
         return true;
   return false;
   }

class Credentials_Manager_Simple : public Botan::Credentials_Manager
   {
   public:
      Credentials_Manager_Simple(Botan::RandomNumberGenerator& rng) : rng(rng) {}

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string& context)
         {
         std::vector<Botan::X509_Certificate> certs;

         if(type == "tls-server")
            {
            const std::string hostname = (context == "" ? "localhost" : context);

            if(value_exists(cert_key_types, "RSA"))
               {
               Botan::X509_Certificate cert(hostname + ".crt");
               Botan::Private_Key* key = Botan::PKCS8::load_key(hostname + ".key", rng);

               certs_and_keys[cert] = key;
               certs.push_back(cert);
               }
            else if(value_exists(cert_key_types, "DSA"))
               {
               Botan::X509_Certificate cert(hostname + ".dsa.crt");
               Botan::Private_Key* key = Botan::PKCS8::load_key(hostname + ".dsa.key", rng);

               certs_and_keys[cert] = key;
               certs.push_back(cert);
               }
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
