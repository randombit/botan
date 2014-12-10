
#ifndef EXAMPLE_CREDENTIALS_MANAGER_H__
#define EXAMPLE_CREDENTIALS_MANAGER_H__

#include <botan/credentials_manager.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/srp6.h>
#include <botan/srp6_files.h>
#include <botan/ecdsa.h>
#include <iostream>
#include <fstream>
#include <memory>

inline bool value_exists(const std::vector<std::string>& vec,
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
      Credentials_Manager_Simple(Botan::RandomNumberGenerator& rng) :
         rng(rng)
         {
         try
            {
            m_certstores.push_back(new Botan::Certificate_Store_In_Memory("/usr/share/ca-certificates"));
            }
         catch(...) {}
         }

      std::string srp_identifier(const std::string& type,
                                 const std::string& hostname)
         {
         if(type == "tls-client" && hostname == "srp-host")
            return "user";
         return "";
         }

      bool attempt_srp(const std::string& type,
                       const std::string& hostname)
         {
         if(hostname == "srp-host" && (type == "tls-client" || type == "tls-server"))
            return true;
         return false;
         }

      std::vector<Botan::Certificate_Store*>
      trusted_certificate_authorities(const std::string& type,
                                      const std::string& /*hostname*/)
         {
         // don't ask for client cert
         if(type == "tls-server")
            return std::vector<Botan::Certificate_Store*>();

         return m_certstores;
         }

      void verify_certificate_chain(
         const std::string& type,
         const std::string& purported_hostname,
         const std::vector<Botan::X509_Certificate>& cert_chain)
         {
         try
            {
            Botan::Credentials_Manager::verify_certificate_chain(type,
                                                                 purported_hostname,
                                                                 cert_chain);
            }
         catch(std::exception& e)
            {
            std::cout << "Certificate verification failed - " << e.what() << " - but will ignore\n";
            }
         }

      std::string srp_password(const std::string& type,
                               const std::string& hostname,
                               const std::string& identifier)
         {
         if(type == "tls-client" && hostname == "srp-host" && identifier == "user")
            return "password";

         return "";
         }

      bool srp_verifier(const std::string& /*type*/,
                        const std::string& context,
                        const std::string& identifier,
                        std::string& group_id,
                        Botan::BigInt& verifier,
                        std::vector<Botan::byte>& salt,
                        bool generate_fake_on_unknown)
         {

         std::string pass = srp_password("tls-client", context, identifier);
         if(pass == "")
            {
            if(!generate_fake_on_unknown)
               return false;

            pass.resize(16);
            rng.randomize(reinterpret_cast<byte*>(&pass[0]), pass.size());
            }

         group_id = "modp/srp/2048";

         salt.resize(16);
         rng.randomize(&salt[0], salt.size());

         verifier = Botan::generate_srp6_verifier(identifier,
                                                  pass,
                                                  salt,
                                                  group_id,
                                                  "SHA-1");

         return true;
         }

      std::string psk_identity_hint(const std::string&,
                                    const std::string&)
         {
         return "";
         }

      std::string psk_identity(const std::string&, const std::string&,
                               const std::string& identity_hint)
         {
         std::cout << "Server sent PSK identity_hint " << identity_hint << "\n";
         return "Client_identity";
         }

      Botan::SymmetricKey psk(const std::string& type, const std::string& context,
                              const std::string& identity)
         {
         if(type == "tls-server" && context == "session-ticket")
            {
            if(session_ticket_key.length() == 0)
               session_ticket_key = Botan::SymmetricKey(rng, 32);
            return session_ticket_key;
            }

         if(identity == "Client_identity")
            return Botan::SymmetricKey("b5a72e1387552e6dc10766dc0eda12961f5b21e17f98ef4c41e6572e53bd7527");
         if(identity == "lloyd")
            return Botan::SymmetricKey("85b3c1b7dc62b507636ac767999c9630");

         throw Botan::Internal_Error("No PSK set for " + identity);
         }

      std::pair<Botan::X509_Certificate,Botan::Private_Key*>
      load_or_make_cert(const std::string& hostname,
                        const std::string& key_type,
                        Botan::RandomNumberGenerator& rng)
         {
         using namespace Botan;

         const std::string key_fsname_prefix = hostname + "." + key_type + ".";
         const std::string key_file_name = key_fsname_prefix + "key";
         const std::string cert_file_name = key_fsname_prefix + "crt";

         try
            {
            X509_Certificate cert(cert_file_name);
            Private_Key* key = PKCS8::load_key(key_file_name, rng);

            //std::cout << "Loaded existing key/cert from " << cert_file_name << " and " << key_file_name << "\n";

            return std::make_pair(cert, key);
            }
         catch(...) {}

         // Failed. Instead, make a new one

         std::cout << "Creating new certificate for identifier '" << hostname << "'\n";

         X509_Cert_Options opts;

         opts.common_name = hostname;
         opts.country = "US";
         opts.email = "root@" + hostname;
         opts.dns = hostname;

         std::unique_ptr<Private_Key> key;
         if(key_type == "rsa")
            key.reset(new RSA_PrivateKey(rng, 1024));
         else if(key_type == "dsa")
            key.reset(new DSA_PrivateKey(rng, DL_Group("dsa/jce/1024")));
         else if(key_type == "ecdsa")
            key.reset(new ECDSA_PrivateKey(rng, EC_Group("secp256r1")));
         else
            throw std::runtime_error("Don't know what to do about key type '" + key_type + "'");

         X509_Certificate cert =
            X509::create_self_signed_cert(opts, *key, "SHA-1", rng);

         // Now save both

         std::cout << "Saving new " << key_type << " key to " << key_file_name << "\n";
         std::ofstream key_file(key_file_name.c_str());
         key_file << PKCS8::PEM_encode(*key, rng, "");
         key_file.close();

         std::cout << "Saving new " << key_type << " cert to " << key_file_name << "\n";
         std::ofstream cert_file(cert_file_name.c_str());
         cert_file << cert.PEM_encode() << "\n";
         cert_file.close();

         return std::make_pair(cert, key.release());
         }

      std::vector<Botan::X509_Certificate> cert_chain(
         const std::vector<std::string>& cert_key_types,
         const std::string& type,
         const std::string& context)
         {
         using namespace Botan;

         std::vector<X509_Certificate> certs;

         try
            {
            if(type == "tls-server")
               {
               const std::string hostname = (context == "" ? "localhost" : context);

               if(hostname == "nosuchname")
                  return std::vector<Botan::X509_Certificate>();

               for(auto i : certs_and_keys)
                  {
                  if(hostname != "" && !i.first.matches_dns_name(hostname))
                     continue;

                  if(!value_exists(cert_key_types, i.second->algo_name()))
                     continue;

                  certs.push_back(i.first);
                  }

               if(!certs.empty())
                  return certs;

               std::string key_name = "";

               if(value_exists(cert_key_types, "RSA"))
                  key_name = "rsa";
               else if(value_exists(cert_key_types, "DSA"))
                  key_name = "dsa";
               else if(value_exists(cert_key_types, "ECDSA"))
                  key_name = "ecdsa";

               std::pair<X509_Certificate, Private_Key*> cert_and_key =
                  load_or_make_cert(hostname, key_name, rng);

               certs_and_keys[cert_and_key.first] = cert_and_key.second;
               certs.push_back(cert_and_key.first);
               }
            else if(type == "tls-client")
               {
               X509_Certificate cert("user-rsa.crt");
               Private_Key* key = PKCS8::load_key("user-rsa.key", rng);

               certs_and_keys[cert] = key;
               certs.push_back(cert);
               }
            }
         catch(std::exception& e)
            {
            std::cout << e.what() << "\n";
            }

         return certs;
         }

      Botan::Private_Key* private_key_for(const Botan::X509_Certificate& cert,
                                          const std::string& /*type*/,
                                          const std::string& /*context*/)
         {
         return certs_and_keys[cert];
         }

   private:
      Botan::RandomNumberGenerator& rng;

      Botan::SymmetricKey session_ticket_key;

      std::map<Botan::X509_Certificate, Botan::Private_Key*> certs_and_keys;

      std::vector<Botan::Certificate_Store*> m_certstores;
   };

#endif
