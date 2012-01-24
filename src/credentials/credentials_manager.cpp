/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/credentials_manager.h>

namespace Botan {

std::string Credentials_Manager::srp_identifier(const std::string&,
                                                const std::string&)
   {
   return "";
   }

std::string Credentials_Manager::srp_password(const std::string&,
                                              const std::string&,
                                              const std::string&)
   {
   return "";
   }

bool Credentials_Manager::srp_verifier(const std::string&,
                                       const std::string&,
                                       const std::string&,
                                       BigInt&,
                                       BigInt&,
                                       BigInt&,
                                       MemoryRegion<byte>&,
                                       bool)
   {
   return false;
   }

std::vector<X509_Certificate> Credentials_Manager::cert_chain(
   const std::vector<std::string>&,
   const std::string&,
   const std::string&)
   {
   return std::vector<X509_Certificate>();
   }

std::vector<X509_Certificate> Credentials_Manager::cert_chain_single_type(
   const std::string& cert_key_type,
   const std::string& type,
   const std::string& context)
   {
   std::vector<std::string> cert_types;
   cert_types.push_back(cert_key_type);
   return cert_chain(cert_types, type, context);
   }

Private_Key* Credentials_Manager::private_key_for(const X509_Certificate&,
                                                  const std::string&,
                                                  const std::string&)
   {
   return 0;
   }

std::vector<X509_Certificate>
Credentials_Manager::trusted_certificate_authorities(
   const std::string&,
   const std::string&)
   {
   return std::vector<X509_Certificate>();
   }

void Credentials_Manager::verify_certificate_chain(
   const std::vector<X509_Certificate>& cert_chain,
   const std::string& purported_hostname)
   {
   if(cert_chain.empty())
      throw std::invalid_argument("Certificate chain was empty");

#if 0
   X509_Store store;

   std::vector<X509_Certificate> CAs = trusted_certificate_authorities();

   for(size_t i = 1; i != CAs.size(); ++i)
      store.add_cert(CAs[i], true);
   for(size_t i = 1; i != cert_chain.size(); ++i)
      store.add_cert(cert_chain[i]);

   X509_Code result = store.validate_cert(cert_chain[0], TLS_SERVER);

   if(result != VERIFIED)
      throw std::runtime_error("Certificate did not validate");

   if(!cert_chain[0].matches_dns_name(purported_hostname))
      throw std::runtime_error("Certificate did not match hostname");

#endif
   }

}
