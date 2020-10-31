/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/credentials_manager.h>
#include <botan/pkix_types.h>

namespace Botan {

std::string Credentials_Manager::psk_identity_hint(const std::string&,
                                                   const std::string&)
   {
   return "";
   }

std::string Credentials_Manager::psk_identity(const std::string&,
                                              const std::string&,
                                              const std::string&)
   {
   return "";
   }

SymmetricKey Credentials_Manager::psk(const std::string&,
                                      const std::string&,
                                      const std::string& identity)
   {
   throw Internal_Error("No PSK set for identity " + identity);
   }

bool Credentials_Manager::attempt_srp(const std::string&,
                                      const std::string&)
   {
   return false;
   }

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
                                       std::string&,
                                       BigInt&,
                                       std::vector<uint8_t>&,
                                       bool)
   {
   return false;
   }

std::vector<X509_Certificate> Credentials_Manager::find_cert_chain(
   const std::vector<std::string>& key_types,
   const std::vector<X509_DN>&,
   const std::string& type,
   const std::string& context)
   {
   return cert_chain(key_types, type, context);
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
   return find_cert_chain(cert_types, std::vector<X509_DN>(), type, context);
   }

Private_Key* Credentials_Manager::private_key_for(const X509_Certificate&,
                                                  const std::string&,
                                                  const std::string&)
   {
   return nullptr;
   }

std::vector<Certificate_Store*>
Credentials_Manager::trusted_certificate_authorities(
   const std::string&,
   const std::string&)
   {
   return std::vector<Certificate_Store*>();
   }

}
