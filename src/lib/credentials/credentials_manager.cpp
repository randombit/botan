/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/credentials_manager.h>
#include <botan/x509path.h>

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
                                       std::vector<byte>&,
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
   return nullptr;
   }

std::vector<Certificate_Store*>
Credentials_Manager::trusted_certificate_authorities(
   const std::string&,
   const std::string&)
   {
   return std::vector<Certificate_Store*>();
   }

namespace {

bool cert_in_some_store(const std::vector<Certificate_Store*>& trusted_CAs,
                        const X509_Certificate& trust_root)
   {
   for(auto CAs : trusted_CAs)
      if(CAs->certificate_known(trust_root))
         return true;
   return false;
   }

}

void Credentials_Manager::verify_certificate_chain(
   const std::string& type,
   const std::string& purported_hostname,
   const std::vector<X509_Certificate>& cert_chain)
   {
   if(cert_chain.empty())
      throw std::invalid_argument("Certificate chain was empty");

   auto trusted_CAs = trusted_certificate_authorities(type, purported_hostname);

   Path_Validation_Restrictions restrictions;

   auto result = x509_path_validate(cert_chain,
                                    restrictions,
                                    trusted_CAs);

   if(!result.successful_validation())
      throw std::runtime_error("Certificate validation failure: " + result.result_string());

   if(!cert_in_some_store(trusted_CAs, result.trust_root()))
      throw std::runtime_error("Certificate chain roots in unknown/untrusted CA");

   if(purported_hostname != "" && !cert_chain[0].matches_dns_name(purported_hostname))
      throw std::runtime_error("Certificate did not match hostname");
   }

}
