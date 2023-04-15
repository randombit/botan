/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/credentials_manager.h>

#include <botan/pkix_types.h>

namespace Botan {

std::string Credentials_Manager::psk_identity_hint(const std::string& /*unused*/,
                                                   const std::string& /*unused*/)
   {
   return "";
   }

std::string Credentials_Manager::psk_identity(const std::string& /*unused*/,
                                              const std::string& /*unused*/,
                                              const std::string& /*unused*/)
   {
   return "";
   }

SymmetricKey Credentials_Manager::psk(const std::string& /*unused*/,
                                      const std::string& /*unused*/,
                                      const std::string& identity)
   {
   throw Internal_Error("No PSK set for identity " + identity);
   }

std::vector<X509_Certificate> Credentials_Manager::find_cert_chain(
   const std::vector<std::string>& key_types,
   const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
   const std::vector<X509_DN>& /*unused*/,
   const std::string& type,
   const std::string& context)
   {
   return cert_chain(key_types, cert_signature_schemes, type, context);
   }

std::vector<X509_Certificate> Credentials_Manager::cert_chain(
   const std::vector<std::string>& /*unused*/,
   const std::vector<AlgorithmIdentifier>& /*unused*/,
   const std::string& /*unused*/,
   const std::string& /*unused*/)
   {
   return std::vector<X509_Certificate>();
   }

std::vector<X509_Certificate> Credentials_Manager::cert_chain_single_type(
   const std::string& cert_key_type,
   const std::vector<AlgorithmIdentifier>& cert_signature_schemes,
   const std::string& type,
   const std::string& context)
   {
   return find_cert_chain({cert_key_type}, cert_signature_schemes, std::vector<X509_DN>(), type, context);
   }

std::shared_ptr<Private_Key>
Credentials_Manager::private_key_for(const X509_Certificate& /*unused*/,
                                     const std::string& /*unused*/,
                                     const std::string& /*unused*/)
   {
   return std::shared_ptr<Private_Key>();
   }

std::vector<Certificate_Store*>
Credentials_Manager::trusted_certificate_authorities(
   const std::string& /*unused*/,
   const std::string& /*unused*/)
   {
   return std::vector<Certificate_Store*>();
   }

}
