/*
* Credentials Manager
* (C) 2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/credentials_manager.h>

namespace Botan {

std::string Credentials_Manager::srp_identifier(const std::string& type,
                                                const std::string& context)
   {
   return "";
   }

std::string Credentials_Manager::srp_password(const std::string& identifier,
                                              const std::string& type,
                                              const std::string& context)
   {
   return "";
   }

bool Credentials_Manager::srp_verifier(const std::string& identifier,
                                       const std::string& type,
                                       const std::string& context,
                                       BigInt& group_prime,
                                       BigInt& group_generator,
                                       BigInt& verifier,
                                       MemoryRegion<byte>& salt)
   {
   return false;
   }

std::vector<X509_Certificate> Credentials_Manager::cert_chain(
   const std::string& cert_key_type,
   const std::string& type,
   const std::string& context)
   {
   return std::vector<X509_Certificate>();
   }

Private_Key* Credentials_Manager::private_key_for(const X509_Certificate& cert,
                                                  const std::string& type,
                                                  const std::string& context)
   {
   return 0;
   }

}
