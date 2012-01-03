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
   const std::string&,
   const std::string&,
   const std::string&)
   {
   return std::vector<X509_Certificate>();
   }

Private_Key* Credentials_Manager::private_key_for(const X509_Certificate&,
                                                  const std::string&,
                                                  const std::string&)
   {
   return 0;
   }

}
