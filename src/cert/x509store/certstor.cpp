/*
* Certificate Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/certstor.h>

namespace Botan {

void Certificate_Store_Memory::add_certificate(const X509_Certificate& cert)
   {
   certs.push_back(cert);
   }

Certificate_Store* Certificate_Store_Memory::clone() const
   {
   return new Certificate_Store_Memory(*this);
   }

std::vector<X509_Certificate>
Certificate_Store_Memory::find_by_subject_and_key_id(
   const X509_DN& subject_dn,
   const MemoryRegion<byte>& key_id)
   {
   std::vector<X509_Certificate> result;

   for(size_t i = 0; i != certs.size(); ++i)
      {
      MemoryVector<byte> skid = certs[i].subject_key_id();

      if(key_id.size() && skid.size() && skid != key_id)
         continue;

      if(certs[i].subject_dn() == subject_dn)
         result.push_back(certs[i]);
      }

   return result;
   }

}
