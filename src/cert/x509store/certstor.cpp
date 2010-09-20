/*
* Certificate Store
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/certstor.h>

namespace Botan {

Certificate_Store* Certificate_Store_Memory::clone() const
   {
   return new Certificate_Store_Memory(*this);
   }

void Certificate_Store_Memory::add_certificate(const X509_Certificate& cert)
   {
   for(size_t i = 0; i != certs.size(); ++i)
      {
      if(certs[i] == cert)
         return;
      }

   certs.push_back(cert);
   }

std::vector<X509_Certificate>
Certificate_Store_Memory::find_cert_by_subject_and_key_id(
   const X509_DN& subject_dn,
   const MemoryRegion<byte>& key_id) const
   {
   std::vector<X509_Certificate> result;

   for(size_t i = 0; i != certs.size(); ++i)
      {
      // Only compare key ids if set in both call and in the cert
      if(key_id.size())
         {
         MemoryVector<byte> skid = certs[i].subject_key_id();

         if(skid.size() && skid != key_id) // no match
            continue;
         }

      if(certs[i].subject_dn() == subject_dn)
         result.push_back(certs[i]);
      }

   return result;
   }

void Certificate_Store_Memory::add_crl(const X509_CRL& crl)
   {
   X509_DN crl_issuer = crl.issuer_dn();

   for(size_t i = 0; i != crls.size(); ++i)
      {
      // Found an update of a previously existing one; replace it
      if(crls[i].issuer_dn() == crl_issuer)
         {
         if(crls[i].this_update() < crl.this_update())
            {
            crls[i] = crl;
            return;
            }
         }
      }

   // Totally new CRL, add to the list
   crls.push_back(crl);
   }

std::vector<X509_CRL>
Certificate_Store_Memory::find_crl_by_subject_and_key_id(
   const X509_DN& issuer_dn,
   const MemoryRegion<byte>& key_id) const
   {
   std::vector<X509_CRL> result;

   for(size_t i = 0; i != crls.size(); ++i)
      {
      // Only compare key ids if set in both call and in the CRL
      if(key_id.size())
         {
         MemoryVector<byte> akid = crls[i].authority_key_id();

         if(akid.size() && akid != key_id) // no match
            continue;
         }

      if(crls[i].issuer_dn() == issuer_dn)
         result.push_back(crls[i]);
      }

   return result;
   }

}
