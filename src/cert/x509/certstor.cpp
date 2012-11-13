/*
* Certificate Store
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/certstor.h>

namespace Botan {

bool Certificate_Store::certificate_known(const X509_Certificate& cert) const
   {
   std::vector<X509_Certificate> found =
      find_cert_by_subject_and_key_id(cert.subject_dn(),
                                      cert.subject_key_id());

   return !found.empty();
   }

void Certificate_Store_In_Memory::add_certificate(const X509_Certificate& cert)
   {
   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      if(m_certs[i] == cert)
         return;
      }

   m_certs.push_back(cert);
   }

std::vector<X509_DN> Certificate_Store_In_Memory::all_subjects() const
   {
   std::vector<X509_DN> subjects;
   for(size_t i = 0; i != m_certs.size(); ++i)
      subjects.push_back(m_certs[i].subject_dn());
   return subjects;
   }

std::vector<X509_Certificate>
Certificate_Store_In_Memory::find_cert_by_subject_and_key_id(
   const X509_DN& subject_dn,
   const std::vector<byte>& key_id) const
   {
   std::vector<X509_Certificate> result;

   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      // Only compare key ids if set in both call and in the cert
      if(key_id.size())
         {
         std::vector<byte> skid = m_certs[i].subject_key_id();

         if(skid.size() && skid != key_id) // no match
            continue;
         }

      if(m_certs[i].subject_dn() == subject_dn)
         result.push_back(m_certs[i]);
      }

   return result;
   }

void Certificate_Store_In_Memory::add_crl(const X509_CRL& crl)
   {
   X509_DN crl_issuer = crl.issuer_dn();

   for(size_t i = 0; i != m_crls.size(); ++i)
      {
      // Found an update of a previously existing one; replace it
      if(m_crls[i].issuer_dn() == crl_issuer)
         {
         if(m_crls[i].this_update() <= crl.this_update())
            m_crls[i] = crl;
         return;
         }
      }

   // Totally new CRL, add to the list
   m_crls.push_back(crl);
   }

std::vector<X509_CRL>
Certificate_Store_In_Memory::find_crl_by_issuer_and_key_id(
   const X509_DN& issuer_dn,
   const std::vector<byte>& key_id) const
   {
   std::vector<X509_CRL> result;

   for(size_t i = 0; i != m_crls.size(); ++i)
      {
      // Only compare key ids if set in both call and in the CRL
      if(key_id.size())
         {
         std::vector<byte> akid = m_crls[i].authority_key_id();

         if(akid.size() && akid != key_id) // no match
            continue;
         }

      if(m_crls[i].issuer_dn() == issuer_dn)
         result.push_back(m_crls[i]);
      }

   return result;
   }

}
