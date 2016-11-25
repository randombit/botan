/*
* Certificate Store
* (C) 1999-2010,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor.h>
#include <botan/internal/filesystem.h>
#include <botan/hash.h>

namespace Botan {

std::shared_ptr<const X509_CRL> Certificate_Store::find_crl_for(const X509_Certificate&) const
   {
   return std::shared_ptr<const X509_CRL>();
   }

void Certificate_Store_In_Memory::add_certificate(const X509_Certificate& cert)
   {
   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      if(*m_certs[i] == cert)
         return;
      }

   m_certs.push_back(std::make_shared<const X509_Certificate>(cert));
   }

void Certificate_Store_In_Memory::add_certificate(std::shared_ptr<const X509_Certificate> cert)
   {
   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      if(*m_certs[i] == *cert)
         return;
      }

   m_certs.push_back(cert);
   }

std::vector<X509_DN> Certificate_Store_In_Memory::all_subjects() const
   {
   std::vector<X509_DN> subjects;
   for(size_t i = 0; i != m_certs.size(); ++i)
      subjects.push_back(m_certs[i]->subject_dn());
   return subjects;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_In_Memory::find_cert(const X509_DN& subject_dn,
                                       const std::vector<byte>& key_id) const
   {
   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      // Only compare key ids if set in both call and in the cert
      if(key_id.size())
         {
         std::vector<byte> skid = m_certs[i]->subject_key_id();

         if(skid.size() && skid != key_id) // no match
            continue;
         }

      if(m_certs[i]->subject_dn() == subject_dn)
         return m_certs[i];
      }

   return std::shared_ptr<const X509_Certificate>();
   }


std::shared_ptr<const X509_Certificate>
Certificate_Store_In_Memory::find_cert_by_pubkey_sha1(const std::vector<byte>& key_hash) const
   {
   if(key_hash.size() != 20)
      throw Invalid_Argument("Certificate_Store_In_Memory::find_cert_by_pubkey_sha1 invalid hash");

   for(size_t i = 0; i != m_certs.size(); ++i)
      {
      const std::vector<byte> hash_i = m_certs[i]->subject_public_key_bitstring_sha1();
      if(key_hash == hash_i)
         {
         return m_certs[i];
         }
      }

   return nullptr;
   }

void Certificate_Store_In_Memory::add_crl(const X509_CRL& crl)
   {
   std::shared_ptr<const X509_CRL> crl_s = std::make_shared<const X509_CRL>(crl);
   return add_crl(crl_s);
   }

void Certificate_Store_In_Memory::add_crl(std::shared_ptr<const X509_CRL> crl)
   {
   X509_DN crl_issuer = crl->issuer_dn();

   for(size_t i = 0; i != m_crls.size(); ++i)
      {
      // Found an update of a previously existing one; replace it
      if(m_crls[i]->issuer_dn() == crl_issuer)
         {
         if(m_crls[i]->this_update() <= crl->this_update())
            m_crls[i] = crl;
         return;
         }
      }

   // Totally new CRL, add to the list
   m_crls.push_back(crl);
   }

std::shared_ptr<const X509_CRL> Certificate_Store_In_Memory::find_crl_for(const X509_Certificate& subject) const
   {
   const std::vector<byte>& key_id = subject.authority_key_id();

   for(size_t i = 0; i != m_crls.size(); ++i)
      {
      // Only compare key ids if set in both call and in the CRL
      if(key_id.size())
         {
         std::vector<byte> akid = m_crls[i]->authority_key_id();

         if(akid.size() && akid != key_id) // no match
            continue;
         }

      if(m_crls[i]->issuer_dn() == subject.issuer_dn())
         return m_crls[i];
      }

   return std::shared_ptr<const X509_CRL>();
   }

Certificate_Store_In_Memory::Certificate_Store_In_Memory(const X509_Certificate& cert)
   {
   add_certificate(cert);
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
Certificate_Store_In_Memory::Certificate_Store_In_Memory(const std::string& dir)
   {
   if(dir.empty())
      return;

   std::vector<std::string> maybe_certs = get_files_recursive(dir);
   for(auto&& cert_file : maybe_certs)
      {
      try
         {
         m_certs.push_back(std::make_shared<X509_Certificate>(cert_file));
         }
      catch(std::exception&)
         {
         }
      }
   }
#endif

}
