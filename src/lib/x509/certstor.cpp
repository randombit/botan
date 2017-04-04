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
   return {};
   }

void Certificate_Store_In_Memory::add_certificate(const X509_Certificate& cert)
   {
   for(const auto& c : m_certs)
      if(*c == cert)
         return;

   m_certs.push_back(std::make_shared<const X509_Certificate>(cert));
   }

void Certificate_Store_In_Memory::add_certificate(std::shared_ptr<const X509_Certificate> cert)
   {
   for(const auto& c : m_certs)
      if(*c == *cert)
         return;

   m_certs.push_back(cert);
   }

std::vector<X509_DN> Certificate_Store_In_Memory::all_subjects() const
   {
   std::vector<X509_DN> subjects;
   for(const auto& cert : m_certs)
      subjects.push_back(cert->subject_dn());
   return subjects;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_In_Memory::find_cert(const X509_DN& subject_dn,
                                       const std::vector<uint8_t>& key_id) const
   {
   for(const auto& cert : m_certs)
      {
      // Only compare key ids if set in both call and in the cert
      if(key_id.size())
         {
         std::vector<uint8_t> skid = cert->subject_key_id();

         if(skid.size() && skid != key_id) // no match
            continue;
         }

      if(cert->subject_dn() == subject_dn)
         return cert;
      }

   return nullptr;
   }


std::shared_ptr<const X509_Certificate>
Certificate_Store_In_Memory::find_cert_by_pubkey_sha1(const std::vector<uint8_t>& key_hash) const
   {
   if(key_hash.size() != 20)
      throw Invalid_Argument("Certificate_Store_In_Memory::find_cert_by_pubkey_sha1 invalid hash");

   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-1"));

   for(const auto& cert : m_certs){
      hash->update(cert->subject_public_key_bitstring());
      if(key_hash == hash->final_stdvec()) //final_stdvec also clears the hash to initial state
         return cert;
   }

   return nullptr;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_In_Memory::find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const
   {
   if(subject_hash.size() != 32)
      throw Invalid_Argument("Certificate_Store_In_Memory::find_cert_by_raw_subject_dn_sha256 invalid hash");

   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-256"));

   for(const auto& cert : m_certs){
      hash->update(cert->raw_subject_dn());
      if(subject_hash == hash->final_stdvec()) //final_stdvec also clears the hash to initial state
         return cert;
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

   for(auto& c : m_crls)
      {
      // Found an update of a previously existing one; replace it
      if(c->issuer_dn() == crl_issuer)
         {
         if(c->this_update() <= crl->this_update())
            c = crl;
         return;
         }
      }

   // Totally new CRL, add to the list
   m_crls.push_back(crl);
   }

std::shared_ptr<const X509_CRL> Certificate_Store_In_Memory::find_crl_for(const X509_Certificate& subject) const
   {
   const std::vector<uint8_t>& key_id = subject.authority_key_id();

   for(const auto& c : m_crls)
      {
      // Only compare key ids if set in both call and in the CRL
      if(key_id.size())
         {
         std::vector<uint8_t> akid = c->authority_key_id();

         if(akid.size() && akid != key_id) // no match
            continue;
         }

      if(c->issuer_dn() == subject.issuer_dn())
         return c;
      }

   return {};
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
