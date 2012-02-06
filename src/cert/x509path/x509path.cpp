/*
* X.509 Certificate Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509path.h>
#include <botan/parsing.h>
#include <botan/pubkey.h>
#include <botan/oids.h>
#include <botan/time.h>
#include <algorithm>
#include <memory>

namespace Botan {

namespace {

class PKIX_Validation_Failure : public std::exception
   {
   public:
      PKIX_Validation_Failure(X509_Path_Validation_Code code) : m_code(code) {}

      X509_Path_Validation_Code code() const { return m_code; }

      const char* what() { return "PKIX validation failed"; }
   private:
      X509_Path_Validation_Code m_code;
   };

X509_Certificate find_issuing_cert(const X509_Certificate& cert,
                                   const std::vector<Certificate_Store*>& certstores)
   {
   const X509_DN issuer_dn = cert.issuer_dn();
   const MemoryVector<byte> auth_key_id = cert.authority_key_id();

   for(size_t i = 0; i != certstores.size(); ++i)
      {
      std::vector<X509_Certificate> certs =
         certstores[i]->find_cert_by_subject_and_key_id(issuer_dn, auth_key_id);

      if(certs.size() == 0)
         throw PKIX_Validation_Failure(CERT_ISSUER_NOT_FOUND);
      else if(certs.size() > 1)
         throw PKIX_Validation_Failure(CERT_MULTIPLE_ISSUERS_FOUND);

      return certs[0];
      }

   throw PKIX_Validation_Failure(CERT_ISSUER_NOT_FOUND);
   }

std::vector<X509_CRL> find_crls_from(const X509_Certificate& cert,
                                     const std::vector<Certificate_Store*>& certstores)
   {
   const X509_DN issuer_dn = cert.subject_dn();
   const MemoryVector<byte> auth_key_id = cert.subject_key_id();

   for(size_t i = 0; i != certstores.size(); ++i)
      {
      std::vector<X509_CRL> crl =
         certstores[i]->find_crl_by_issuer_and_key_id(issuer_dn, auth_key_id);

      if(!crl.empty())
         return crl;
      }

   return std::vector<X509_CRL>();
   }

}

std::set<std::string> Path_Validation_Result::trusted_hashes() const
   {
   std::set<std::string> hashes;
   for(size_t i = 0; i != cert_path.size(); ++i)
      hashes.insert(cert_path[i].hash_used_for_signature());
   return hashes;
   }

Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   const std::vector<Certificate_Store*>& certstores)
   {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);
   return x509_path_validate(certs, certstores);
   }

Path_Validation_Result x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   Certificate_Store& store)
   {
   std::vector<Certificate_Store*> certstores;
   certstores.push_back(&store);

   return x509_path_validate(end_certs, certstores);
   }

Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   Certificate_Store& store)
   {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);

   std::vector<Certificate_Store*> certstores;
   certstores.push_back(&store);

   return x509_path_validate(certs, certstores);
   }

Path_Validation_Result
x509_path_validate(const std::vector<X509_Certificate>& end_certs,
                   const std::vector<Certificate_Store*>& certstores)
   {
   Path_Validation_Result r;

   r.cert_path = end_certs;

   try
      {
      // iterate until we reach a root or cannot find the issuer

      while(!r.cert_path.back().is_self_signed())
         {
         X509_Certificate cert = find_issuing_cert(r.cert_path.back(),
                                                   certstores);

         r.cert_path.push_back(cert);
         }

      /*
      for(size_t i = 0; i != r.cert_path.size(); ++i)
         std::cout << "Cert " << i << " = " << r.cert_path[i].subject_dn() << "\n";
      */

      X509_Time current_time(system_time());

      for(size_t i = 0; i != r.cert_path.size(); ++i)
         {
         const X509_Certificate& subject = r.cert_path[i];

         // Check all certs for valid time range
         if(current_time < X509_Time(subject.start_time()))
            throw PKIX_Validation_Failure(CERT_NOT_YET_VALID);

         if(current_time > X509_Time(subject.end_time()))
            throw PKIX_Validation_Failure(CERT_HAS_EXPIRED);

         const bool at_self_signed_root = (i == r.cert_path.size() - 1);

         const X509_Certificate& issuer =
            r.cert_path[at_self_signed_root ? (i) : (i + 1)];

         // Check issuer constraints
         if(!issuer.is_CA_cert()) // require this for self-signed end-entity?
            throw PKIX_Validation_Failure(CA_CERT_NOT_FOR_CERT_ISSUER);

         if(issuer.path_limit() < i)
            throw PKIX_Validation_Failure(CERT_CHAIN_TOO_LONG);

         if(subject.check_signature(issuer.subject_public_key()) == false)
            throw PKIX_Validation_Failure(SIGNATURE_ERROR);
         }

      r.validation_result = VERIFIED;

      for(size_t i = 1; i != r.cert_path.size(); ++i)
         {
         const X509_Certificate& subject = r.cert_path[i-1];
         const X509_Certificate& ca = r.cert_path[i];

         std::vector<X509_CRL> crls = find_crls_from(ca, certstores);

         if(crls.empty())
            throw PKIX_Validation_Failure(CRL_NOT_FOUND);

         const X509_CRL& crl = crls[0];

         if(!ca.allowed_usage(CRL_SIGN))
            throw PKIX_Validation_Failure(CA_CERT_NOT_FOR_CRL_ISSUER);

         if(current_time < X509_Time(crl.this_update()))
            throw PKIX_Validation_Failure(CRL_NOT_YET_VALID);

         if(current_time > X509_Time(crl.next_update()))
            throw PKIX_Validation_Failure(CRL_HAS_EXPIRED);

         if(crl.check_signature(ca.subject_public_key()) == false)
            throw PKIX_Validation_Failure(SIGNATURE_ERROR);

         if(crl.is_revoked(subject))
            throw PKIX_Validation_Failure(CERT_IS_REVOKED);
         }

      }
   catch(PKIX_Validation_Failure& e)
      {
      r.validation_result = e.code();
      }

   return r;
   }

}
