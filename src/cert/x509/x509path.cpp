/*
* X.509 Certificate Path Validation
* (C) 2010,2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509path.h>
#include <botan/parsing.h>
#include <botan/pubkey.h>
#include <botan/oids.h>
#include <algorithm>
#include <chrono>
#include <memory>

namespace Botan {

namespace {

class PKIX_Validation_Failure : public std::exception
   {
   public:
      PKIX_Validation_Failure(Certificate_Status_Code code) : m_code(code) {}

      Certificate_Status_Code code() const { return m_code; }

      const char* what() const noexcept { return "PKIX validation failed"; }
   private:
      Certificate_Status_Code m_code;
   };

X509_Certificate find_issuing_cert(const X509_Certificate& cert,
                                   const std::vector<Certificate_Store*>& certstores)
   {
   const X509_DN issuer_dn = cert.issuer_dn();
   const std::vector<byte> auth_key_id = cert.authority_key_id();

   for(size_t i = 0; i != certstores.size(); ++i)
      {
      if(const X509_Certificate* cert = certstores[i]->find_cert(issuer_dn, auth_key_id))
         return *cert;
      }

   throw PKIX_Validation_Failure(Certificate_Status_Code::CERT_ISSUER_NOT_FOUND);
   }

const X509_CRL* find_crls_from(const X509_Certificate& cert,
                         const std::vector<Certificate_Store*>& certstores)
   {
   const X509_DN issuer_dn = cert.subject_dn();
   const std::vector<byte> auth_key_id = cert.subject_key_id();

   for(size_t i = 0; i != certstores.size(); ++i)
      {
      if(const X509_CRL* crl = certstores[i]->find_crl(cert))
         return crl;
      }

   return nullptr;
   }

}

Path_Validation_Result x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& certstores)
   {
   if(end_certs.empty())
      throw std::invalid_argument("x509_path_validate called with no subjects");

   Path_Validation_Result r;

   r.m_cert_path = end_certs;

   std::vector<X509_Certificate>& cert_path = r.m_cert_path;

   const std::set<std::string>& trusted_hashes = restrictions.trusted_hashes();

   try
      {
      // iterate until we reach a root or cannot find the issuer
      while(!cert_path.back().is_self_signed())
         {
         cert_path.push_back(
            find_issuing_cert(cert_path.back(), certstores)
            );
         }

      const bool self_signed_ee_cert = (cert_path.size() == 1);

      X509_Time current_time(std::chrono::system_clock::now());

      for(size_t i = 0; i != cert_path.size(); ++i)
         {
         const X509_Certificate& subject = cert_path[i];

         // Check all certs for valid time range
         if(current_time < X509_Time(subject.start_time()))
            throw PKIX_Validation_Failure(Certificate_Status_Code::CERT_NOT_YET_VALID);

         if(current_time > X509_Time(subject.end_time()))
            throw PKIX_Validation_Failure(Certificate_Status_Code::CERT_HAS_EXPIRED);

         const bool at_self_signed_root = (i == cert_path.size() - 1);

         const X509_Certificate& issuer =
            cert_path[at_self_signed_root ? (i) : (i + 1)];

         // Check issuer constraints

         // Don't require CA bit set on self-signed end entity cert
         if(!issuer.is_CA_cert() && !self_signed_ee_cert)
            throw PKIX_Validation_Failure(Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER);

         if(issuer.path_limit() < i)
            throw PKIX_Validation_Failure(Certificate_Status_Code::CERT_CHAIN_TOO_LONG);

         std::unique_ptr<Public_Key> issuer_key(issuer.subject_public_key());

         if(subject.check_signature(*issuer_key) == false)
            throw PKIX_Validation_Failure(Certificate_Status_Code::SIGNATURE_ERROR);

         if(issuer_key->estimated_strength() < restrictions.minimum_key_strength())
            throw PKIX_Validation_Failure(Certificate_Status_Code::SIGNATURE_METHOD_TOO_WEAK);

         if(!trusted_hashes.empty() && !at_self_signed_root)
            if(!trusted_hashes.count(subject.hash_used_for_signature()))
               throw PKIX_Validation_Failure(Certificate_Status_Code::UNTRUSTED_HASH);
         }

      for(size_t i = 1; i != cert_path.size(); ++i)
         {
         const X509_Certificate& subject = cert_path[i-1];
         const X509_Certificate& ca = cert_path[i];

         const X509_CRL* crl_p = find_crls_from(ca, certstores);

         if(!crl_p)
            {
            if(restrictions.require_revocation_information())
               throw PKIX_Validation_Failure(Certificate_Status_Code::CRL_NOT_FOUND);
            continue;
            }

         const X509_CRL& crl = *crl_p;

         if(!ca.allowed_usage(CRL_SIGN))
            throw PKIX_Validation_Failure(Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER);

         if(current_time < X509_Time(crl.this_update()))
            throw PKIX_Validation_Failure(Certificate_Status_Code::CRL_NOT_YET_VALID);

         if(current_time > X509_Time(crl.next_update()))
            throw PKIX_Validation_Failure(Certificate_Status_Code::CRL_HAS_EXPIRED);

         if(crl.check_signature(ca.subject_public_key()) == false)
            throw PKIX_Validation_Failure(Certificate_Status_Code::SIGNATURE_ERROR);

         if(crl.is_revoked(subject))
            throw PKIX_Validation_Failure(Certificate_Status_Code::CERT_IS_REVOKED);
         }

      r.set_result(self_signed_ee_cert ?
                   Certificate_Status_Code::CANNOT_ESTABLISH_TRUST :
                   Certificate_Status_Code::VERIFIED);
      }
   catch(PKIX_Validation_Failure& e)
      {
      r.set_result(e.code());
      }

   return r;
   }

Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& certstores)
   {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);
   return x509_path_validate(certs, restrictions, certstores);
   }

Path_Validation_Result x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store)
   {
   std::vector<Certificate_Store*> certstores;
   certstores.push_back(const_cast<Certificate_Store*>(&store));

   return x509_path_validate(end_certs, restrictions, certstores);
   }

Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store)
   {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);

   std::vector<Certificate_Store*> certstores;
   certstores.push_back(const_cast<Certificate_Store*>(&store));

   return x509_path_validate(certs, restrictions, certstores);
   }

Path_Validation_Restrictions::Path_Validation_Restrictions(bool require_rev,
                                                           size_t key_strength) :
   m_require_revocation_information(require_rev),
   m_minimum_key_strength(key_strength)
   {
   if(key_strength <= 80)
      m_trusted_hashes.insert("SHA-160");

   m_trusted_hashes.insert("SHA-224");
   m_trusted_hashes.insert("SHA-256");
   m_trusted_hashes.insert("SHA-384");
   m_trusted_hashes.insert("SHA-512");
   }

const X509_Certificate& Path_Validation_Result::trust_root() const
   {
   return m_cert_path[m_cert_path.size()-1];
   }

std::set<std::string> Path_Validation_Result::trusted_hashes() const
   {
   std::set<std::string> hashes;
   for(size_t i = 0; i != m_cert_path.size(); ++i)
      hashes.insert(m_cert_path[i].hash_used_for_signature());
   return hashes;
   }

std::string Path_Validation_Result::result_string() const
   {
   switch(m_result)
      {
      case VERIFIED:
         return "verified";
      case UNKNOWN_X509_ERROR:
         return "unknown error";
      case CANNOT_ESTABLISH_TRUST:
         return "cannot establish trust";
      case CERT_CHAIN_TOO_LONG:
         return "certificate chain too long";
      case SIGNATURE_ERROR:
         return "signature error";
      case SIGNATURE_METHOD_TOO_WEAK:
         return "signature method too weak";

      case POLICY_ERROR:
         return "policy error";
      case INVALID_USAGE:
         return "invalid usage";
      case UNTRUSTED_HASH:
         return "untrusted hash function";

      case CERT_MULTIPLE_ISSUERS_FOUND:
         return "Multiple certificate issuers found";
      case CERT_FORMAT_ERROR:
         return "Certificate format error";
      case CERT_ISSUER_NOT_FOUND:
         return "Certificate issuer not found";
      case CERT_NOT_YET_VALID:
         return "Certificate is not yet valid";
      case CERT_HAS_EXPIRED:
         return "Certificate has expired";
      case CERT_IS_REVOKED:
         return "Certificate is revoked";
      case CRL_NOT_FOUND:
         return "CRL not found";
      case CRL_FORMAT_ERROR:
         return "CRL format error";
      case CRL_NOT_YET_VALID:
         return "CRL is not yet valid";
      case CRL_HAS_EXPIRED:
         return "CRL has expired";
      case CA_CERT_CANNOT_SIGN:
         return "CA certificate cannot sign";
      case CA_CERT_NOT_FOR_CERT_ISSUER:
         return "CA certificate not allowed to issue certs";
      case CA_CERT_NOT_FOR_CRL_ISSUER:
         return "CA certificate not allowed to issue CRLs";

      case OCSP_CERT_NOT_LISTED:
         return "OCSP response does not included requested cert";
      case OCSP_NOT_YET_VALID:
         return "OCSP response is from the future";
      case OCSP_EXPIRED:
         return "OCSP response is expired";
      case OCSP_BAD_STATUS:
         return "OCSP response had unknown/bad status";
      case OCSP_RESPONSE_GOOD:
         return "OCSP response had good status";
      }

   // default case
   return "Unknown code " + std::to_string(m_result);
   }

}
