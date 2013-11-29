/*
* X.509 Certificate Path Validation
* (C) 2010,2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509path.h>
#include <botan/ocsp.h>
#include <botan/http_util.h>
#include <botan/parsing.h>
#include <botan/pubkey.h>
#include <botan/oids.h>
#include <algorithm>
#include <chrono>
#include <memory>
#include <iostream>

namespace Botan {

namespace {

const X509_Certificate* find_issuing_cert(const X509_Certificate& cert,
                                    const std::vector<Certificate_Store*>& certstores)
   {
   const X509_DN issuer_dn = cert.issuer_dn();
   const std::vector<byte> auth_key_id = cert.authority_key_id();

   for(size_t i = 0; i != certstores.size(); ++i)
      {
      if(const X509_Certificate* cert = certstores[i]->find_cert(issuer_dn, auth_key_id))
         return cert;
      }

   return nullptr;
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

#if 0
   const std::string crl_url = cert.crl_distribution_point();
   if(crl_url != "")
      {
      std::cout << "Downloading CRL " << crl_url << "\n";
      auto http = HTTP::GET_sync(crl_url);

      std::cout << http.status_message() << "\n";

      http.throw_unless_ok();
      // check the mime type

      std::unique_ptr<X509_CRL> crl(new X509_CRL(http.body()));

      return crl.release();
      }
#endif

   return nullptr;
   }

Certificate_Status_Code check_chain(const std::vector<X509_Certificate>& cert_path,
                                    const Path_Validation_Restrictions& restrictions,
                                    const std::vector<Certificate_Store*>& certstores)
   {
   const std::set<std::string>& trusted_hashes = restrictions.trusted_hashes();

   const bool self_signed_ee_cert = (cert_path.size() == 1);

   X509_Time current_time(std::chrono::system_clock::now());

   std::vector<std::future<OCSP::Response>> ocsp_responses;

   for(size_t i = 0; i != cert_path.size(); ++i)
      {
      const bool at_self_signed_root = (i == cert_path.size() - 1);

      const X509_Certificate& subject = cert_path[i];

      const X509_Certificate& issuer = cert_path[at_self_signed_root ? (i) : (i + 1)];

      const Certificate_Store* trusted = certstores[0]; // fixme

      if(i == 0 || restrictions.ocsp_all_intermediates())
         ocsp_responses.push_back(
            std::async(std::launch::async,
                       OCSP::online_check, issuer, subject, trusted));

      // Check all certs for valid time range
      if(current_time < X509_Time(subject.start_time()))
         return Certificate_Status_Code::CERT_NOT_YET_VALID;

      if(current_time > X509_Time(subject.end_time()))
         return Certificate_Status_Code::CERT_HAS_EXPIRED;

      // Check issuer constraints

      // Don't require CA bit set on self-signed end entity cert
      if(!issuer.is_CA_cert() && !self_signed_ee_cert)
         return Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER;

      if(issuer.path_limit() < i)
         return Certificate_Status_Code::CERT_CHAIN_TOO_LONG;

      std::unique_ptr<Public_Key> issuer_key(issuer.subject_public_key());

      if(subject.check_signature(*issuer_key) == false)
         return Certificate_Status_Code::SIGNATURE_ERROR;

      if(issuer_key->estimated_strength() < restrictions.minimum_key_strength())
         return Certificate_Status_Code::SIGNATURE_METHOD_TOO_WEAK;

      if(!trusted_hashes.empty() && !at_self_signed_root)
         if(!trusted_hashes.count(subject.hash_used_for_signature()))
            return Certificate_Status_Code::UNTRUSTED_HASH;
      }

   for(size_t i = 0; i != cert_path.size() - 1; ++i)
      {
      const X509_Certificate& subject = cert_path[i];
      const X509_Certificate& ca = cert_path[i+1];

      if(i < ocsp_responses.size())
         {
         try
            {
            OCSP::Response ocsp = ocsp_responses[i].get();

            auto status = ocsp.status_for(ca, subject);

            if(status == CERT_IS_REVOKED)
               return status;

            if(status == OCSP_RESPONSE_GOOD)
               {
               if(i == 0 && !restrictions.ocsp_all_intermediates())
                  return status; // return immediately to just OCSP end cert
               else
                  continue;
               }
            }
         catch(std::exception& e)
            {
            }
         }

      const X509_CRL* crl_p = find_crls_from(ca, certstores);

      if(!crl_p)
         {
         if(restrictions.require_revocation_information())
            return Certificate_Status_Code::NO_REVOCATION_DATA;
         std::cout << "No revocation information for " << subject.subject_dn() << "\n";
         continue;
         }

      const X509_CRL& crl = *crl_p;

      if(!ca.allowed_usage(CRL_SIGN))
         return Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER;

      if(current_time < X509_Time(crl.this_update()))
         return Certificate_Status_Code::CRL_NOT_YET_VALID;

      if(current_time > X509_Time(crl.next_update()))
         return Certificate_Status_Code::CRL_HAS_EXPIRED;

      if(crl.check_signature(ca.subject_public_key()) == false)
         return Certificate_Status_Code::SIGNATURE_ERROR;

      if(crl.is_revoked(subject))
         return Certificate_Status_Code::CERT_IS_REVOKED;
      }

   if(self_signed_ee_cert)
      return Certificate_Status_Code::CANNOT_ESTABLISH_TRUST;

   return Certificate_Status_Code::VERIFIED;
   }

}

Path_Validation_Result x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& certstores)
   {
   if(end_certs.empty())
      throw std::invalid_argument("x509_path_validate called with no subjects");

   std::vector<X509_Certificate> cert_path = end_certs;

   // iterate until we reach a root or cannot find the issuer
   while(!cert_path.back().is_self_signed())
      {
      const X509_Certificate* cert = find_issuing_cert(cert_path.back(), certstores);
      if(!cert)
         return Path_Validation_Result(Certificate_Status_Code::CERT_ISSUER_NOT_FOUND);
      cert_path.push_back(*cert);
      }

   Certificate_Status_Code res = check_chain(cert_path, restrictions, certstores);

   return Path_Validation_Result(res, std::move(cert_path));
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
                                                           size_t key_strength,
                                                           bool ocsp_all) :
   m_require_revocation_information(require_rev),
   m_ocsp_all_intermediates(ocsp_all),
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

bool Path_Validation_Result::successful_validation() const
   {
   if(status() == VERIFIED || status() == OCSP_RESPONSE_GOOD)
      return true;
   return false;
   }

std::string Path_Validation_Result::result_string() const
   {
   return status_string(m_status);
   }

std::string Path_Validation_Result::status_string(Certificate_Status_Code code)
   {
   switch(code)
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
      case NO_REVOCATION_DATA:
         return "No revocation data available";
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
   return "Unknown code " + std::to_string(code);
   }

}
