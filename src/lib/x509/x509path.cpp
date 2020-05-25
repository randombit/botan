/*
* X.509 Certificate Path Validation
* (C) 2010,2011,2012,2014,2016 Jack Lloyd
* (C) 2017 Fabian Weissberg, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509path.h>
#include <botan/x509_ext.h>
#include <botan/pk_keys.h>
#include <botan/ocsp.h>
#include <botan/oids.h>
#include <algorithm>
#include <chrono>
#include <vector>
#include <set>
#include <string>
#include <sstream>

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)
  #include <future>
  #include <botan/http_util.h>
#endif

namespace Botan {

/*
* PKIX path validation
*/
CertificatePathStatusCodes
PKIX::check_chain(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                  std::chrono::system_clock::time_point ref_time,
                  const std::string& hostname,
                  Usage_Type usage,
                  size_t min_signature_algo_strength,
                  const std::set<std::string>& trusted_hashes)
   {
   if(cert_path.empty())
      throw Invalid_Argument("PKIX::check_chain cert_path empty");

   const bool self_signed_ee_cert = (cert_path.size() == 1);

   X509_Time validation_time(ref_time);

   CertificatePathStatusCodes cert_status(cert_path.size());

   if(!hostname.empty() && !cert_path[0]->matches_dns_name(hostname))
      cert_status[0].insert(Certificate_Status_Code::CERT_NAME_NOMATCH);

   if(!cert_path[0]->allowed_usage(usage))
      cert_status[0].insert(Certificate_Status_Code::INVALID_USAGE);

   if(cert_path[0]->is_CA_cert() == false &&
      cert_path[0]->has_constraints(KEY_CERT_SIGN))
      {
      /*
      "If the keyCertSign bit is asserted, then the cA bit in the
      basic constraints extension (Section 4.2.1.9) MUST also be
      asserted." - RFC 5280

      We don't bother doing this check on the rest of the path since they
      must have the cA bit asserted or the validation will fail anyway.
      */
      cert_status[0].insert(Certificate_Status_Code::INVALID_USAGE);
      }

   for(size_t i = 0; i != cert_path.size(); ++i)
      {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);

      const bool at_self_signed_root = (i == cert_path.size() - 1);

      const std::shared_ptr<const X509_Certificate>& subject = cert_path[i];

      const std::shared_ptr<const X509_Certificate>& issuer = cert_path[at_self_signed_root ? (i) : (i + 1)];

      if(at_self_signed_root && (issuer->is_self_signed() == false))
         {
         status.insert(Certificate_Status_Code::CHAIN_LACKS_TRUST_ROOT);
         }

      if(subject->issuer_dn() != issuer->subject_dn())
         {
         status.insert(Certificate_Status_Code::CHAIN_NAME_MISMATCH);
         }

      // Check the serial number
      if(subject->is_serial_negative())
         {
         status.insert(Certificate_Status_Code::CERT_SERIAL_NEGATIVE);
         }

      // Check the subject's DN components' length

      for(const auto& dn_pair : subject->subject_dn().dn_info())
         {
         const size_t dn_ub = X509_DN::lookup_ub(dn_pair.first);
         // dn_pair = <OID,str>
         if(dn_ub > 0 && dn_pair.second.size() > dn_ub)
            {
            status.insert(Certificate_Status_Code::DN_TOO_LONG);
            }
         }

      // Check all certs for valid time range
      if(validation_time < subject->not_before())
         status.insert(Certificate_Status_Code::CERT_NOT_YET_VALID);

      if(validation_time > subject->not_after())
         status.insert(Certificate_Status_Code::CERT_HAS_EXPIRED);

      // Check issuer constraints
      if(!issuer->is_CA_cert() && !self_signed_ee_cert)
         status.insert(Certificate_Status_Code::CA_CERT_NOT_FOR_CERT_ISSUER);

      std::unique_ptr<Public_Key> issuer_key(issuer->subject_public_key());

      // Check the signature algorithm is known
      if(OIDS::oid2str_or_empty(subject->signature_algorithm().get_oid()).empty())
         {
         status.insert(Certificate_Status_Code::SIGNATURE_ALGO_UNKNOWN);
         }
      else
         {
         // only perform the following checks if the signature algorithm is known
         if(!issuer_key)
            {
            status.insert(Certificate_Status_Code::CERT_PUBKEY_INVALID);
            }
         else
            {
            const Certificate_Status_Code sig_status = subject->verify_signature(*issuer_key);

            if(sig_status != Certificate_Status_Code::VERIFIED)
               status.insert(sig_status);

            if(issuer_key->estimated_strength() < min_signature_algo_strength)
               status.insert(Certificate_Status_Code::SIGNATURE_METHOD_TOO_WEAK);
            }

         // Ignore untrusted hashes on self-signed roots
         if(trusted_hashes.size() > 0 && !at_self_signed_root)
            {
            if(trusted_hashes.count(subject->hash_used_for_signature()) == 0)
               status.insert(Certificate_Status_Code::UNTRUSTED_HASH);
            }
         }

      // Check cert extensions

      if(subject->x509_version() == 1)
         {
         if(subject->v2_issuer_key_id().empty() == false ||
            subject->v2_subject_key_id().empty() == false)
            {
            status.insert(Certificate_Status_Code::V2_IDENTIFIERS_IN_V1_CERT);
            }
         }

      Extensions extensions = subject->v3_extensions();
      const auto& extensions_vec = extensions.extensions();
      if(subject->x509_version() < 3 && !extensions_vec.empty())
         {
         status.insert(Certificate_Status_Code::EXT_IN_V1_V2_CERT);
         }
      for(auto& extension : extensions_vec)
         {
         extension.first->validate(*subject, *issuer, cert_path, cert_status, i);
         }
      if(extensions.extensions().size() != extensions.get_extension_oids().size())
         {
         status.insert(Certificate_Status_Code::DUPLICATE_CERT_EXTENSION);
         }
      }

   // path len check
   size_t max_path_length = cert_path.size();
   for(size_t i = cert_path.size() - 1; i > 0 ; --i)
      {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);
      const std::shared_ptr<const X509_Certificate>& subject = cert_path[i];

      /*
      * If the certificate was not self-issued, verify that max_path_length is
      * greater than zero and decrement max_path_length by 1.
      */
      if(subject->subject_dn() != subject->issuer_dn())
         {
         if(max_path_length > 0)
            {
            --max_path_length;
            }
         else
            {
            status.insert(Certificate_Status_Code::CERT_CHAIN_TOO_LONG);
            }
         }

      /*
      * If pathLenConstraint is present in the certificate and is less than max_path_length,
      * set max_path_length to the value of pathLenConstraint.
      */
      if(subject->path_limit() != Cert_Extension::NO_CERT_PATH_LIMIT && subject->path_limit() < max_path_length)
         {
         max_path_length = subject->path_limit();
         }
      }

   return cert_status;
   }

CertificatePathStatusCodes
PKIX::check_ocsp(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                 const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses,
                 const std::vector<Certificate_Store*>& trusted_certstores,
                 std::chrono::system_clock::time_point ref_time,
                 std::chrono::seconds max_ocsp_age)
   {
   if(cert_path.empty())
      throw Invalid_Argument("PKIX::check_ocsp cert_path empty");

   CertificatePathStatusCodes cert_status(cert_path.size() - 1);

   for(size_t i = 0; i != cert_path.size() - 1; ++i)
      {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);

      std::shared_ptr<const X509_Certificate> subject = cert_path.at(i);
      std::shared_ptr<const X509_Certificate> ca = cert_path.at(i+1);

      if(i < ocsp_responses.size() && (ocsp_responses.at(i) != nullptr)
            && (ocsp_responses.at(i)->status() == OCSP::Response_Status_Code::Successful))
         {
         try
            {
            Certificate_Status_Code ocsp_signature_status = ocsp_responses.at(i)->check_signature(trusted_certstores, cert_path);

            if(ocsp_signature_status == Certificate_Status_Code::OCSP_SIGNATURE_OK)
               {
               // Signature ok, so check the claimed status
               Certificate_Status_Code ocsp_status = ocsp_responses.at(i)->status_for(*ca, *subject, ref_time, max_ocsp_age);
               status.insert(ocsp_status);
               }
            else
               {
               // Some signature problem
               status.insert(ocsp_signature_status);
               }
            }
         catch(Exception&)
            {
            status.insert(Certificate_Status_Code::OCSP_RESPONSE_INVALID);
            }
         }
      }

   while(cert_status.size() > 0 && cert_status.back().empty())
      cert_status.pop_back();

   return cert_status;
   }

CertificatePathStatusCodes
PKIX::check_crl(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                const std::vector<std::shared_ptr<const X509_CRL>>& crls,
                std::chrono::system_clock::time_point ref_time)
   {
   if(cert_path.empty())
      throw Invalid_Argument("PKIX::check_crl cert_path empty");

   CertificatePathStatusCodes cert_status(cert_path.size());
   const X509_Time validation_time(ref_time);

   for(size_t i = 0; i != cert_path.size() - 1; ++i)
      {
      std::set<Certificate_Status_Code>& status = cert_status.at(i);

      if(i < crls.size() && crls.at(i))
         {
         std::shared_ptr<const X509_Certificate> subject = cert_path.at(i);
         std::shared_ptr<const X509_Certificate> ca = cert_path.at(i+1);

         if(!ca->allowed_usage(CRL_SIGN))
            status.insert(Certificate_Status_Code::CA_CERT_NOT_FOR_CRL_ISSUER);

         if(validation_time < crls[i]->this_update())
            status.insert(Certificate_Status_Code::CRL_NOT_YET_VALID);

         if(validation_time > crls[i]->next_update())
            status.insert(Certificate_Status_Code::CRL_HAS_EXPIRED);

         if(crls[i]->check_signature(ca->subject_public_key()) == false)
            status.insert(Certificate_Status_Code::CRL_BAD_SIGNATURE);

         status.insert(Certificate_Status_Code::VALID_CRL_CHECKED);

         if(crls[i]->is_revoked(*subject))
            status.insert(Certificate_Status_Code::CERT_IS_REVOKED);

         std::string dp = subject->crl_distribution_point();
         if(!dp.empty())
            {
            if(dp != crls[i]->crl_issuing_distribution_point())
               {
               status.insert(Certificate_Status_Code::NO_MATCHING_CRLDP);
               }
            }

         for(const auto& extension : crls[i]->extensions().extensions())
            {
            // XXX this is wrong - the OID might be defined but the extention not full parsed
            // for example see #1652

            // is the extension critical and unknown?
            if(extension.second && OIDS::oid2str_or_empty(extension.first->oid_of()) == "")
               {
               /* NIST Certificate Path Valiadation Testing document: "When an implementation does not recognize a critical extension in the
                * crlExtensions field, it shall assume that identified certificates have been revoked and are no longer valid"
                */
               status.insert(Certificate_Status_Code::CERT_IS_REVOKED);
               }
            }

         }
      }

   while(cert_status.size() > 0 && cert_status.back().empty())
      cert_status.pop_back();

   return cert_status;
   }

CertificatePathStatusCodes
PKIX::check_crl(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                const std::vector<Certificate_Store*>& certstores,
                std::chrono::system_clock::time_point ref_time)
   {
   if(cert_path.empty())
      throw Invalid_Argument("PKIX::check_crl cert_path empty");

   if(certstores.empty())
      throw Invalid_Argument("PKIX::check_crl certstores empty");

   std::vector<std::shared_ptr<const X509_CRL>> crls(cert_path.size());

   for(size_t i = 0; i != cert_path.size(); ++i)
      {
      BOTAN_ASSERT_NONNULL(cert_path[i]);
      for(size_t c = 0; c != certstores.size(); ++c)
         {
         crls[i] = certstores[c]->find_crl_for(*cert_path[i]);
         if(crls[i])
            break;
         }
      }

   return PKIX::check_crl(cert_path, crls, ref_time);
   }

#if defined(BOTAN_HAS_ONLINE_REVOCATION_CHECKS)

CertificatePathStatusCodes
PKIX::check_ocsp_online(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                        const std::vector<Certificate_Store*>& trusted_certstores,
                        std::chrono::system_clock::time_point ref_time,
                        std::chrono::milliseconds timeout,
                        bool ocsp_check_intermediate_CAs,
                        std::chrono::seconds max_ocsp_age)
   {
   if(cert_path.empty())
      throw Invalid_Argument("PKIX::check_ocsp_online cert_path empty");

   std::vector<std::future<std::shared_ptr<const OCSP::Response>>> ocsp_response_futures;

   size_t to_ocsp = 1;

   if(ocsp_check_intermediate_CAs)
      to_ocsp = cert_path.size() - 1;
   if(cert_path.size() == 1)
      to_ocsp = 0;

   for(size_t i = 0; i < to_ocsp; ++i)
      {
      const std::shared_ptr<const X509_Certificate>& subject = cert_path.at(i);
      const std::shared_ptr<const X509_Certificate>& issuer = cert_path.at(i+1);

      if(subject->ocsp_responder() == "")
         {
         ocsp_response_futures.emplace_back(std::async(std::launch::deferred, [&]() -> std::shared_ptr<const OCSP::Response> {
                  return std::make_shared<const OCSP::Response>(Certificate_Status_Code::OCSP_NO_REVOCATION_URL);
                  }));
         }
      else
         {
         ocsp_response_futures.emplace_back(std::async(std::launch::async, [&]() -> std::shared_ptr<const OCSP::Response> {
               OCSP::Request req(*issuer, BigInt::decode(subject->serial_number()));

               HTTP::Response http;
               try
                  {
                  http = HTTP::POST_sync(subject->ocsp_responder(),
                                                "application/ocsp-request",
                                                req.BER_encode(),
                                                /*redirects*/1,
                                                timeout);
                  }
               catch(std::exception&)
                  {
                  // log e.what() ?
                  }
               if (http.status_code() != 200)
                  return std::make_shared<const OCSP::Response>(Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE);
               // Check the MIME type?

               return std::make_shared<const OCSP::Response>(http.body());
               }));
         }
      }

   std::vector<std::shared_ptr<const OCSP::Response>> ocsp_responses;

   for(size_t i = 0; i < ocsp_response_futures.size(); ++i)
      {
      ocsp_responses.push_back(ocsp_response_futures[i].get());
      }

   return PKIX::check_ocsp(cert_path, ocsp_responses, trusted_certstores, ref_time, max_ocsp_age);
   }

CertificatePathStatusCodes
PKIX::check_crl_online(const std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                       const std::vector<Certificate_Store*>& certstores,
                       Certificate_Store_In_Memory* crl_store,
                       std::chrono::system_clock::time_point ref_time,
                       std::chrono::milliseconds timeout)
   {
   if(cert_path.empty())
      throw Invalid_Argument("PKIX::check_crl_online cert_path empty");
   if(certstores.empty())
      throw Invalid_Argument("PKIX::check_crl_online certstores empty");

   std::vector<std::future<std::shared_ptr<const X509_CRL>>> future_crls;
   std::vector<std::shared_ptr<const X509_CRL>> crls(cert_path.size());

   for(size_t i = 0; i != cert_path.size(); ++i)
      {
      const std::shared_ptr<const X509_Certificate>& cert = cert_path.at(i);
      for(size_t c = 0; c != certstores.size(); ++c)
         {
         crls[i] = certstores[c]->find_crl_for(*cert);
         if(crls[i])
            break;
         }

      // TODO: check if CRL is expired and re-request?

      // Only request if we don't already have a CRL
      if(crls[i])
         {
         /*
         We already have a CRL, so just insert this empty one to hold a place in the vector
         so that indexes match up
         */
         future_crls.emplace_back(std::future<std::shared_ptr<const X509_CRL>>());
         }
      else if(cert->crl_distribution_point() == "")
         {
         // Avoid creating a thread for this case
         future_crls.emplace_back(std::async(std::launch::deferred, [&]() -> std::shared_ptr<const X509_CRL> {
               throw Not_Implemented("No CRL distribution point for this certificate");
               }));
         }
      else
         {
         future_crls.emplace_back(std::async(std::launch::async, [&]() -> std::shared_ptr<const X509_CRL> {
               auto http = HTTP::GET_sync(cert->crl_distribution_point(),
                                          /*redirects*/ 1, timeout);

               http.throw_unless_ok();
               // check the mime type?
               return std::make_shared<const X509_CRL>(http.body());
               }));
         }
      }

   for(size_t i = 0; i != future_crls.size(); ++i)
      {
      if(future_crls[i].valid())
         {
         try
            {
            crls[i] = future_crls[i].get();
            }
         catch(std::exception&)
            {
            // crls[i] left null
            // todo: log exception e.what() ?
            }
         }
      }

   const CertificatePathStatusCodes crl_status = PKIX::check_crl(cert_path, crls, ref_time);

   if(crl_store)
      {
      for(size_t i = 0; i != crl_status.size(); ++i)
         {
         if(crl_status[i].count(Certificate_Status_Code::VALID_CRL_CHECKED))
            {
            // better be non-null, we supposedly validated it
            BOTAN_ASSERT_NONNULL(crls[i]);
            crl_store->add_crl(crls[i]);
            }
         }
      }

   return crl_status;
   }

#endif

Certificate_Status_Code
PKIX::build_certificate_path(std::vector<std::shared_ptr<const X509_Certificate>>& cert_path,
                             const std::vector<Certificate_Store*>& trusted_certstores,
                             const std::shared_ptr<const X509_Certificate>& end_entity,
                             const std::vector<std::shared_ptr<const X509_Certificate>>& end_entity_extra)
   {
   if(end_entity->is_self_signed())
      {
      return Certificate_Status_Code::CANNOT_ESTABLISH_TRUST;
      }

   /*
   * This is an inelegant but functional way of preventing path loops
   * (where C1 -> C2 -> C3 -> C1). We store a set of all the certificate
   * fingerprints in the path. If there is a duplicate, we error out.
   * TODO: save fingerprints in result struct? Maybe useful for blacklists, etc.
   */
   std::set<std::string> certs_seen;

   cert_path.push_back(end_entity);
   certs_seen.insert(end_entity->fingerprint("SHA-256"));

   Certificate_Store_In_Memory ee_extras;
   for(size_t i = 0; i != end_entity_extra.size(); ++i)
      ee_extras.add_certificate(end_entity_extra[i]);

   // iterate until we reach a root or cannot find the issuer
   for(;;)
      {
      const X509_Certificate& last = *cert_path.back();
      const X509_DN issuer_dn = last.issuer_dn();
      const std::vector<uint8_t> auth_key_id = last.authority_key_id();

      std::shared_ptr<const X509_Certificate> issuer;
      bool trusted_issuer = false;

      for(Certificate_Store* store : trusted_certstores)
         {
         issuer = store->find_cert(issuer_dn, auth_key_id);
         if(issuer)
            {
            trusted_issuer = true;
            break;
            }
         }

      if(!issuer)
         {
         // fall back to searching supplemental certs
         issuer = ee_extras.find_cert(issuer_dn, auth_key_id);
         }

      if(!issuer)
         return Certificate_Status_Code::CERT_ISSUER_NOT_FOUND;

      const std::string fprint = issuer->fingerprint("SHA-256");

      if(certs_seen.count(fprint) > 0) // already seen?
         {
         return Certificate_Status_Code::CERT_CHAIN_LOOP;
         }

      certs_seen.insert(fprint);
      cert_path.push_back(issuer);

      if(issuer->is_self_signed())
         {
         if(trusted_issuer)
            {
            return Certificate_Status_Code::OK;
            }
         else
            {
            return Certificate_Status_Code::CANNOT_ESTABLISH_TRUST;
            }
         }
      }
   }

/**
 * utilities for PKIX::build_all_certificate_paths
 */
namespace
{
// <certificate, trusted?>
using cert_maybe_trusted = std::pair<std::shared_ptr<const X509_Certificate>,bool>;
}

/**
 * Build all possible certificate paths from the end certificate to self-signed trusted roots.
 *
 * All potentially valid paths are put into the cert_paths vector. If no potentially valid paths are found,
 * one of the encountered errors is returned arbitrarily.
 *
 * todo add a path building function that returns detailed information on errors encountered while building
 * the potentially numerous path candidates.
 *
 * Basically, a DFS is performed starting from the end certificate. A stack (vector) serves to control the DFS.
 * At the beginning of each iteration, a pair is popped from the stack that contains (1) the next certificate
 * to add to the path (2) a bool that indicates if the certificate is part of a trusted certstore. Ideally, we
 * follow the unique issuer of the current certificate until a trusted root is reached. However, the issuer DN +
 * authority key id need not be unique among the certificates used for building the path. In such a case,
 * we consider all the matching issuers by pushing <IssuerCert, trusted?> on the stack for each of them.
 *
 */
Certificate_Status_Code
PKIX::build_all_certificate_paths(std::vector<std::vector<std::shared_ptr<const X509_Certificate>>>& cert_paths_out,
                                  const std::vector<Certificate_Store*>& trusted_certstores,
                                  const std::shared_ptr<const X509_Certificate>& end_entity,
                                  const std::vector<std::shared_ptr<const X509_Certificate>>& end_entity_extra)
   {
   if(!cert_paths_out.empty())
      {
      throw Invalid_Argument("PKIX::build_all_certificate_paths: cert_paths_out must be empty");
      }

   if(end_entity->is_self_signed())
      {
      return Certificate_Status_Code::CANNOT_ESTABLISH_TRUST;
      }

   /*
    * Pile up error messages
    */
   std::vector<Certificate_Status_Code> stats;

   Certificate_Store_In_Memory ee_extras;
   for(size_t i = 0; i != end_entity_extra.size(); ++i)
      {
      ee_extras.add_certificate(end_entity_extra[i]);
      }

   /*
   * This is an inelegant but functional way of preventing path loops
   * (where C1 -> C2 -> C3 -> C1). We store a set of all the certificate
   * fingerprints in the path. If there is a duplicate, we error out.
   * TODO: save fingerprints in result struct? Maybe useful for blacklists, etc.
   */
   std::set<std::string> certs_seen;

   // new certs are added and removed from the path during the DFS
   // it is copied into cert_paths_out when we encounter a trusted root
   std::vector<std::shared_ptr<const X509_Certificate>> path_so_far;

   // todo can we assume that the end certificate is not trusted?
   std::vector<cert_maybe_trusted> stack = { {end_entity, false} };

   while(!stack.empty())
      {
      // found a deletion marker that guides the DFS, backtracing
      if(stack.back().first == nullptr)
         {
         stack.pop_back();
         std::string fprint = path_so_far.back()->fingerprint("SHA-256");
         certs_seen.erase(fprint);
         path_so_far.pop_back();
         }
      // process next cert on the path
      else
         {
         std::shared_ptr<const X509_Certificate> last = stack.back().first;
         bool trusted = stack.back().second;
         stack.pop_back();

         // certificate already seen?
         const std::string fprint = last->fingerprint("SHA-256");
         if(certs_seen.count(fprint) == 1)
            {
            stats.push_back(Certificate_Status_Code::CERT_CHAIN_LOOP);
            // the current path ended in a loop
            continue;
            }

         // the current path ends here
         if(last->is_self_signed())
            {
            // found a trust anchor
            if(trusted)
               {
               cert_paths_out.push_back(path_so_far);
               cert_paths_out.back().push_back(last);

               continue;
               }
            // found an untrustworthy root
            else
               {
               stats.push_back(Certificate_Status_Code::CANNOT_ESTABLISH_TRUST);
               continue;
               }
            }

         const X509_DN issuer_dn = last->issuer_dn();
         const std::vector<uint8_t> auth_key_id = last->authority_key_id();

         // search for trusted issuers
         std::vector<std::shared_ptr<const X509_Certificate>> trusted_issuers;
         for(Certificate_Store* store : trusted_certstores)
            {
            auto new_issuers = store->find_all_certs(issuer_dn, auth_key_id);
            trusted_issuers.insert(trusted_issuers.end(), new_issuers.begin(), new_issuers.end());
            }

         // search the supplemental certs
         std::vector<std::shared_ptr<const X509_Certificate>> misc_issuers =
            ee_extras.find_all_certs(issuer_dn, auth_key_id);

         // if we could not find any issuers, the current path ends here
         if(trusted_issuers.size() + misc_issuers.size() == 0)
            {
            stats.push_back(Certificate_Status_Code::CERT_ISSUER_NOT_FOUND);
            continue;
            }

         // push the latest certificate onto the path_so_far
         path_so_far.push_back(last);
         certs_seen.emplace(fprint);

         // push a deletion marker on the stack for backtracing later
         stack.push_back({std::shared_ptr<const X509_Certificate>(nullptr),false});

         for(const auto& trusted_cert : trusted_issuers)
            {
            stack.push_back({trusted_cert,true});
            }

         for(const auto& misc : misc_issuers)
            {
            stack.push_back({misc,false});
            }
         }
      }

   // could not construct any potentially valid path
   if(cert_paths_out.empty())
      {
      if(stats.empty())
         throw Internal_Error("X509 path building failed for unknown reasons");
      else
         // arbitrarily return the first error
         return stats[0];
      }
   else
      {
      return Certificate_Status_Code::OK;
      }
   }


void PKIX::merge_revocation_status(CertificatePathStatusCodes& chain_status,
                                   const CertificatePathStatusCodes& crl,
                                   const CertificatePathStatusCodes& ocsp,
                                   bool require_rev_on_end_entity,
                                   bool require_rev_on_intermediates)
   {
   if(chain_status.empty())
      throw Invalid_Argument("PKIX::merge_revocation_status chain_status was empty");

   for(size_t i = 0; i != chain_status.size() - 1; ++i)
      {
      bool had_crl = false, had_ocsp = false;

      if(i < crl.size() && crl[i].size() > 0)
         {
         for(auto&& code : crl[i])
            {
            if(code == Certificate_Status_Code::VALID_CRL_CHECKED)
               {
               had_crl = true;
               }
            chain_status[i].insert(code);
            }
         }

      if(i < ocsp.size() && ocsp[i].size() > 0)
         {
         for(auto&& code : ocsp[i])
            {
            if(code == Certificate_Status_Code::OCSP_RESPONSE_GOOD ||
               code == Certificate_Status_Code::OCSP_NO_REVOCATION_URL ||  // softfail
               code == Certificate_Status_Code::OCSP_SERVER_NOT_AVAILABLE) // softfail
               {
               had_ocsp = true;
               }

            chain_status[i].insert(code);
            }
         }

      if(had_crl == false && had_ocsp == false)
         {
         if((require_rev_on_end_entity && i == 0) ||
            (require_rev_on_intermediates && i > 0))
            {
            chain_status[i].insert(Certificate_Status_Code::NO_REVOCATION_DATA);
            }
         }
      }
   }

Certificate_Status_Code PKIX::overall_status(const CertificatePathStatusCodes& cert_status)
   {
   if(cert_status.empty())
      throw Invalid_Argument("PKIX::overall_status empty cert status");

   Certificate_Status_Code overall_status = Certificate_Status_Code::OK;

   // take the "worst" error as overall
   for(const std::set<Certificate_Status_Code>& s : cert_status)
      {
      if(!s.empty())
         {
         auto worst = *s.rbegin();
         // Leave informative OCSP/CRL confirmations on cert-level status only
         if(worst >= Certificate_Status_Code::FIRST_ERROR_STATUS && worst > overall_status)
            {
            overall_status = worst;
            }
         }
      }
   return overall_status;
   }

Path_Validation_Result x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& trusted_roots,
   const std::string& hostname,
   Usage_Type usage,
   std::chrono::system_clock::time_point ref_time,
   std::chrono::milliseconds ocsp_timeout,
   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_resp)
   {
   if(end_certs.empty())
      {
      throw Invalid_Argument("x509_path_validate called with no subjects");
      }

   std::shared_ptr<const X509_Certificate> end_entity(std::make_shared<const X509_Certificate>(end_certs[0]));
   std::vector<std::shared_ptr<const X509_Certificate>> end_entity_extra;
   for(size_t i = 1; i < end_certs.size(); ++i)
      {
      end_entity_extra.push_back(std::make_shared<const X509_Certificate>(end_certs[i]));
      }

   std::vector<std::vector<std::shared_ptr<const X509_Certificate>>> cert_paths;
   Certificate_Status_Code path_building_result = PKIX::build_all_certificate_paths(cert_paths, trusted_roots, end_entity, end_entity_extra);

   // If we cannot successfully build a chain to a trusted self-signed root, stop now
   if(path_building_result != Certificate_Status_Code::OK)
      {
      return Path_Validation_Result(path_building_result);
      }

   std::vector<Path_Validation_Result> error_results;
   // Try validating all the potentially valid paths and return the first one to validate properly
   for(auto cert_path : cert_paths)
      {
      CertificatePathStatusCodes status =
         PKIX::check_chain(cert_path, ref_time,
                           hostname, usage,
                           restrictions.minimum_key_strength(),
                           restrictions.trusted_hashes());

      CertificatePathStatusCodes crl_status =
         PKIX::check_crl(cert_path, trusted_roots, ref_time);

      CertificatePathStatusCodes ocsp_status;

      if(ocsp_resp.size() > 0)
         {
         ocsp_status = PKIX::check_ocsp(cert_path, ocsp_resp, trusted_roots, ref_time, restrictions.max_ocsp_age());
         }

      if(ocsp_status.empty() && ocsp_timeout != std::chrono::milliseconds(0))
         {
#if defined(BOTAN_TARGET_OS_HAS_THREADS) && defined(BOTAN_HAS_HTTP_UTIL)
         ocsp_status = PKIX::check_ocsp_online(cert_path, trusted_roots, ref_time,
                                               ocsp_timeout, restrictions.ocsp_all_intermediates());
#else
         ocsp_status.resize(1);
         ocsp_status[0].insert(Certificate_Status_Code::OCSP_NO_HTTP);
#endif
         }

      PKIX::merge_revocation_status(status, crl_status, ocsp_status,
                                    restrictions.require_revocation_information(),
                                    restrictions.ocsp_all_intermediates());

      Path_Validation_Result pvd(status, std::move(cert_path));
      if(pvd.successful_validation())
         {
         return pvd;
         }
      else
         {
         error_results.push_back(std::move(pvd));
         }
      }
   return error_results[0];
   }

Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& trusted_roots,
   const std::string& hostname,
   Usage_Type usage,
   std::chrono::system_clock::time_point when,
   std::chrono::milliseconds ocsp_timeout,
   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_resp)
   {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);
   return x509_path_validate(certs, restrictions, trusted_roots, hostname, usage, when, ocsp_timeout, ocsp_resp);
   }

Path_Validation_Result x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname,
   Usage_Type usage,
   std::chrono::system_clock::time_point when,
   std::chrono::milliseconds ocsp_timeout,
   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_resp)
   {
   std::vector<Certificate_Store*> trusted_roots;
   trusted_roots.push_back(const_cast<Certificate_Store*>(&store));

   return x509_path_validate(end_certs, restrictions, trusted_roots, hostname, usage, when, ocsp_timeout, ocsp_resp);
   }

Path_Validation_Result x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store,
   const std::string& hostname,
   Usage_Type usage,
   std::chrono::system_clock::time_point when,
   std::chrono::milliseconds ocsp_timeout,
   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_resp)
   {
   std::vector<X509_Certificate> certs;
   certs.push_back(end_cert);

   std::vector<Certificate_Store*> trusted_roots;
   trusted_roots.push_back(const_cast<Certificate_Store*>(&store));

   return x509_path_validate(certs, restrictions, trusted_roots, hostname, usage, when, ocsp_timeout, ocsp_resp);
   }

Path_Validation_Restrictions::Path_Validation_Restrictions(bool require_rev,
      size_t key_strength,
      bool ocsp_intermediates,
      std::chrono::seconds max_ocsp_age) :
   m_require_revocation_information(require_rev),
   m_ocsp_all_intermediates(ocsp_intermediates),
   m_minimum_key_strength(key_strength),
   m_max_ocsp_age(max_ocsp_age)
   {
   if(key_strength <= 80)
      { m_trusted_hashes.insert("SHA-160"); }

   m_trusted_hashes.insert("SHA-224");
   m_trusted_hashes.insert("SHA-256");
   m_trusted_hashes.insert("SHA-384");
   m_trusted_hashes.insert("SHA-512");
   }

namespace {
CertificatePathStatusCodes find_warnings(const CertificatePathStatusCodes& all_statuses)
   {
   CertificatePathStatusCodes warnings;
   for(const auto& status_set_i : all_statuses)
      {
      std::set<Certificate_Status_Code> warning_set_i;
      for(const auto& code : status_set_i)
         {
         if(code >= Certificate_Status_Code::FIRST_WARNING_STATUS &&
            code < Certificate_Status_Code::FIRST_ERROR_STATUS)
            {
            warning_set_i.insert(code);
            }
         }
      warnings.push_back(warning_set_i);
      }
   return warnings;
   }
}

Path_Validation_Result::Path_Validation_Result(CertificatePathStatusCodes status,
                                               std::vector<std::shared_ptr<const X509_Certificate>>&& cert_chain) :
   m_all_status(status),
   m_warnings(find_warnings(m_all_status)),
   m_cert_path(cert_chain),
   m_overall(PKIX::overall_status(m_all_status))
   {
   }

const X509_Certificate& Path_Validation_Result::trust_root() const
   {
   if(m_cert_path.empty())
      throw Invalid_State("Path_Validation_Result::trust_root no path set");
   if(result() != Certificate_Status_Code::VERIFIED)
      throw Invalid_State("Path_Validation_Result::trust_root meaningless with invalid status");

   return *m_cert_path[m_cert_path.size()-1];
   }

std::set<std::string> Path_Validation_Result::trusted_hashes() const
   {
   std::set<std::string> hashes;
   for(size_t i = 0; i != m_cert_path.size(); ++i)
      hashes.insert(m_cert_path[i]->hash_used_for_signature());
   return hashes;
   }

bool Path_Validation_Result::successful_validation() const
   {
   return (result() == Certificate_Status_Code::VERIFIED ||
           result() == Certificate_Status_Code::OCSP_RESPONSE_GOOD ||
           result() == Certificate_Status_Code::VALID_CRL_CHECKED);
   }

bool Path_Validation_Result::no_warnings() const
   {
   for(auto status_set_i : m_warnings)
      if(!status_set_i.empty())
         return false;
   return true;
   }

CertificatePathStatusCodes Path_Validation_Result::warnings() const
   {
   return m_warnings;
   }

std::string Path_Validation_Result::result_string() const
   {
   return status_string(result());
   }

const char* Path_Validation_Result::status_string(Certificate_Status_Code code)
   {
   if(const char* s = to_string(code))
      return s;

   return "Unknown error";
   }

std::string Path_Validation_Result::warnings_string() const
   {
   const std::string sep(", ");
   std::string res;
   for(size_t i = 0; i < m_warnings.size(); i++)
      {
      for(auto code : m_warnings[i])
         res += "[" + std::to_string(i) + "] " + status_string(code) + sep;
      }
   // remove last sep
   if(res.size() >= sep.size())
      res = res.substr(0, res.size() - sep.size());
   return res;
   }
}
