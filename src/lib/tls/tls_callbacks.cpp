/*
* TLS Callbacks
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_callbacks.h>
#include <botan/tls_policy.h>
#include <botan/x509path.h>
#include <botan/ocsp.h>

namespace Botan {

void TLS::Callbacks::tls_inspect_handshake_msg(const Handshake_Message&)
   {
   // default is no op
   }

std::string TLS::Callbacks::tls_server_choose_app_protocol(const std::vector<std::string>&)
   {
   return "";
   }

void TLS::Callbacks::tls_verify_cert_chain(
   const std::vector<X509_Certificate>& cert_chain,
   const std::vector<std::shared_ptr<const OCSP::Response>>& ocsp_responses,
   const std::vector<Certificate_Store*>& trusted_roots,
   Usage_Type usage,
   const std::string& hostname,
   const TLS::Policy& policy)
   {
   if(cert_chain.empty())
      throw Invalid_Argument("Certificate chain was empty");

   Path_Validation_Restrictions restrictions(policy.require_cert_revocation_info(),
                                             policy.minimum_signature_strength());

   Path_Validation_Result result =
      x509_path_validate(cert_chain,
                         restrictions,
                         trusted_roots,
                         (usage == Usage_Type::TLS_SERVER_AUTH ? hostname : ""),
                         usage,
                         std::chrono::system_clock::now(),
                         tls_verify_cert_chain_ocsp_timeout(),
                         ocsp_responses);

   if(!result.successful_validation())
      throw Exception("Certificate validation failure: " + result.result_string());
   }

}
