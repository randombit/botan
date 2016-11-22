/*
* TLS Callbacks
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/tls_callbacks.h>
#include <botan/x509path.h>
#include <botan/ocsp.h>
#include <botan/certstor.h>

namespace Botan {

TLS::Callbacks::~Callbacks() {}

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
   const std::vector<Certificate_Store*>& trusted_roots,
   Usage_Type usage,
   const std::string& hostname)
   {
   if(cert_chain.empty())
      throw Invalid_Argument("Certificate chain was empty");

   Path_Validation_Restrictions restrictions;

   Path_Validation_Result result =
      x509_path_validate(cert_chain,
                         restrictions,
                         trusted_roots,
                         (usage == Usage_Type::TLS_SERVER_AUTH ? hostname : ""),
                         usage,
                         std::chrono::system_clock::now(),
                         tls_verify_cert_chain_ocsp_timeout());

   if(!result.successful_validation())
      throw Exception("Certificate validation failure: " + result.result_string());
   }

}
