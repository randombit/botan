/*
* (C) 2012,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ocsp.h>

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/internal/http_util.h>
#endif

namespace Botan::OCSP {

#if defined(BOTAN_HAS_HTTP_UTIL)

Response online_check(const X509_Certificate& issuer,
                      const BigInt& subject_serial,
                      std::string_view ocsp_responder,
                      std::chrono::milliseconds timeout) {
   if(ocsp_responder.empty()) {
      throw Invalid_Argument("No OCSP responder specified");
   }

   const OCSP::Request req(issuer, subject_serial);

   auto http = HTTP::POST_sync(ocsp_responder, "application/ocsp-request", req.BER_encode(), 1, timeout);

   http.throw_unless_ok();

   // Check the MIME type?

   return OCSP::Response(http.body());
}

Response online_check(const X509_Certificate& issuer,
                      const X509_Certificate& subject,
                      std::chrono::milliseconds timeout) {
   if(subject.issuer_dn() != issuer.subject_dn()) {
      throw Invalid_Argument("Invalid cert pair to OCSP::online_check (mismatched issuer,subject args?)");
   }

   return online_check(issuer, BigInt::from_bytes(subject.serial_number()), subject.ocsp_responder(), timeout);
}

#endif

}  // namespace Botan::OCSP
