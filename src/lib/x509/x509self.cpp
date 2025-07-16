/*
* PKCS #10/Self Signed Cert Creation
* (C) 1999-2008,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509self.h>

namespace Botan::X509 {

/*
* Create a new self-signed X.509 certificate
*/
X509_Certificate create_self_signed_cert(const X509_Cert_Options& opts,
                                         const Private_Key& key,
                                         std::string_view hash_fn,
                                         RandomNumberGenerator& rng) {
   auto not_before = opts.start.to_std_timepoint();
   auto not_after = opts.end.to_std_timepoint();

   const std::optional<std::string_view> padding =
      (opts.padding_scheme.empty()) ? std::nullopt : std::optional<std::string_view>(opts.padding_scheme);

   return opts.into_builder().into_self_signed_cert(not_before, not_after, key, rng, hash_fn, padding);
}

/*
* Create a PKCS #10 certificate request
*/
PKCS10_Request create_cert_req(const X509_Cert_Options& opts,
                               const Private_Key& key,
                               std::string_view hash_fn,
                               RandomNumberGenerator& rng) {
   const std::optional<std::string_view> challenge_password =
      (opts.challenge.empty()) ? std::nullopt : std::optional<std::string_view>(opts.challenge);
   const std::optional<std::string_view> padding =
      (opts.padding_scheme.empty()) ? std::nullopt : std::optional<std::string_view>(opts.padding_scheme);

   // opts.start and opts.end are ignored here

   return opts.into_builder().into_pkcs10_request(key, rng, hash_fn, padding, challenge_password);
}

}  // namespace Botan::X509
