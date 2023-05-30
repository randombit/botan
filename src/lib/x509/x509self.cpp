/*
* PKCS #10/Self Signed Cert Creation
* (C) 1999-2008,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509self.h>

#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/pubkey.h>
#include <botan/x509_ca.h>
#include <botan/x509_ext.h>
#include <botan/x509_key.h>

namespace Botan {

namespace {

/*
* Load information from the X509_Cert_Options
*/
void load_info(const X509_Cert_Options& opts, X509_DN& subject_dn, AlternativeName& subject_alt) {
   subject_dn.add_attribute("X520.CommonName", opts.common_name);
   subject_dn.add_attribute("X520.Country", opts.country);
   subject_dn.add_attribute("X520.State", opts.state);
   subject_dn.add_attribute("X520.Locality", opts.locality);
   subject_dn.add_attribute("X520.Organization", opts.organization);
   subject_dn.add_attribute("X520.OrganizationalUnit", opts.org_unit);
   for(const auto& extra_ou : opts.more_org_units) {
      subject_dn.add_attribute("X520.OrganizationalUnit", extra_ou);
   }

   subject_dn.add_attribute("X520.SerialNumber", opts.serial_number);
   subject_alt = AlternativeName(opts.email, opts.uri, opts.dns, opts.ip);
   subject_alt.add_othername(OID::from_string("PKIX.XMPPAddr"), opts.xmpp, ASN1_Type::Utf8String);

   for(const auto& dns : opts.more_dns) {
      subject_alt.add_attribute("DNS", dns);
   }
}
}  // namespace

namespace X509 {

/*
* Create a new self-signed X.509 certificate
*/
X509_Certificate create_self_signed_cert(const X509_Cert_Options& opts,
                                         const Private_Key& key,
                                         std::string_view hash_fn,
                                         RandomNumberGenerator& rng) {
   const std::vector<uint8_t> pub_key = X509::BER_encode(key);
   auto signer = X509_Object::choose_sig_format(key, rng, hash_fn, opts.padding_scheme);
   const AlgorithmIdentifier sig_algo = signer->algorithm_identifier();
   BOTAN_ASSERT_NOMSG(sig_algo.oid().has_value());

   X509_DN subject_dn;
   AlternativeName subject_alt;
   load_info(opts, subject_dn, subject_alt);

   Extensions extensions = opts.extensions;

   const auto constraints = opts.is_CA ? Key_Constraints::ca_constraints() : opts.constraints;

   if(!constraints.compatible_with(key)) {
      throw Invalid_Argument("The requested key constraints are incompatible with the algorithm");
   }

   extensions.add_new(std::make_unique<Cert_Extension::Basic_Constraints>(opts.is_CA, opts.path_limit), true);

   if(!constraints.empty()) {
      extensions.add_new(std::make_unique<Cert_Extension::Key_Usage>(constraints), true);
   }

   auto skid = std::make_unique<Cert_Extension::Subject_Key_ID>(pub_key, signer->hash_function());

   extensions.add_new(std::make_unique<Cert_Extension::Authority_Key_ID>(skid->get_key_id()));
   extensions.add_new(std::move(skid));

   extensions.add_new(std::make_unique<Cert_Extension::Subject_Alternative_Name>(subject_alt));

   extensions.add_new(std::make_unique<Cert_Extension::Extended_Key_Usage>(opts.ex_constraints));

   return X509_CA::make_cert(*signer, rng, sig_algo, pub_key, opts.start, opts.end, subject_dn, subject_dn, extensions);
}

/*
* Create a PKCS #10 certificate request
*/
PKCS10_Request create_cert_req(const X509_Cert_Options& opts,
                               const Private_Key& key,
                               std::string_view hash_fn,
                               RandomNumberGenerator& rng) {
   X509_DN subject_dn;
   AlternativeName subject_alt;
   load_info(opts, subject_dn, subject_alt);

   const auto constraints = opts.is_CA ? Key_Constraints::ca_constraints() : opts.constraints;

   if(!constraints.compatible_with(key)) {
      throw Invalid_Argument("The requested key constraints are incompatible with the algorithm");
   }

   Extensions extensions = opts.extensions;

   extensions.add_new(std::make_unique<Cert_Extension::Basic_Constraints>(opts.is_CA, opts.path_limit));

   if(!constraints.empty()) {
      extensions.add_new(std::make_unique<Cert_Extension::Key_Usage>(constraints));
   }

   extensions.add_new(std::make_unique<Cert_Extension::Extended_Key_Usage>(opts.ex_constraints));
   extensions.add_new(std::make_unique<Cert_Extension::Subject_Alternative_Name>(subject_alt));

   return PKCS10_Request::create(key, subject_dn, extensions, hash_fn, rng, opts.padding_scheme, opts.challenge);
}

}  // namespace X509

}  // namespace Botan
