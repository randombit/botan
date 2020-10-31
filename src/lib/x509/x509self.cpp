/*
* PKCS #10/Self Signed Cert Creation
* (C) 1999-2008,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509self.h>
#include <botan/x509_key.h>
#include <botan/x509_ext.h>
#include <botan/x509_ca.h>
#include <botan/der_enc.h>
#include <botan/pubkey.h>
#include <botan/hash.h>

namespace Botan {

namespace {

/*
* Load information from the X509_Cert_Options
*/
void load_info(const X509_Cert_Options& opts, X509_DN& subject_dn,
               AlternativeName& subject_alt)
   {
   subject_dn.add_attribute("X520.CommonName", opts.common_name);
   subject_dn.add_attribute("X520.Country", opts.country);
   subject_dn.add_attribute("X520.State", opts.state);
   subject_dn.add_attribute("X520.Locality", opts.locality);
   subject_dn.add_attribute("X520.Organization", opts.organization);
   subject_dn.add_attribute("X520.OrganizationalUnit", opts.org_unit);
   for(auto extra_ou : opts.more_org_units) {
      subject_dn.add_attribute("X520.OrganizationalUnit", extra_ou);
   }

   subject_dn.add_attribute("X520.SerialNumber", opts.serial_number);
   subject_alt = AlternativeName(opts.email, opts.uri, opts.dns, opts.ip);
   subject_alt.add_othername(OID::from_string("PKIX.XMPPAddr"),
                             opts.xmpp, UTF8_STRING);

   for(auto dns : opts.more_dns)
      subject_alt.add_attribute("DNS", dns);
   }
}

namespace X509 {

/*
* Create a new self-signed X.509 certificate
*/
X509_Certificate create_self_signed_cert(const X509_Cert_Options& opts,
                                         const Private_Key& key,
                                         const std::string& hash_fn,
                                         RandomNumberGenerator& rng)
   {
   AlgorithmIdentifier sig_algo;
   X509_DN subject_dn;
   AlternativeName subject_alt;

   // for now, only the padding option is used
   std::map<std::string,std::string> sig_opts = { {"padding",opts.padding_scheme} };

   const std::vector<uint8_t> pub_key = X509::BER_encode(key);
   std::unique_ptr<PK_Signer> signer(choose_sig_format(key, sig_opts, rng, hash_fn, sig_algo));
   BOTAN_ASSERT_NOMSG(sig_algo.get_oid().has_value());
   load_info(opts, subject_dn, subject_alt);

   Extensions extensions = opts.extensions;

   Key_Constraints constraints;
   if(opts.is_CA)
      {
      constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
      }
   else
      {
      verify_cert_constraints_valid_for_key_type(key, opts.constraints);
      constraints = opts.constraints;
      }

   extensions.add_new(
      new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit),
      true);

   if(constraints != NO_CONSTRAINTS)
      {
      extensions.add_new(new Cert_Extension::Key_Usage(constraints), true);
      }

   std::unique_ptr<Cert_Extension::Subject_Key_ID> skid(new Cert_Extension::Subject_Key_ID(pub_key, hash_fn));

   extensions.add_new(new Cert_Extension::Authority_Key_ID(skid->get_key_id()));
   extensions.add_new(skid.release());

   extensions.add_new(
      new Cert_Extension::Subject_Alternative_Name(subject_alt));

   extensions.add_new(
      new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));

   return X509_CA::make_cert(signer.get(), rng, sig_algo, pub_key,
                             opts.start, opts.end,
                             subject_dn, subject_dn,
                             extensions);
   }

/*
* Create a PKCS #10 certificate request
*/
PKCS10_Request create_cert_req(const X509_Cert_Options& opts,
                               const Private_Key& key,
                               const std::string& hash_fn,
                               RandomNumberGenerator& rng)
   {
   X509_DN subject_dn;
   AlternativeName subject_alt;
   load_info(opts, subject_dn, subject_alt);

   Key_Constraints constraints;
   if(opts.is_CA)
      {
      constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
      }
   else
      {
      verify_cert_constraints_valid_for_key_type(key, opts.constraints);
      constraints = opts.constraints;
      }

   Extensions extensions = opts.extensions;

   extensions.add_new(new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit));

   if(constraints != NO_CONSTRAINTS)
      {
      extensions.add_new(new Cert_Extension::Key_Usage(constraints));
      }
   extensions.add_new(new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));
   extensions.add_new(new Cert_Extension::Subject_Alternative_Name(subject_alt));

   return PKCS10_Request::create(key,
                                 subject_dn,
                                 extensions,
                                 hash_fn,
                                 rng,
                                 opts.padding_scheme,
                                 opts.challenge);
   }

}

}
