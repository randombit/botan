/*
* PKCS #10/Self Signed Cert Creation
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509self.h>
#include <botan/x509_ext.h>
#include <botan/x509_ca.h>
#include <botan/der_enc.h>
#include <botan/look_pk.h>
#include <botan/oids.h>
#include <botan/pipe.h>
#include <memory>

namespace Botan {

namespace {

/*
* Shared setup for self-signed items
*/
MemoryVector<byte> shared_setup(const X509_Cert_Options& opts,
                                const Private_Key& key)
   {
   const Private_Key* key_pointer = &key;
   if(!dynamic_cast<const PK_Signing_Key*>(key_pointer))
      throw Invalid_Argument("Key type " + key.algo_name() + " cannot sign");

   opts.sanity_check();

   Pipe key_encoder;
   key_encoder.start_msg();
   X509::encode(key, key_encoder, RAW_BER);
   key_encoder.end_msg();

   return key_encoder.read_all();
   }

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
   subject_dn.add_attribute("X520.SerialNumber", opts.serial_number);
   subject_alt = AlternativeName(opts.email, opts.uri, opts.dns, opts.ip);
   subject_alt.add_othername(OIDS::lookup("PKIX.XMPPAddr"),
                             opts.xmpp, UTF8_STRING);
   }

}

namespace X509 {

/*
* Create a new self-signed X.509 certificate
*/
X509_Certificate create_self_signed_cert(const X509_Cert_Options& opts,
                                         const Private_Key& key,
                                         RandomNumberGenerator& rng)
   {
   AlgorithmIdentifier sig_algo;
   X509_DN subject_dn;
   AlternativeName subject_alt;

   MemoryVector<byte> pub_key = shared_setup(opts, key);
   std::auto_ptr<PK_Signer> signer(choose_sig_format(key, sig_algo));
   load_info(opts, subject_dn, subject_alt);

   Key_Constraints constraints;
   if(opts.is_CA)
      constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
   else
      constraints = find_constraints(key, opts.constraints);

   Extensions extensions;

   extensions.add(new Cert_Extension::Subject_Key_ID(pub_key));
   extensions.add(new Cert_Extension::Key_Usage(constraints));
   extensions.add(
      new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));
   extensions.add(
      new Cert_Extension::Subject_Alternative_Name(subject_alt));
   extensions.add(
      new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit));

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
                               RandomNumberGenerator& rng)
   {
   AlgorithmIdentifier sig_algo;
   X509_DN subject_dn;
   AlternativeName subject_alt;

   MemoryVector<byte> pub_key = shared_setup(opts, key);
   std::auto_ptr<PK_Signer> signer(choose_sig_format(key, sig_algo));
   load_info(opts, subject_dn, subject_alt);

   const u32bit PKCS10_VERSION = 0;

   Extensions extensions;

   extensions.add(
      new Cert_Extension::Basic_Constraints(opts.is_CA, opts.path_limit));
   extensions.add(
      new Cert_Extension::Key_Usage(
         opts.is_CA ? Key_Constraints(KEY_CERT_SIGN | CRL_SIGN) :
                      find_constraints(key, opts.constraints)
         )
      );
   extensions.add(
      new Cert_Extension::Extended_Key_Usage(opts.ex_constraints));
   extensions.add(
      new Cert_Extension::Subject_Alternative_Name(subject_alt));

   DER_Encoder tbs_req;

   tbs_req.start_cons(SEQUENCE)
      .encode(PKCS10_VERSION)
      .encode(subject_dn)
      .raw_bytes(pub_key)
      .start_explicit(0);

   if(opts.challenge != "")
      {
      ASN1_String challenge(opts.challenge, DIRECTORY_STRING);

      tbs_req.encode(
         Attribute("PKCS9.ChallengePassword",
                   DER_Encoder().encode(challenge).get_contents()
            )
         );
      }

   tbs_req.encode(
      Attribute("PKCS9.ExtensionRequest",
                DER_Encoder()
                   .start_cons(SEQUENCE)
                      .encode(extensions)
                   .end_cons()
               .get_contents()
         )
      )
      .end_explicit()
      .end_cons();

   DataSource_Memory source(
      X509_Object::make_signed(signer.get(),
                               rng,
                               sig_algo,
                               tbs_req.get_contents())
      );

   return PKCS10_Request(source);
   }

}

}
