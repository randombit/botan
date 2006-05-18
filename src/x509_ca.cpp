/*************************************************
* X.509 Certificate Authority Source File        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x509_ca.h>
#include <botan/x509_ext.h>
#include <botan/x509stor.h>
#include <botan/conf.h>
#include <botan/lookup.h>
#include <botan/look_pk.h>
#include <botan/numthry.h>
#include <botan/oids.h>
#include <botan/util.h>
#include <algorithm>
#include <memory>
#include <set>

namespace Botan {

/*************************************************
* Load the certificate and private key           *
*************************************************/
X509_CA::X509_CA(const X509_Certificate& c,
                 const PKCS8_PrivateKey& key) : cert(c)
   {
   const PKCS8_PrivateKey* key_pointer = &key;
   if(!dynamic_cast<const PK_Signing_Key*>(key_pointer))
      throw Invalid_Argument("X509_CA: " + key.algo_name() + " cannot sign");

   if(!cert.is_CA_cert())
      throw Invalid_Argument("X509_CA: This certificate is not for a CA");

   std::string padding;
   Signature_Format format;

   Config::choose_sig_format(key.algo_name(), padding, format);

   ca_sig_algo.oid = OIDS::lookup(key.algo_name() + "/" + padding);
   ca_sig_algo.parameters = key.DER_encode_params();

   const PK_Signing_Key& sig_key = dynamic_cast<const PK_Signing_Key&>(key);
   signer = get_pk_signer(sig_key, padding, format);
   }

/*************************************************
* Sign a PKCS #10 certificate request            *
*************************************************/
X509_Certificate X509_CA::sign_request(const PKCS10_Request& req,
                                       u32bit expire_time) const
   {
   if(req.is_CA() && !Config::get_bool("x509/ca/allow_ca"))
      throw Policy_Violation("X509_CA: Attempted to sign new CA certificate");

   Key_Constraints constraints;
   if(req.is_CA())
      constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
   else
      {
      std::auto_ptr<X509_PublicKey> key(req.subject_public_key());
      constraints = X509::find_constraints(*key, req.constraints());
      }

   if(expire_time == 0)
      expire_time = Config::get_time("x509/ca/default_expire");

   const u64bit current_time = system_time();

   X509_Time not_before(current_time);
   X509_Time not_after(current_time + expire_time);

   return make_cert(signer, ca_sig_algo, req.raw_public_key(),
                    cert.subject_key_id(), not_before, not_after,
                    cert.subject_dn(), req.subject_dn(),
                    req.is_CA(), req.path_limit(), req.subject_alt_name(),
                    AlternativeName(), constraints, req.ex_constraints());
   }

/*************************************************
* Create a new certificate                       *
*************************************************/
X509_Certificate X509_CA::make_cert(PK_Signer* signer,
                                    const AlgorithmIdentifier& sig_algo,
                                    const MemoryRegion<byte>& pub_key,
                                    const MemoryRegion<byte>& auth_key_id,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after,
                                    const X509_DN& issuer_dn,
                                    const X509_DN& subject_dn,
                                    bool is_CA, u32bit path_limit,
                                    const AlternativeName& subject_alt,
                                    const AlternativeName& issuer_alt,
                                    Key_Constraints constraints,
                                    const std::vector<OID>& ex_constraints)
   {
   const u32bit X509_CERT_VERSION = 2;
   const u32bit SERIAL_BITS = 128;

   Extensions extensions;

   extensions.add(new Cert_Extension::Subject_Key_ID(pub_key));
   extensions.add(new Cert_Extension::Authority_Key_ID(auth_key_id));

   extensions.add(
      new Cert_Extension::Basic_Constraints(is_CA, path_limit));

   extensions.add(new Cert_Extension::Key_Usage(constraints));
   extensions.add(
      new Cert_Extension::Extended_Key_Usage(ex_constraints));

   extensions.add(
      new Cert_Extension::Alternative_Name(subject_alt,
                                           "X509v3.SubjectAlternativeName",
                                           "subject_alternative_name")
      );

   extensions.add(
      new Cert_Extension::Alternative_Name(issuer_alt,
                                           "X509v3.IssuerAlternativeName",
                                           "issuer_alternative_name")
      );

   MemoryVector<byte> tbs_bits = 
      DER_Encoder().start_sequence()
         .start_explicit(ASN1_Tag(0))
            .encode(X509_CERT_VERSION)
         .end_explicit(ASN1_Tag(0))

         .encode(random_integer(SERIAL_BITS))
         .encode(sig_algo)
         .encode(issuer_dn)

         .start_sequence()
            .encode(not_before)
            .encode(not_after)
         .end_sequence()

         .encode(subject_dn)
         .add_raw_octets(pub_key)

         .start_explicit(ASN1_Tag(3))
            .start_sequence()
               .encode(extensions)
             .end_sequence()
         .end_explicit(ASN1_Tag(3))
      .end_sequence()
   .get_contents();

   DataSource_Memory source(
      DER_Encoder()
         .start_sequence()
            .add_raw_octets(tbs_bits)
            .encode(sig_algo)
            .encode(signer->sign_message(tbs_bits), BIT_STRING)
         .end_sequence()
      .get_contents()
      );

   return X509_Certificate(source);
   }

/*************************************************
* Create a new, empty CRL                        *
*************************************************/
X509_CRL X509_CA::new_crl(u32bit next_update) const
   {
   std::vector<CRL_Entry> empty;
   return make_crl(empty, 1, next_update);
   }

/*************************************************
* Update a CRL with new entries                  *
*************************************************/
X509_CRL X509_CA::update_crl(const X509_CRL& crl,
                             const std::vector<CRL_Entry>& new_revoked,
                             u32bit next_update) const
   {
   std::vector<CRL_Entry> already_revoked = crl.get_revoked();
   std::vector<CRL_Entry> all_revoked;

   X509_Store store;
   store.add_cert(cert, true);
   if(store.add_crl(crl) != VERIFIED)
      throw Invalid_Argument("X509_CA::update_crl: Invalid CRL provided");

   std::set<SecureVector<byte> > removed_from_crl;
   for(u32bit j = 0; j != new_revoked.size(); ++j)
      {
      if(new_revoked[j].reason == DELETE_CRL_ENTRY)
         removed_from_crl.insert(new_revoked[j].serial);
      else
         all_revoked.push_back(new_revoked[j]);
      }

   for(u32bit j = 0; j != already_revoked.size(); ++j)
      {
      std::set<SecureVector<byte> >::const_iterator i;
      i = removed_from_crl.find(already_revoked[j].serial);

      if(i == removed_from_crl.end())
         all_revoked.push_back(already_revoked[j]);
      }
   std::sort(all_revoked.begin(), all_revoked.end());

   std::vector<CRL_Entry> cert_list;
   std::unique_copy(all_revoked.begin(), all_revoked.end(),
                    std::back_inserter(cert_list));

   return make_crl(cert_list, crl.crl_number() + 1, next_update);
   }

/*************************************************
* Create a CRL                                   *
*************************************************/
X509_CRL X509_CA::make_crl(const std::vector<CRL_Entry>& revoked,
                           u32bit crl_number, u32bit next_update) const
   {
   const u32bit X509_CRL_VERSION = 1;

   if(next_update == 0)
      next_update = Config::get_time("x509/crl/next_update");

   const u64bit current_time = system_time();

   Extensions extensions;
   extensions.add(new Cert_Extension::Authority_Key_ID(cert.subject_key_id()));
   extensions.add(new Cert_Extension::CRL_Number(crl_number));

   DER_Encoder tbs_crl;

   tbs_crl
      .start_sequence()
         .encode(X509_CRL_VERSION)
         .encode(ca_sig_algo)
         .encode(cert.subject_dn())
         .encode(X509_Time(current_time))
         .encode(X509_Time(current_time + next_update));

   if(revoked.size())
      {
      tbs_crl.start_sequence();
      for(u32bit j = 0; j != revoked.size(); ++j)
         DER::encode(tbs_crl, revoked[j]);
      tbs_crl.end_sequence();
      }

   tbs_crl
      .start_explicit(ASN1_Tag(0))
         .start_sequence()
            .encode(extensions)
         .end_sequence()
      .end_explicit(ASN1_Tag(0))
   .end_sequence();

   MemoryVector<byte> tbs_bits = tbs_crl.get_contents();
   MemoryVector<byte> sig = signer->sign_message(tbs_bits);

   DataSource_Memory source(
      DER_Encoder()
         .start_sequence()
            .add_raw_octets(tbs_bits)
            .encode(ca_sig_algo)
            .encode(sig, BIT_STRING)
         .end_sequence()
      .get_contents()
      );

   return X509_CRL(source);
   }

/*************************************************
* Return the CA's certificate                    *
*************************************************/
X509_Certificate X509_CA::ca_certificate() const
   {
   return cert;
   }

/*************************************************
* X509_CA Destructor                             *
*************************************************/
X509_CA::~X509_CA()
   {
   delete signer;
   }

}
