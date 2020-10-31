/*
* X.509 Certificate Authority
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ca.h>
#include <botan/x509_key.h>
#include <botan/x509self.h>
#include <botan/x509_ext.h>
#include <botan/pkix_types.h>
#include <botan/pubkey.h>
#include <botan/der_enc.h>
#include <botan/bigint.h>
#include <botan/parsing.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <botan/emsa.h>
#include <botan/scan_name.h>
#include <algorithm>
#include <iterator>

namespace Botan {

/*
* Load the certificate and private key
*/
X509_CA::X509_CA(const X509_Certificate& c,
                 const Private_Key& key,
                 const std::string& hash_fn,
                 RandomNumberGenerator& rng) :
   m_ca_cert(c),
   m_hash_fn(hash_fn)
   {
   if(!m_ca_cert.is_CA_cert())
      throw Invalid_Argument("X509_CA: This certificate is not for a CA");

   std::map<std::string,std::string> opts;
   // constructor without additional options: use the padding used in the CA certificate
   // sig_oid_str = <sig_alg>/<padding>, so padding with all its options will look
   // like a cipher mode to the scanner
   std::string sig_oid_str = OIDS::oid2str_or_throw(c.signature_algorithm().get_oid());
   SCAN_Name scanner(sig_oid_str);
   std::string pad = scanner.cipher_mode();
   if(!pad.empty())
      opts.insert({"padding",pad});

   m_signer.reset(choose_sig_format(key, opts, rng, hash_fn, m_ca_sig_algo));
   }

/*
* Load the certificate and private key, and additional options
*/
X509_CA::X509_CA(const X509_Certificate& ca_certificate,
        const Private_Key& key,
        const std::map<std::string,std::string>& opts,
        const std::string& hash_fn,
        RandomNumberGenerator& rng) : m_ca_cert(ca_certificate), m_hash_fn(hash_fn)
   {
   if(!m_ca_cert.is_CA_cert())
      throw Invalid_Argument("X509_CA: This certificate is not for a CA");

   m_signer.reset(choose_sig_format(key, opts, rng, hash_fn, m_ca_sig_algo));
   }

/*
* X509_CA Destructor
*/
X509_CA::~X509_CA()
   {
   /* for unique_ptr */
   }

namespace {

Extensions choose_extensions(const PKCS10_Request& req,
                             const X509_Certificate& ca_cert,
                             const std::string& hash_fn)
   {
   Key_Constraints constraints;
   if(req.is_CA())
      {
      constraints = Key_Constraints(KEY_CERT_SIGN | CRL_SIGN);
      }
   else
      {
      std::unique_ptr<Public_Key> key(req.subject_public_key());
      verify_cert_constraints_valid_for_key_type(*key, req.constraints());
      constraints = req.constraints();
      }

   Extensions extensions = req.extensions();

   extensions.replace(
      new Cert_Extension::Basic_Constraints(req.is_CA(), req.path_limit()),
      true);

   if(constraints != NO_CONSTRAINTS)
      {
      extensions.replace(new Cert_Extension::Key_Usage(constraints), true);
      }

   extensions.replace(new Cert_Extension::Authority_Key_ID(ca_cert.subject_key_id()));
   extensions.replace(new Cert_Extension::Subject_Key_ID(req.raw_public_key(), hash_fn));

   extensions.replace(
      new Cert_Extension::Subject_Alternative_Name(req.subject_alt_name()));

   extensions.replace(
      new Cert_Extension::Extended_Key_Usage(req.ex_constraints()));

   return extensions;
   }

}

X509_Certificate X509_CA::sign_request(const PKCS10_Request& req,
                                       RandomNumberGenerator& rng,
                                       const BigInt& serial_number,
                                       const X509_Time& not_before,
                                       const X509_Time& not_after) const
   {
   auto extensions = choose_extensions(req, m_ca_cert, m_hash_fn);

   return make_cert(m_signer.get(), rng, serial_number,
                    m_ca_sig_algo, req.raw_public_key(),
                    not_before, not_after,
                    m_ca_cert.subject_dn(), req.subject_dn(),
                    extensions);
   }

/*
* Sign a PKCS #10 certificate request
*/
X509_Certificate X509_CA::sign_request(const PKCS10_Request& req,
                                       RandomNumberGenerator& rng,
                                       const X509_Time& not_before,
                                       const X509_Time& not_after) const
   {
   auto extensions = choose_extensions(req, m_ca_cert, m_hash_fn);

   return make_cert(m_signer.get(), rng, m_ca_sig_algo,
                    req.raw_public_key(),
                    not_before, not_after,
                    m_ca_cert.subject_dn(), req.subject_dn(),
                    extensions);
   }

X509_Certificate X509_CA::make_cert(PK_Signer* signer,
                                    RandomNumberGenerator& rng,
                                    const AlgorithmIdentifier& sig_algo,
                                    const std::vector<uint8_t>& pub_key,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after,
                                    const X509_DN& issuer_dn,
                                    const X509_DN& subject_dn,
                                    const Extensions& extensions)
   {
   const size_t SERIAL_BITS = 128;
   BigInt serial_no(rng, SERIAL_BITS);

   return make_cert(signer, rng, serial_no, sig_algo, pub_key,
                    not_before, not_after, issuer_dn, subject_dn, extensions);
   }

/*
* Create a new certificate
*/
X509_Certificate X509_CA::make_cert(PK_Signer* signer,
                                    RandomNumberGenerator& rng,
                                    const BigInt& serial_no,
                                    const AlgorithmIdentifier& sig_algo,
                                    const std::vector<uint8_t>& pub_key,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after,
                                    const X509_DN& issuer_dn,
                                    const X509_DN& subject_dn,
                                    const Extensions& extensions)
   {
   const size_t X509_CERT_VERSION = 3;

   // clang-format off
   return X509_Certificate(X509_Object::make_signed(
      signer, rng, sig_algo,
      DER_Encoder().start_cons(SEQUENCE)
         .start_explicit(0)
            .encode(X509_CERT_VERSION-1)
         .end_explicit()

         .encode(serial_no)

         .encode(sig_algo)
         .encode(issuer_dn)

         .start_cons(SEQUENCE)
            .encode(not_before)
            .encode(not_after)
         .end_cons()

         .encode(subject_dn)
         .raw_bytes(pub_key)

         .start_explicit(3)
            .start_cons(SEQUENCE)
               .encode(extensions)
             .end_cons()
         .end_explicit()
      .end_cons()
      .get_contents()
      ));
   // clang-format on
   }

/*
* Create a new, empty CRL
*/
X509_CRL X509_CA::new_crl(RandomNumberGenerator& rng,
                          uint32_t next_update) const
   {
   return new_crl(rng,
                  std::chrono::system_clock::now(),
                  std::chrono::seconds(next_update));
   }

/*
* Update a CRL with new entries
*/
X509_CRL X509_CA::update_crl(const X509_CRL& crl,
                             const std::vector<CRL_Entry>& new_revoked,
                             RandomNumberGenerator& rng,
                             uint32_t next_update) const
   {
   return update_crl(crl, new_revoked, rng,
                     std::chrono::system_clock::now(),
                     std::chrono::seconds(next_update));
   }


X509_CRL X509_CA::new_crl(RandomNumberGenerator& rng,
                          std::chrono::system_clock::time_point issue_time,
                          std::chrono::seconds next_update) const
   {
   std::vector<CRL_Entry> empty;
   return make_crl(empty, 1, rng, issue_time, next_update);
   }

X509_CRL X509_CA::update_crl(const X509_CRL& last_crl,
                             const std::vector<CRL_Entry>& new_revoked,
                             RandomNumberGenerator& rng,
                             std::chrono::system_clock::time_point issue_time,
                             std::chrono::seconds next_update) const
   {
   std::vector<CRL_Entry> revoked = last_crl.get_revoked();

   std::copy(new_revoked.begin(), new_revoked.end(),
             std::back_inserter(revoked));

   return make_crl(revoked, last_crl.crl_number() + 1, rng, issue_time, next_update);
   }

/*
* Create a CRL
*/
X509_CRL X509_CA::make_crl(const std::vector<CRL_Entry>& revoked,
                           uint32_t crl_number,
                           RandomNumberGenerator& rng,
                           std::chrono::system_clock::time_point issue_time,
                           std::chrono::seconds next_update) const
   {
   const size_t X509_CRL_VERSION = 2;

   auto expire_time = issue_time + next_update;

   Extensions extensions;
   extensions.add(new Cert_Extension::Authority_Key_ID(m_ca_cert.subject_key_id()));
   extensions.add(new Cert_Extension::CRL_Number(crl_number));

   // clang-format off
   const std::vector<uint8_t> crl = X509_Object::make_signed(
      m_signer.get(), rng, m_ca_sig_algo,
      DER_Encoder().start_cons(SEQUENCE)
         .encode(X509_CRL_VERSION-1)
         .encode(m_ca_sig_algo)
         .encode(m_ca_cert.subject_dn())
         .encode(X509_Time(issue_time))
         .encode(X509_Time(expire_time))
         .encode_if(revoked.size() > 0,
              DER_Encoder()
                 .start_cons(SEQUENCE)
                    .encode_list(revoked)
                 .end_cons()
            )
         .start_explicit(0)
            .start_cons(SEQUENCE)
               .encode(extensions)
            .end_cons()
         .end_explicit()
      .end_cons()
      .get_contents());
   // clang-format on

   return X509_CRL(crl);
   }

/*
* Return the CA's certificate
*/
X509_Certificate X509_CA::ca_certificate() const
   {
   return m_ca_cert;
   }

/*
* Choose a signing format for the key
*/

PK_Signer* choose_sig_format(const Private_Key& key,
                             RandomNumberGenerator& rng,
                             const std::string& hash_fn,
                             AlgorithmIdentifier& sig_algo)
   {
   return X509_Object::choose_sig_format(sig_algo, key, rng, hash_fn, "").release();
   }

PK_Signer* choose_sig_format(const Private_Key& key,
                             const std::map<std::string,std::string>& opts,
                             RandomNumberGenerator& rng,
                             const std::string& hash_fn,
                             AlgorithmIdentifier& sig_algo)
   {
   std::string padding;
   if(opts.count("padding"))
      padding = opts.at("padding");
   return X509_Object::choose_sig_format(sig_algo, key, rng, hash_fn, padding).release();
   }

}
