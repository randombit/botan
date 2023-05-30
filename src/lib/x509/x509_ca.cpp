/*
* X.509 Certificate Authority
* (C) 1999-2010,2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ca.h>

#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/pkcs10.h>
#include <botan/pubkey.h>
#include <botan/x509_ext.h>
#include <botan/x509_key.h>

namespace Botan {

/*
* Load the certificate and private key
*/
X509_CA::X509_CA(const X509_Certificate& cert,
                 const Private_Key& key,
                 std::string_view hash_fn,
                 std::string_view padding_method,
                 RandomNumberGenerator& rng) :
      m_ca_cert(cert) {
   if(!m_ca_cert.is_CA_cert()) {
      throw Invalid_Argument("X509_CA: This certificate is not for a CA");
   }

   m_signer = X509_Object::choose_sig_format(key, rng, hash_fn, padding_method);
   m_ca_sig_algo = m_signer->algorithm_identifier();
   m_hash_fn = m_signer->hash_function();
}

X509_CA::~X509_CA() = default;

Extensions X509_CA::choose_extensions(const PKCS10_Request& req,
                                      const X509_Certificate& ca_cert,
                                      std::string_view hash_fn) {
   const auto constraints = req.is_CA() ? Key_Constraints::ca_constraints() : req.constraints();

   auto key = req.subject_public_key();
   if(!constraints.compatible_with(*key)) {
      throw Invalid_Argument("The requested key constraints are incompatible with the algorithm");
   }

   Extensions extensions = req.extensions();

   extensions.replace(std::make_unique<Cert_Extension::Basic_Constraints>(req.is_CA(), req.path_limit()), true);

   if(!constraints.empty()) {
      extensions.replace(std::make_unique<Cert_Extension::Key_Usage>(constraints), true);
   }

   extensions.replace(std::make_unique<Cert_Extension::Authority_Key_ID>(ca_cert.subject_key_id()));
   extensions.replace(std::make_unique<Cert_Extension::Subject_Key_ID>(req.raw_public_key(), hash_fn));

   extensions.replace(std::make_unique<Cert_Extension::Subject_Alternative_Name>(req.subject_alt_name()));

   extensions.replace(std::make_unique<Cert_Extension::Extended_Key_Usage>(req.ex_constraints()));

   return extensions;
}

X509_Certificate X509_CA::sign_request(const PKCS10_Request& req,
                                       RandomNumberGenerator& rng,
                                       const BigInt& serial_number,
                                       const X509_Time& not_before,
                                       const X509_Time& not_after) const {
   auto extensions = choose_extensions(req, m_ca_cert, m_hash_fn);

   return make_cert(*m_signer,
                    rng,
                    serial_number,
                    algorithm_identifier(),
                    req.raw_public_key(),
                    not_before,
                    not_after,
                    ca_certificate().subject_dn(),
                    req.subject_dn(),
                    extensions);
}

/*
* Sign a PKCS #10 certificate request
*/
X509_Certificate X509_CA::sign_request(const PKCS10_Request& req,
                                       RandomNumberGenerator& rng,
                                       const X509_Time& not_before,
                                       const X509_Time& not_after) const {
   auto extensions = choose_extensions(req, m_ca_cert, m_hash_fn);

   return make_cert(*m_signer,
                    rng,
                    algorithm_identifier(),
                    req.raw_public_key(),
                    not_before,
                    not_after,
                    ca_certificate().subject_dn(),
                    req.subject_dn(),
                    extensions);
}

X509_Certificate X509_CA::make_cert(PK_Signer& signer,
                                    RandomNumberGenerator& rng,
                                    const AlgorithmIdentifier& sig_algo,
                                    const std::vector<uint8_t>& pub_key,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after,
                                    const X509_DN& issuer_dn,
                                    const X509_DN& subject_dn,
                                    const Extensions& extensions) {
   const size_t SERIAL_BITS = 128;
   BigInt serial_no(rng, SERIAL_BITS);

   return make_cert(
      signer, rng, serial_no, sig_algo, pub_key, not_before, not_after, issuer_dn, subject_dn, extensions);
}

/*
* Create a new certificate
*/
X509_Certificate X509_CA::make_cert(PK_Signer& signer,
                                    RandomNumberGenerator& rng,
                                    const BigInt& serial_no,
                                    const AlgorithmIdentifier& sig_algo,
                                    const std::vector<uint8_t>& pub_key,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after,
                                    const X509_DN& issuer_dn,
                                    const X509_DN& subject_dn,
                                    const Extensions& extensions) {
   const size_t X509_CERT_VERSION = 3;

   // clang-format off
   return X509_Certificate(X509_Object::make_signed(
      signer, rng, sig_algo,
      DER_Encoder().start_sequence()
         .start_explicit(0)
            .encode(X509_CERT_VERSION-1)
         .end_explicit()

         .encode(serial_no)

         .encode(sig_algo)
         .encode(issuer_dn)

         .start_sequence()
            .encode(not_before)
            .encode(not_after)
         .end_cons()

         .encode(subject_dn)
         .raw_bytes(pub_key)

         .start_explicit(3)
            .start_sequence()
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
X509_CRL X509_CA::new_crl(RandomNumberGenerator& rng, uint32_t next_update) const {
   return new_crl(rng, std::chrono::system_clock::now(), std::chrono::seconds(next_update));
}

/*
* Update a CRL with new entries
*/
X509_CRL X509_CA::update_crl(const X509_CRL& crl,
                             const std::vector<CRL_Entry>& new_revoked,
                             RandomNumberGenerator& rng,
                             uint32_t next_update) const {
   return update_crl(crl, new_revoked, rng, std::chrono::system_clock::now(), std::chrono::seconds(next_update));
}

X509_CRL X509_CA::new_crl(RandomNumberGenerator& rng,
                          std::chrono::system_clock::time_point issue_time,
                          std::chrono::seconds next_update) const {
   std::vector<CRL_Entry> empty;
   return make_crl(empty, 1, rng, issue_time, next_update);
}

X509_CRL X509_CA::update_crl(const X509_CRL& last_crl,
                             const std::vector<CRL_Entry>& new_revoked,
                             RandomNumberGenerator& rng,
                             std::chrono::system_clock::time_point issue_time,
                             std::chrono::seconds next_update) const {
   std::vector<CRL_Entry> revoked = last_crl.get_revoked();

   std::copy(new_revoked.begin(), new_revoked.end(), std::back_inserter(revoked));

   return make_crl(revoked, last_crl.crl_number() + 1, rng, issue_time, next_update);
}

/*
* Create a CRL
*/
X509_CRL X509_CA::make_crl(const std::vector<CRL_Entry>& revoked,
                           uint32_t crl_number,
                           RandomNumberGenerator& rng,
                           std::chrono::system_clock::time_point issue_time,
                           std::chrono::seconds next_update) const {
   const size_t X509_CRL_VERSION = 2;

   auto expire_time = issue_time + next_update;

   Extensions extensions;
   extensions.add(std::make_unique<Cert_Extension::Authority_Key_ID>(m_ca_cert.subject_key_id()));
   extensions.add(std::make_unique<Cert_Extension::CRL_Number>(crl_number));

   // clang-format off
   const std::vector<uint8_t> crl = X509_Object::make_signed(
      *m_signer, rng, m_ca_sig_algo,
      DER_Encoder().start_sequence()
         .encode(X509_CRL_VERSION-1)
         .encode(m_ca_sig_algo)
         .encode(m_ca_cert.subject_dn())
         .encode(X509_Time(issue_time))
         .encode(X509_Time(expire_time))
         .encode_if(!revoked.empty(),
              DER_Encoder()
                 .start_sequence()
                    .encode_list(revoked)
                 .end_cons()
            )
         .start_explicit(0)
            .start_sequence()
               .encode(extensions)
            .end_cons()
         .end_explicit()
      .end_cons()
      .get_contents());
   // clang-format on

   return X509_CRL(crl);
}

}  // namespace Botan
