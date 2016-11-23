/*
* X.509 Certificate Authority
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/x509_ca.h>
#include <botan/pubkey.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/bigint.h>
#include <botan/parsing.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <botan/key_constraint.h>
#include <algorithm>
#include <typeinfo>
#include <iterator>
#include <set>

namespace Botan {

/*
* Load the certificate and private key
*/
X509_CA::X509_CA(const X509_Certificate& c,
                 const Private_Key& key,
                 const std::string& hash_fn,
                 RandomNumberGenerator& rng) : m_cert(c)
   {
   if(!m_cert.is_CA_cert())
      throw Invalid_Argument("X509_CA: This certificate is not for a CA");

   m_signer = choose_sig_format(key, rng, hash_fn, m_ca_sig_algo);
   }

/*
* X509_CA Destructor
*/
X509_CA::~X509_CA()
   {
   delete m_signer;
   }

/*
* Sign a PKCS #10 certificate request
*/
X509_Certificate X509_CA::sign_request(const PKCS10_Request& req,
                                       RandomNumberGenerator& rng,
                                       const X509_Time& not_before,
                                       const X509_Time& not_after)
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

   Extensions extensions;

   extensions.add(
      new Cert_Extension::Basic_Constraints(req.is_CA(), req.path_limit()),
      true);

   if(constraints != NO_CONSTRAINTS)
      {
      extensions.add(new Cert_Extension::Key_Usage(constraints), true);
      }

   extensions.add(new Cert_Extension::Authority_Key_ID(m_cert.subject_key_id()));
   extensions.add(new Cert_Extension::Subject_Key_ID(req.raw_public_key()));

   extensions.add(
      new Cert_Extension::Subject_Alternative_Name(req.subject_alt_name()));

   extensions.add(
      new Cert_Extension::Extended_Key_Usage(req.ex_constraints()));

   return make_cert(m_signer, rng, m_ca_sig_algo,
                    req.raw_public_key(),
                    not_before, not_after,
                    m_cert.subject_dn(), req.subject_dn(),
                    extensions);
   }

/*
* Create a new certificate
*/
X509_Certificate X509_CA::make_cert(PK_Signer* signer,
                                    RandomNumberGenerator& rng,
                                    const AlgorithmIdentifier& sig_algo,
                                    const std::vector<byte>& pub_key,
                                    const X509_Time& not_before,
                                    const X509_Time& not_after,
                                    const X509_DN& issuer_dn,
                                    const X509_DN& subject_dn,
                                    const Extensions& extensions)
   {
   const size_t X509_CERT_VERSION = 3;
   const size_t SERIAL_BITS = 128;

   BigInt serial_no(rng, SERIAL_BITS);

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
      ));;
   // clang-format on
   }

/*
* Create a new, empty CRL
*/
X509_CRL X509_CA::new_crl(RandomNumberGenerator& rng,
                          u32bit next_update) const
   {
   std::vector<CRL_Entry> empty;
   return make_crl(empty, 1, next_update, rng);
   }

/*
* Update a CRL with new entries
*/
X509_CRL X509_CA::update_crl(const X509_CRL& crl,
                             const std::vector<CRL_Entry>& new_revoked,
                             RandomNumberGenerator& rng,
                             u32bit next_update) const
   {
   std::vector<CRL_Entry> revoked = crl.get_revoked();

   std::copy(new_revoked.begin(), new_revoked.end(),
             std::back_inserter(revoked));

   return make_crl(revoked, crl.crl_number() + 1, next_update, rng);
   }

/*
* Create a CRL
*/
X509_CRL X509_CA::make_crl(const std::vector<CRL_Entry>& revoked,
                           u32bit crl_number, u32bit next_update,
                           RandomNumberGenerator& rng) const
   {
   const size_t X509_CRL_VERSION = 2;

   if(next_update == 0)
      next_update = timespec_to_u32bit("7d");

   // Totally stupid: ties encoding logic to the return of std::time!!
   auto current_time = std::chrono::system_clock::now();
   auto expire_time = current_time + std::chrono::seconds(next_update);

   Extensions extensions;
   extensions.add(
      new Cert_Extension::Authority_Key_ID(m_cert.subject_key_id()));
   extensions.add(new Cert_Extension::CRL_Number(crl_number));

   // clang-format off
   const std::vector<byte> crl = X509_Object::make_signed(
      m_signer, rng, m_ca_sig_algo,
      DER_Encoder().start_cons(SEQUENCE)
         .encode(X509_CRL_VERSION-1)
         .encode(m_ca_sig_algo)
         .encode(m_cert.issuer_dn())
         .encode(X509_Time(current_time))
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
   return m_cert;
   }

/*
* Choose a signing format for the key
*/
PK_Signer* choose_sig_format(const Private_Key& key,
                             RandomNumberGenerator& rng,
                             const std::string& hash_fn,
                             AlgorithmIdentifier& sig_algo)
   {
   const std::string algo_name = key.algo_name();

   std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw(hash_fn));

   std::string padding;
   if(algo_name == "RSA")
      {
      padding = "EMSA3";
      }
   else if(algo_name == "DSA" ||
           algo_name == "ECDSA" ||
           algo_name == "ECGDSA" ||
           algo_name == "ECKCDSA" ||
           algo_name == "GOST-34.10")
      {
      padding = "EMSA1";
      }
   else
      {
      throw Invalid_Argument("Unknown X.509 signing key type: " + algo_name);
      }

   const Signature_Format format = (key.message_parts() > 1) ? DER_SEQUENCE : IEEE_1363;

   padding = padding + "(" + hash->name() + ")";

   sig_algo.oid = OIDS::lookup(algo_name + "/" + padding);
   sig_algo.parameters = key.algorithm_identifier().parameters;

   return new PK_Signer(key, rng, padding, format);
   }

}
