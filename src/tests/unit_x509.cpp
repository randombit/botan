/*
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

#if defined(BOTAN_HAS_RSA) && defined(BOTAN_HAS_DSA)

#include <botan/calendar.h>
#include <botan/pkcs8.h>
#include <botan/hash.h>
#include <botan/pkcs10.h>
#include <botan/x509self.h>
#include <botan/x509path.h>
#include <botan/x509_ca.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#include <iostream>
#include <memory>

using namespace Botan;

namespace {

X509_Time from_date(const int y, const int m, const int d)
   {
   auto t = calendar_point(y, m, d, 0, 0, 0);
   return X509_Time(t.to_std_timepoint());
   }

u64bit key_id(const Public_Key* key)
   {
   std::unique_ptr<HashFunction> hash(HashFunction::create("SHA-1"));
   hash->update(key->algo_name());
   hash->update(key->algorithm_identifier().parameters);
   hash->update(key->x509_subject_public_key());
   secure_vector<byte> output = hash->final();
   return load_be<u64bit>(output.data(), 0);
   }


/* Return some option sets */
X509_Cert_Options ca_opts()
   {
   X509_Cert_Options opts("Test CA/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   opts.CA_key(1);

   return opts;
   }

X509_Cert_Options req_opts1()
   {
   X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   return opts;
   }

X509_Cert_Options req_opts2()
   {
   X509_Cert_Options opts("Test User 2/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   opts.add_ex_constraint("PKIX.EmailProtection");

   return opts;
   }

u32bit check_against_copy(const Private_Key& orig,
                          RandomNumberGenerator& rng)
   {
   Private_Key* copy_priv = PKCS8::copy_key(orig, rng);
   Public_Key* copy_pub = X509::copy_key(orig);

   const std::string passphrase= "I need work! -Mr. T";
   DataSource_Memory enc_source(PKCS8::PEM_encode(orig, rng, passphrase));
   Private_Key* copy_priv_enc = PKCS8::load_key(enc_source, rng,
                                                passphrase);

   u64bit orig_id = key_id(&orig);
   u64bit pub_id = key_id(copy_pub);
   u64bit priv_id = key_id(copy_priv);
   u64bit priv_enc_id = key_id(copy_priv_enc);

   delete copy_pub;
   delete copy_priv;
   delete copy_priv_enc;

   if(orig_id != pub_id || orig_id != priv_id || orig_id != priv_enc_id)
      {
      std::cout << "Failed copy check for " << orig.algo_name() << std::endl;
      return 1;
      }
   return 0;
   }

}

size_t test_x509()
   {
   auto& rng = test_rng();
   const std::string hash_fn = "SHA-256";

   size_t fails = 0;

   /* Create the CA's key and self-signed cert */
   RSA_PrivateKey ca_key(rng, 2048);

   X509_Certificate ca_cert = X509::create_self_signed_cert(ca_opts(),
                                                            ca_key,
                                                            hash_fn,
                                                            rng);
   /* Create user #1's key and cert request */
   DSA_PrivateKey user1_key(rng, DL_Group("dsa/botan/2048"));

   PKCS10_Request user1_req = X509::create_cert_req(req_opts1(),
                                                    user1_key,
                                                    "SHA-1",
                                                    rng);

   /* Create user #2's key and cert request */
#if defined(BOTAN_HAS_ECDSA)
   EC_Group ecc_domain(OID("1.2.840.10045.3.1.7"));
   ECDSA_PrivateKey user2_key(rng, ecc_domain);
#else
   RSA_PrivateKey user2_key(rng, 1536);
#endif

   PKCS10_Request user2_req = X509::create_cert_req(req_opts2(),
                                                    user2_key,
                                                    hash_fn,
                                                    rng);

   /* Create the CA object */
   X509_CA ca(ca_cert, ca_key, hash_fn);

   /* Sign the requests to create the certs */
   X509_Certificate user1_cert =
      ca.sign_request(user1_req, rng,
                      from_date(2008, 01, 01), from_date(2033, 01, 01));

   X509_Certificate user2_cert = ca.sign_request(user2_req, rng,
                                                 from_date(2008, 01, 01),
                                                 from_date(2033, 01, 01));
   X509_CRL crl1 = ca.new_crl(rng);

   /* Verify the certs */
   Certificate_Store_In_Memory store;

   store.add_certificate(ca_cert);

   Path_Validation_Restrictions restrictions(false);

   Path_Validation_Result result_u1 = x509_path_validate(user1_cert, restrictions, store);
   if(!result_u1.successful_validation())
      {
      std::cout << "FAILED: User cert #1 did not validate - "
                << result_u1.result_string() << std::endl;
      ++fails;
      }

   Path_Validation_Result result_u2 = x509_path_validate(user2_cert, restrictions, store);
   if(!result_u2.successful_validation())
      {
      std::cout << "FAILED: User cert #2 did not validate - "
                << result_u2.result_string() << std::endl;
      ++fails;
      }

   store.add_crl(crl1);

   std::vector<CRL_Entry> revoked;
   revoked.push_back(CRL_Entry(user1_cert, CESSATION_OF_OPERATION));
   revoked.push_back(user2_cert);

   X509_CRL crl2 = ca.update_crl(crl1, revoked, rng);

   store.add_crl(crl2);

   result_u1 = x509_path_validate(user1_cert, restrictions, store);
   if(result_u1.result() != Certificate_Status_Code::CERT_IS_REVOKED)
      {
      std::cout << "FAILED: User cert #1 was not revoked - "
                << result_u1.result_string() << std::endl;
      ++fails;
      }

   result_u2 = x509_path_validate(user2_cert, restrictions, store);
   if(result_u2.result() != Certificate_Status_Code::CERT_IS_REVOKED)
      {
      std::cout << "FAILED: User cert #2 was not revoked - "
                << result_u2.result_string() << std::endl;
      ++fails;
      }

   revoked.clear();
   revoked.push_back(CRL_Entry(user1_cert, REMOVE_FROM_CRL));
   X509_CRL crl3 = ca.update_crl(crl2, revoked, rng);

   store.add_crl(crl3);

   result_u1 = x509_path_validate(user1_cert, restrictions, store);
   if(!result_u1.successful_validation())
      {
      std::cout << "FAILED: User cert #1 was not un-revoked - "
                << result_u1.result_string() << std::endl;
      ++fails;
      }

   check_against_copy(ca_key, rng);
   check_against_copy(user1_key, rng);
   check_against_copy(user2_key, rng);

   test_report("X509", 0, fails);
   
   return fails;
   }

#else

UNTESTED_WARNING(x509);

#endif // BOTAN_HAS_RSA && BOTAN_HAS_DSA

#else

SKIP_TEST(x509);

#endif // BOTAN_HAS_X509_CERTIFICATES
