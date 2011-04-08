/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/


#include <botan/filters.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_X509_CERTIFICATES)
  #include <botan/x509self.h>
  #include <botan/x509stor.h>
  #include <botan/x509_ca.h>
  #include <botan/pkcs10.h>
#endif

using namespace Botan;

#include <iostream>
#include <memory>

#include "validate.h"
#include "common.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES) && \
    defined(BOTAN_HAS_RSA) && \
    defined(BOTAN_HAS_DSA)

namespace {

u64bit key_id(const Public_Key* key)
   {
   Pipe pipe(new Hash_Filter("SHA-1", 8));
   pipe.start_msg();
   pipe.write(key->algo_name());
   pipe.write(key->algorithm_identifier().parameters);
   pipe.write(key->x509_subject_public_key());
   pipe.end_msg();

   SecureVector<byte> output = pipe.read_all();

   if(output.size() != 8)
      throw Internal_Error("Public_Key::key_id: Incorrect output size");

   u64bit id = 0;
   for(u32bit j = 0; j != 8; ++j)
      id = (id << 8) | output[j];
   return id;
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
      std::cout << "Failed copy check for " << orig.algo_name() << "\n";
      return 1;
      }
   return 0;
   }

}

void do_x509_tests(RandomNumberGenerator& rng)
   {
   std::cout << "Testing X.509 CA/CRL/cert/cert request: " << std::flush;

   std::string hash_fn = "SHA-256";

   /* Create the CA's key and self-signed cert */
   std::cout << '.' << std::flush;
   RSA_PrivateKey ca_key(rng, 1024);

   std::cout << '.' << std::flush;
   X509_Certificate ca_cert = X509::create_self_signed_cert(ca_opts(),
                                                            ca_key,
                                                            hash_fn,
                                                            rng);
   std::cout << '.' << std::flush;

   /* Create user #1's key and cert request */
   std::cout << '.' << std::flush;
   DSA_PrivateKey user1_key(rng, DL_Group("dsa/jce/1024"));

   std::cout << '.' << std::flush;
   PKCS10_Request user1_req = X509::create_cert_req(req_opts1(),
                                                    user1_key,
                                                    "SHA-1",
                                                    rng);

   /* Create user #2's key and cert request */
   std::cout << '.' << std::flush;
#if defined(BOTAN_HAS_ECDSA)
   EC_Group ecc_domain(OID("1.2.840.10045.3.1.7"));
   ECDSA_PrivateKey user2_key(rng, ecc_domain);
#else
   RSA_PrivateKey user2_key(rng, 1024);
#endif

   std::cout << '.' << std::flush;
   PKCS10_Request user2_req = X509::create_cert_req(req_opts2(),
                                                    user2_key,
                                                    hash_fn,
                                                    rng);

   /* Create the CA object */
   std::cout << '.' << std::flush;
   X509_CA ca(ca_cert, ca_key, hash_fn);
   std::cout << '.' << std::flush;

   /* Sign the requests to create the certs */
   std::cout << '.' << std::flush;
   X509_Certificate user1_cert =
      ca.sign_request(user1_req, rng,
                      X509_Time("2008-01-01"), X509_Time("2100-01-01"));

   std::cout << '.' << std::flush;
   X509_Certificate user2_cert = ca.sign_request(user2_req, rng,
                                                 X509_Time("2008-01-01"),
                                                 X509_Time("2100-01-01"));
   std::cout << '.' << std::flush;

   X509_CRL crl1 = ca.new_crl(rng);

   /* Verify the certs */
   X509_Store store;

   store.add_cert(ca_cert, true); // second arg == true: trusted CA cert

   std::cout << '.' << std::flush;
   if(store.validate_cert(user1_cert) != VERIFIED)
      std::cout << "\nFAILED: User cert #1 did not validate" << std::endl;

   if(store.validate_cert(user2_cert) != VERIFIED)
      std::cout << "\nFAILED: User cert #2 did not validate" << std::endl;

   if(store.add_crl(crl1) != VERIFIED)
      std::cout << "\nFAILED: CRL #1 did not validate" << std::endl;

   std::vector<CRL_Entry> revoked;
   revoked.push_back(CRL_Entry(user1_cert, CESSATION_OF_OPERATION));
   revoked.push_back(user2_cert);

   X509_CRL crl2 = ca.update_crl(crl1, revoked, rng);

   if(store.add_crl(crl2) != VERIFIED)
      std::cout << "\nFAILED: CRL #2 did not validate" << std::endl;

   if(store.validate_cert(user1_cert) != CERT_IS_REVOKED)
      std::cout << "\nFAILED: User cert #1 was not revoked" << std::endl;

   if(store.validate_cert(user2_cert) != CERT_IS_REVOKED)
      std::cout << "\nFAILED: User cert #2 was not revoked" << std::endl;

   revoked.clear();
   revoked.push_back(CRL_Entry(user1_cert, REMOVE_FROM_CRL));
   X509_CRL crl3 = ca.update_crl(crl2, revoked, rng);

   if(store.add_crl(crl3) != VERIFIED)
      std::cout << "\nFAILED: CRL #3 did not validate" << std::endl;

   if(store.validate_cert(user1_cert) != VERIFIED)
      std::cout << "\nFAILED: User cert #1 was not un-revoked" << std::endl;

   check_against_copy(ca_key, rng);
   check_against_copy(user1_key, rng);
   check_against_copy(user2_key, rng);

   std::cout << std::endl;
   }

#else

void do_x509_tests(RandomNumberGenerator&)
   {
   std::cout << "Skipping Botan X.509 tests (disabled in build)\n";
   }

#endif

