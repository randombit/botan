/*
* (C) 2009 Jack Lloyd
* (C) 2016 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)

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

#if defined(BOTAN_HAS_ECGDSA)
  #include <botan/ecgdsa.h>
#endif

#if defined(BOTAN_HAS_ECKCDSA)
  #include <botan/eckcdsa.h>
#endif

#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)

Botan::X509_Time from_date(const int y, const int m, const int d)
   {
   Botan::calendar_point t(y, m, d, 0, 0, 0);
   return Botan::X509_Time(t.to_std_timepoint());
   }

/* Return some option sets */
Botan::X509_Cert_Options ca_opts()
   {
   Botan::X509_Cert_Options opts("Test CA/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   opts.CA_key(1);

   return opts;
   }

Botan::X509_Cert_Options req_opts1(const std::string& algo)
   {
   Botan::X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   opts.not_before("1601012000Z");
   opts.not_after("3001012000Z");

   if(algo == "RSA")
      {
      opts.constraints = Botan::Key_Constraints(Botan::KEY_ENCIPHERMENT);
      }
   else if(algo == "DSA" || algo == "ECDSA" || algo == "ECGDSA" || algo == "ECKCDSA")
      {
      opts.constraints = Botan::Key_Constraints(Botan::DIGITAL_SIGNATURE);
      }

   return opts;
   }

Botan::X509_Cert_Options req_opts2()
   {
   Botan::X509_Cert_Options opts("Test User 2/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

   opts.add_ex_constraint("PKIX.EmailProtection");

   return opts;
   }

std::unique_ptr<Botan::Private_Key> make_a_private_key(const std::string& algo)
   {
#if defined(BOTAN_HAS_RSA)
   if(algo == "RSA")
      {
      return std::unique_ptr<Botan::Private_Key>(new Botan::RSA_PrivateKey(Test::rng(), 1024));
      }
#endif
#if defined(BOTAN_HAS_DSA)
   if(algo == "DSA")
      {
      Botan::DL_Group grp("dsa/botan/2048");
      return std::unique_ptr<Botan::Private_Key>(new Botan::DSA_PrivateKey(Test::rng(), grp));
      }
#endif
#if defined(BOTAN_HAS_ECDSA)
   if(algo == "ECDSA")
      {
      Botan::EC_Group grp("secp256r1");
      return std::unique_ptr<Botan::Private_Key>(new Botan::ECDSA_PrivateKey(Test::rng(), grp));
      }
#endif
#if defined(BOTAN_HAS_ECGDSA)
   if(algo == "ECGDSA")
      {
      Botan::EC_Group grp("brainpool256r1");
      return std::unique_ptr<Botan::Private_Key>(new Botan::ECGDSA_PrivateKey(Test::rng(), grp));
      }
#endif
#if defined(BOTAN_HAS_ECKCDSA)
   if(algo == "ECKCDSA")
      {
      Botan::EC_Group grp("brainpool256r1");
      return std::unique_ptr<Botan::Private_Key>(new Botan::ECKCDSA_PrivateKey(Test::rng(), grp));
      }
#endif
   return std::unique_ptr<Botan::Private_Key>(nullptr);
   }


Test::Result test_x509_dates()
   {
   Test::Result result("X509_Time");

   Botan::X509_Time time;
   result.confirm("unset time not set", !time.time_is_set());
   time = Botan::X509_Time("0802011822Z", Botan::ASN1_Tag::UTC_TIME);
   result.confirm("time set after construction", time.time_is_set());
   result.test_eq("time readable_string", time.readable_string(), "2008/02/01 18:22:00 UTC");

   const std::vector<std::string> valid = {
      "0802010000Z",
      "0802011724Z",
      "0406142334Z",
      "9906142334Z",
      "0006142334Z",

      "080201000000Z",
      "080201172412Z",
      "040614233433Z",
      "990614233444Z",
      "000614233455Z",
   };

   // Dates that are valid per X.500 but rejected as unsupported
   const std::vector<std::string> valid_but_unsup = {
      "0802010000-0000",
      "0802011724+0000",
      "0406142334-0500",
      "9906142334+0500",
      "0006142334-0530",
      "0006142334+0530",

      "080201000000-0000",
      "080201172412+0000",
      "040614233433-0500",
      "990614233444+0500",
      "000614233455-0530",
      "000614233455+0530",
   };

   const std::vector<std::string> invalid = {
      "",
      " ",
      "2008`02-01",
      "9999-02-01",
      "2000-02-01 17",
      "999921",

      // valid length 13 -> range check
      "080201000061Z", // seconds too big (61)
      "080201000060Z", // seconds too big (60, leap seconds not covered by the standard)
      "0802010000-1Z", // seconds too small (-1)
      "080201006000Z", // minutes too big (60)
      "080201240000Z", // hours too big (24:00)

      // valid length 13 -> invalid numbers
      "08020123112 Z",
      "08020123112!Z",
      "08020123112,Z",
      "08020123112\nZ",
      "080201232 33Z",
      "080201232!33Z",
      "080201232,33Z",
      "080201232\n33Z",
      "0802012 3344Z",
      "0802012!3344Z",
      "0802012,3344Z",
      "08022\n334455Z",
      "08022 334455Z",
      "08022!334455Z",
      "08022,334455Z",
      "08022\n334455Z",
      "082 33445511Z",
      "082!33445511Z",
      "082,33445511Z",
      "082\n33445511Z",
      "2 2211221122Z",
      "2!2211221122Z",
      "2,2211221122Z",
      "2\n2211221122Z",

      // wrong time zone
      "0802010000",
      "0802010000z"
   };

   for(auto&& v : valid)
      {
      Botan::X509_Time t(v, Botan::ASN1_Tag::UTC_TIME);
      }

   for(auto&& v : valid_but_unsup)
      {
      result.test_throws("valid but unsupported", [v]() { Botan::X509_Time t(v, Botan::ASN1_Tag::UTC_TIME); });
      }

   for(auto&& v : invalid)
      {
      result.test_throws("invalid", [v]() { Botan::X509_Time t(v, Botan::ASN1_Tag::UTC_TIME); });
      }

   return result;
   }

Test::Result test_x509_cert(const std::string& sig_algo, const std::string& hash_fn = "SHA-256")
   {
   Test::Result result("X509 Unit");

   /* Create the CA's key and self-signed cert */
   std::unique_ptr<Botan::Private_Key> ca_key(make_a_private_key(sig_algo));

   if(!ca_key)
      {
      // Failure because X.509 enabled but requested signature algorithm is not present
      result.test_note("Skipping due to missing signature algorithm: " + sig_algo);
      return result;
      }

   /* Create the self-signed cert */
   Botan::X509_Certificate ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts(),
                                           *ca_key,
                                           hash_fn,
                                           Test::rng());

   result.test_eq("ca key usage", (ca_cert.constraints() & Botan::Key_Constraints(Botan::KEY_CERT_SIGN | Botan::CRL_SIGN)) ==
         Botan::Key_Constraints(Botan::KEY_CERT_SIGN | Botan::CRL_SIGN), true);

   /* Create user #1's key and cert request */
   std::unique_ptr<Botan::Private_Key> user1_key(make_a_private_key(sig_algo));

   Botan::PKCS10_Request user1_req =
      Botan::X509::create_cert_req(req_opts1(sig_algo),
                                   *user1_key,
                                   hash_fn,
                                   Test::rng());

   /* Create user #2's key and cert request */
   std::unique_ptr<Botan::Private_Key> user2_key(make_a_private_key(sig_algo));

   Botan::PKCS10_Request user2_req =
      Botan::X509::create_cert_req(req_opts2(),
                                   *user2_key,
                                   hash_fn,
                                   Test::rng());

   /* Create the CA object */
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn);

   /* Sign the requests to create the certs */
   Botan::X509_Certificate user1_cert =
      ca.sign_request(user1_req, Test::rng(),
                      from_date(2008, 01, 01),
                      from_date(2033, 01, 01));

   Botan::X509_Certificate user2_cert =
      ca.sign_request(user2_req, Test::rng(),
                      from_date(2008, 01, 01),
                      from_date(2033, 01, 01));

   result.test_eq("user1 key usage", (user1_cert.constraints() & req_opts1(sig_algo).constraints) == req_opts1(sig_algo).constraints, true);

   /* Copy, assign and compare */
   Botan::X509_Certificate user1_cert_copy(user1_cert);
   result.test_eq("certificate copy", user1_cert == user1_cert_copy, true);

   user1_cert_copy = user1_cert;
   result.test_eq("certificate assignment", user1_cert == user1_cert_copy, true);

   Botan::X509_Certificate user1_cert_differ =
      ca.sign_request(user1_req, Test::rng(),
                      from_date(2008, 01, 01),
                      from_date(2032, 01, 01));

   result.test_eq("certificate differs", user1_cert == user1_cert_differ, false);

   /* Get cert data */
   result.test_eq("x509 version", user1_cert.x509_version(), size_t(3));

   result.test_eq("issuer info CN", user1_cert.issuer_info("CN").at(0), ca_opts().common_name);
   result.test_eq("issuer info Country", user1_cert.issuer_info("C").at(0), ca_opts().country);
   result.test_eq("issuer info Orga", user1_cert.issuer_info("O").at(0), ca_opts().organization);
   result.test_eq("issuer info OrgaUnit", user1_cert.issuer_info("OU").at(0), ca_opts().org_unit);

   Botan::X509_CRL crl1 = ca.new_crl(Test::rng());

   /* Verify the certs */
   Botan::Certificate_Store_In_Memory store;

   store.add_certificate(ca.ca_certificate());

   Botan::Path_Validation_Restrictions restrictions(false);

   Botan::Path_Validation_Result result_u1 = Botan::x509_path_validate(user1_cert, restrictions, store);
   if(!result.confirm("user 1 validates", result_u1.successful_validation()))
      {
      result.test_note("user 1 validation result was " + result_u1.result_string());
      }

   Botan::Path_Validation_Result result_u2 = Botan::x509_path_validate(user2_cert, restrictions, store);
   if(!result.confirm("user 2 validates", result_u2.successful_validation()))
      {
      result.test_note("user 2 validation result was " + result_u2.result_string());
      }

   store.add_crl(crl1);

   std::vector<Botan::CRL_Entry> revoked;
   revoked.push_back(Botan::CRL_Entry(user1_cert, Botan::CESSATION_OF_OPERATION));
   revoked.push_back(user2_cert);

   Botan::X509_CRL crl2 = ca.update_crl(crl1, revoked, Test::rng());

   store.add_crl(crl2);

   const std::string revoked_str =
      Botan::Path_Validation_Result::status_string(Botan::Certificate_Status_Code::CERT_IS_REVOKED);

   result_u1 = Botan::x509_path_validate(user1_cert, restrictions, store);
   result.test_eq("user 1 revoked", result_u1.result_string(), revoked_str);

   result_u2 = Botan::x509_path_validate(user2_cert, restrictions, store);
   result.test_eq("user 1 revoked", result_u2.result_string(), revoked_str);

   revoked.clear();
   revoked.push_back(Botan::CRL_Entry(user1_cert, Botan::REMOVE_FROM_CRL));
   Botan::X509_CRL crl3 = ca.update_crl(crl2, revoked, Test::rng());

   store.add_crl(crl3);

   result_u1 = Botan::x509_path_validate(user1_cert, restrictions, store);
   if(!result.confirm("user 1 validates", result_u1.successful_validation()))
      {
      result.test_note("user 1 validation result was " + result_u1.result_string());
      }

   result_u2 = Botan::x509_path_validate(user2_cert, restrictions, store);
   result.test_eq("user 2 still revoked", result_u2.result_string(), revoked_str);

   return result;
   }

Test::Result test_usage(const std::string& sig_algo, const std::string& hash_fn = "SHA-256")
   {
   using Botan::Key_Constraints;

   Test::Result result("X509 Usage");

   /* Create the CA's key and self-signed cert */
   std::unique_ptr<Botan::Private_Key> ca_key(make_a_private_key(sig_algo));

   if(!ca_key)
      {
      // Failure because X.509 enabled but requested signature algorithm is not present
      result.test_note("Skipping due to missing signature algorithm: " + sig_algo);
      return result;
      }

   /* Create the self-signed cert */
   Botan::X509_Certificate ca_cert =
        Botan::X509::create_self_signed_cert(ca_opts(),
                                           *ca_key,
                                           hash_fn,
                                           Test::rng());

   /* Create the CA object */
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn);

   std::unique_ptr<Botan::Private_Key> user1_key(make_a_private_key(sig_algo));

   Botan::X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");
   opts.constraints = Key_Constraints::DIGITAL_SIGNATURE;

   Botan::PKCS10_Request user1_req =
        Botan::X509::create_cert_req(opts,
                                      *user1_key,
                                      hash_fn,
                                      Test::rng());

   Botan::X509_Certificate user1_cert =
      ca.sign_request(user1_req, Test::rng(),
                      from_date(2008, 01, 01),
                      from_date(2033, 01, 01));

   // cert only allows digitalSignature, but we check for both digitalSignature and cRLSign
   result.test_eq("key usage cRLSign not allowed", user1_cert.allowed_usage(Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE |
        Key_Constraints::CRL_SIGN)), false);

   // cert only allows digitalSignature, so checking for only that should be ok
   result.confirm("key usage digitalSignature allowed", user1_cert.allowed_usage(Key_Constraints::DIGITAL_SIGNATURE));

   opts.constraints = Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE | Key_Constraints::CRL_SIGN);

   Botan::PKCS10_Request mult_usage_req =
        Botan::X509::create_cert_req(opts,
                                        *user1_key,
                                        hash_fn,
                                        Test::rng());

   Botan::X509_Certificate mult_usage_cert =
         ca.sign_request(mult_usage_req, Test::rng(),
                         from_date(2008, 01, 01),
                         from_date(2033, 01, 01));

   // cert allows multiple usages, so each one of them as well as both together should be allowed
   result.confirm("key usage multiple digitalSignature allowed", mult_usage_cert.allowed_usage(Key_Constraints::DIGITAL_SIGNATURE));
   result.confirm("key usage multiple cRLSign allowed", mult_usage_cert.allowed_usage(Key_Constraints::CRL_SIGN));
   result.confirm("key usage multiple digitalSignature and cRLSign allowed", mult_usage_cert.allowed_usage(
         Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE | Key_Constraints::CRL_SIGN)));

   opts.constraints = Key_Constraints::NO_CONSTRAINTS;

   Botan::PKCS10_Request no_usage_req =
        Botan::X509::create_cert_req(opts,
                                        *user1_key,
                                        hash_fn,
                                        Test::rng());

   Botan::X509_Certificate no_usage_cert =
         ca.sign_request(no_usage_req, Test::rng(),
                         from_date(2008, 01, 01),
                         from_date(2033, 01, 01));

   // cert allows every usage
   result.confirm("key usage digitalSignature allowed", no_usage_cert.allowed_usage(Key_Constraints::DIGITAL_SIGNATURE));
   result.confirm("key usage cRLSign allowed", no_usage_cert.allowed_usage(Key_Constraints::CRL_SIGN));

   return result;
   }

using Botan::Key_Constraints;

/**
* @brief Some typical key usage scenarios (taken from RFC 5280, sec. 4.2.1.3)
*/
struct typical_usage_constraints
   {
   // ALL constraints are not typical at all, but we use them for a negative test
   Key_Constraints all = Key_Constraints(
                           Key_Constraints::DIGITAL_SIGNATURE | Key_Constraints::NON_REPUDIATION | Key_Constraints::KEY_ENCIPHERMENT |
                           Key_Constraints::DATA_ENCIPHERMENT | Key_Constraints::KEY_AGREEMENT | Key_Constraints::KEY_CERT_SIGN |
                           Key_Constraints::CRL_SIGN | Key_Constraints::ENCIPHER_ONLY | Key_Constraints::DECIPHER_ONLY);

   Key_Constraints ca = Key_Constraints(Key_Constraints::KEY_CERT_SIGN);
   Key_Constraints sign_data = Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE);
   Key_Constraints non_repudiation = Key_Constraints(Key_Constraints::NON_REPUDIATION | Key_Constraints::DIGITAL_SIGNATURE);
   Key_Constraints key_encipherment = Key_Constraints(Key_Constraints::KEY_ENCIPHERMENT);
   Key_Constraints data_encipherment = Key_Constraints(Key_Constraints::DATA_ENCIPHERMENT);
   Key_Constraints key_agreement = Key_Constraints(Key_Constraints::KEY_AGREEMENT);
   Key_Constraints key_agreement_encipher_only = Key_Constraints(Key_Constraints::KEY_AGREEMENT | Key_Constraints::ENCIPHER_ONLY);
   Key_Constraints key_agreement_decipher_only = Key_Constraints(Key_Constraints::KEY_AGREEMENT | Key_Constraints::DECIPHER_ONLY);
   Key_Constraints crl_sign = Key_Constraints(Key_Constraints::CRL_SIGN);
   Key_Constraints sign_everything = Key_Constraints(Key_Constraints::DIGITAL_SIGNATURE | Key_Constraints::KEY_CERT_SIGN | Key_Constraints::CRL_SIGN);
   };


Test::Result test_valid_constraints(const std::string& pk_algo)
   {
   Test::Result result("X509 Valid Constraints");

   std::unique_ptr<Botan::Private_Key> key(make_a_private_key(pk_algo));

   if(!key)
      {
      // Failure because X.509 enabled but requested algorithm is not present
      result.test_note("Skipping due to missing signature algorithm: " + pk_algo);
      return result;
      }

   // should not throw on empty constraints
   verify_cert_constraints_valid_for_key_type(*key, Key_Constraints(Key_Constraints::NO_CONSTRAINTS));

   // now check some typical usage scenarios for the given key type
   typical_usage_constraints typical_usage;

   if(pk_algo == "DH" || pk_algo == "ECDH")
      {
      // DH and ECDH only for key agreement
      result.test_throws("all constraints not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.all); });
      result.test_throws("cert sign not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.ca); });
      result.test_throws("signature not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.sign_data); });
      result.test_throws("non repudiation not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.non_repudiation); });
      result.test_throws("key encipherment not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_encipherment); });
      result.test_throws("data encipherment not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.data_encipherment); });

      verify_cert_constraints_valid_for_key_type(*key, typical_usage.key_agreement);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.key_agreement_encipher_only);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.key_agreement_decipher_only);

      result.test_throws("crl sign not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.crl_sign); });
      result.test_throws("sign, cert sign, crl sign not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.sign_everything); });
      }
   else if(pk_algo == "RSA")
      {
      // RSA can do everything except key agreement
      result.test_throws("all constraints not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.all); });

      verify_cert_constraints_valid_for_key_type(*key, typical_usage.ca);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.sign_data);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.non_repudiation);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.key_encipherment);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.data_encipherment);

      result.test_throws("key agreement not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement); });
      result.test_throws("key agreement, encipher only not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement_encipher_only); });
      result.test_throws("key agreement, decipher only not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement_decipher_only); });

      verify_cert_constraints_valid_for_key_type(*key, typical_usage.crl_sign);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.sign_everything);
      }
   else if(pk_algo == "ElGamal")
      {
      // only ElGamal encryption is currently implemented
      result.test_throws("all constraints not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.all); });
      result.test_throws("cert sign not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.ca); });

      verify_cert_constraints_valid_for_key_type(*key, typical_usage.non_repudiation);

      result.test_throws("key encipherment not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_encipherment); });
      result.test_throws("data encipherment not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.data_encipherment); });

      result.test_throws("key agreement not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement); });
      result.test_throws("key agreement, encipher only not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement_encipher_only); });
      result.test_throws("key agreement, decipher only not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement_decipher_only); });
      result.test_throws("crl sign not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.crl_sign); });
      result.test_throws("sign, cert sign, crl sign not permitted not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.sign_everything); });
      }
   else if(pk_algo == "RW" || pk_algo == "NR" || pk_algo == "DSA" ||
         pk_algo == "ECDSA" || pk_algo == "ECGDSA" || pk_algo == "ECKCDSA")
      {
      // these are signature algorithms only
      result.test_throws("all constraints not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.all); });

      verify_cert_constraints_valid_for_key_type(*key, typical_usage.ca);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.sign_data);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.non_repudiation);

      result.test_throws("key encipherment not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_encipherment); });
      result.test_throws("data encipherment not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.data_encipherment); });
      result.test_throws("key agreement not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement); });
      result.test_throws("key agreement, encipher only not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement_encipher_only); });
      result.test_throws("key agreement, decipher only not permitted", [&key, &typical_usage]() { verify_cert_constraints_valid_for_key_type(*key,
            typical_usage.key_agreement_decipher_only); });

      verify_cert_constraints_valid_for_key_type(*key, typical_usage.crl_sign);
      verify_cert_constraints_valid_for_key_type(*key, typical_usage.sign_everything);
      }

   return result;
   }


class X509_Cert_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;
         const std::vector<std::string> sig_algos { "RSA", "DSA", "ECDSA", "ECGDSA", "ECKCDSA" };
         Test::Result cert_result("X509 Unit");
         Test::Result usage_result("X509 Usage");

         for(const auto& algo : sig_algos)
            {
            cert_result.merge(test_x509_cert(algo));
            usage_result.merge(test_usage(algo));
            }

         results.push_back(cert_result);
         results.push_back(usage_result);

         const std::vector<std::string> pk_algos { "DH", "ECDH", "RSA", "ElGamal", "RW", "NR",
                                                   "DSA", "ECDSA", "ECGDSA", "ECKCDSA" };
         Test::Result valid_constraints_result("X509 Valid Constraints");

         for(const auto& algo : pk_algos)
            {
            valid_constraints_result.merge(test_valid_constraints(algo));
            }

         results.push_back(valid_constraints_result);
         results.push_back(test_x509_dates());

         return results;
         }
   };

BOTAN_REGISTER_TEST("unit_x509", X509_Cert_Unit_Tests);

#endif

}

}
