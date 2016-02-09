/*
* (C) 2009 Jack Lloyd
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

Botan::X509_Cert_Options req_opts1()
   {
   Botan::X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");

   opts.uri = "http://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";

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

std::unique_ptr<Botan::Private_Key> make_a_private_key()
   {
#if defined(BOTAN_HAS_ECDSA)
   Botan::EC_Group grp("secp256r1");
   return std::unique_ptr<Botan::Private_Key>(new Botan::ECDSA_PrivateKey(Test::rng(), grp));
#elif defined(BOTAN_HAS_RSA)
   return std::unique_ptr<Botan::Private_Key>(new Botan::RSA_PrivateKey(Test::rng(), 1024));
#elif defined(BOTAN_HAS_DSA)
   Botan::DL_Group grp("dsa/botan/2048");
   return std::unique_ptr<Botan::Private_Key>(new Botan::DSA_PrivateKey(Test::rng(), grp));
#else
   return std::unique_ptr<Botan::Private_Key>(nullptr);
#endif
   }

class X509_Cert_Unit_Tests : public Test
   {
   public:
      std::vector<Test::Result> run() override;

   private:
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
   };

std::vector<Test::Result> X509_Cert_Unit_Tests::run()
   {
   std::vector<Test::Result> results;
   Test::Result result("X509 Unit");

   const std::string hash_fn = "SHA-256";

   /* Create the CA's key and self-signed cert */
   std::unique_ptr<Botan::Private_Key> ca_key(make_a_private_key());

   if(!ca_key)
      {
      // Failure because X.509 enabled but no RSA or ECDSA seems off
      result.test_failure("Skipping due to no enabled signature algorithms");
      results.push_back(result);
      return results;
      }

   Botan::X509_Certificate ca_cert =
      Botan::X509::create_self_signed_cert(ca_opts(),
                                           *ca_key,
                                           hash_fn,
                                           Test::rng());

   /* Create user #1's key and cert request */
   std::unique_ptr<Botan::Private_Key> user1_key(make_a_private_key());

   Botan::PKCS10_Request user1_req =
      Botan::X509::create_cert_req(req_opts1(),
                                   *user1_key,
                                   hash_fn,
                                   Test::rng());

   /* Create user #2's key and cert request */
   std::unique_ptr<Botan::Private_Key> user2_key(make_a_private_key());

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

   Botan::X509_Certificate user2_cert = ca.sign_request(user2_req, Test::rng(),
                                                 from_date(2008, 01, 01),
                                                 from_date(2033, 01, 01));
   Botan::X509_CRL crl1 = ca.new_crl(Test::rng());

   /* Verify the certs */
   Botan::Certificate_Store_In_Memory store;

   store.add_certificate(ca_cert);

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

   results.push_back(result);
   results.push_back(test_x509_dates());
   return results;
   }

BOTAN_REGISTER_TEST("unit_x509", X509_Cert_Unit_Tests);

#endif

}

}
