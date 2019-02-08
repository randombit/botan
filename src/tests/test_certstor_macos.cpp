/*
* (C) 1999-2019 Jack Lloyd
* (C) 2019      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_CERTSTOR_MACOS)

#include <botan/certstor_macos.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/hex.h>

namespace Botan_Tests {

namespace {

Botan::X509_DN read_dn(const std::string hex)
   {
   Botan::X509_DN dn;
   Botan::BER_Decoder decoder(Botan::hex_decode(hex));
   dn.decode_from(decoder);
   return dn;
   }

Botan::X509_DN get_dn()
   {
   // Public key fingerprint of "DST Root CA X3"
   // This certificate is in the standard "System Roots" of any macOS setup,
   // serves as the trust root of botan.randombit.net and expires on
   // Thursday, 30. September 2021 at 16:01:15 Central European Summer Time
   return read_dn("303f31243022060355040a131b4469676974616c205369676e6174757265"
                  "20547275737420436f2e311730150603550403130e44535420526f6f7420"
                  "4341205833");
   }

std::vector<uint8_t> get_key_id()
   {
   // this is the same as the public key SHA1
   return Botan::hex_decode("c4a7b1a47b2c71fadbe14b9075ffc41560858910");
   }

Botan::X509_DN get_unknown_dn()
   {
   // thats a D-Trust "Test Certificate". It should be fairly likely that
   // _nobody_ will _ever_ have that in their system keychain
   // CN: D-TRUST Limited Basic Test PU CA 1-4 2016
   return read_dn("305b310b300906035504061302444531153013060355040a0c0c442d5472"
                  "75737420476d62483135303306035504030c2c442d5452555354204c696d"
                  "6974656420426173696320526f6f74205465737420505520434120312032"
                  "303135");
   }

Botan::X509_DN get_skewed_dn()
   {
   // This DN contains ASN.1 PrintableString fields that are not 'normalized'
   // according to Apple's idea of a normalized PrintableString field:
   //   (1) It has leading and trailing white space
   //   (2) It contains multiple spaces between 'words'
   return read_dn("304b312a3028060355040a132120204469676974616c2020205369676e61"
                  "7475726520547275737420436f2e2020311d301b06035504031314202044"
                  "5354202020526f6f742043412058332020");
   }

std::vector<uint8_t> get_unknown_key_id()
   {
   // this is the same as the public key SHA1
   return Botan::hex_decode("785c0b67b536eeacbb2b27cf9123301abe7ab09a");
   }

Test::Result open_certificate_store()
   {
   Test::Result result("macOS Certificate Store - Open Keychain");

   try
      {
      result.start_timer();
      Botan::Certificate_Store_MacOS unused;
      result.end_timer();
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   result.test_success();

   return result;
   }

Test::Result find_certificate_by_pubkey_sha1()
   {
   Test::Result result("macOS Certificate Store - Find Certificate by SHA1(pubkey)");

   try
      {
      result.start_timer();
      Botan::Certificate_Store_MacOS certstore;
      auto cert = certstore.find_cert_by_pubkey_sha1(get_key_id());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   result.test_throws("on invalid SHA1 hash data", [&]
      {
      Botan::Certificate_Store_MacOS certstore;
      certstore.find_cert_by_pubkey_sha1({});
      });

   return result;
   }

Test::Result find_cert_by_subject_dn()
   {
   Test::Result result("macOS Certificate Store - Find Certificate by subject DN");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Certificate_Store_MacOS certstore;
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result find_cert_by_subject_dn_and_key_id()
   {
   Test::Result result("macOS Certificate Store - Find Certificate by subject DN and key ID");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Certificate_Store_MacOS certstore;
      auto cert = certstore.find_cert(dn, get_key_id());
      result.end_timer();

      if(result.test_not_null("found certificate", cert.get()))
         {
         auto cns = cert->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result find_certs_by_subject_dn_and_key_id()
   {
   Test::Result result("macOS Certificate Store - Find Certificates by subject DN and key ID");

   try
      {
      auto dn = get_dn();

      result.start_timer();
      Botan::Certificate_Store_MacOS certstore;
      auto certs = certstore.find_all_certs(dn, get_key_id());
      result.end_timer();

      if(result.confirm("result not empty", !certs.empty()) &&
            result.test_eq("exactly one certificate", certs.size(), 1))
         {
         auto cns = certs.front()->subject_dn().get_attribute("CN");
         result.test_is_eq("exactly one CN", cns.size(), 1ul);
         result.test_eq("CN", cns.front(), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result find_all_subjects()
   {
   Test::Result result("macOS Certificate Store - Find all Certificate Subjects");

   try
      {
      result.start_timer();
      Botan::Certificate_Store_MacOS certstore;
      auto subjects = certstore.all_subjects();
      result.end_timer();

      if(result.confirm("result not empty", !subjects.empty()))
         {
         auto dn = get_dn();
         auto needle = std::find_if(subjects.cbegin(),
                                    subjects.cend(),
                                    [=](const Botan::X509_DN &subject)
            {
            return subject == dn;
            });

         if(result.confirm("found expected certificate", needle != subjects.end()))
            {
            result.confirm("expected certificate", *needle == dn);
            }
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result no_certificate_matches()
   {
   Test::Result result("macOS Certificate Store - can deal with no matches (regression test)");

   try
      {
      auto dn  = get_unknown_dn();
      auto kid = get_unknown_key_id();

      result.start_timer();
      Botan::Certificate_Store_MacOS certstore;

      auto certs = certstore.find_all_certs(dn, kid);
      auto cert = certstore.find_cert(dn, kid);
      auto pubk_cert = certstore.find_cert_by_pubkey_sha1(kid);
      result.end_timer();

      result.confirm("find_all_certs did not find the dummy", certs.empty());
      result.confirm("find_cert did not find the dummy", !cert);
      result.confirm("find_cert_by_pubkey_sha1 did not find the dummy", !pubk_cert);
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

Test::Result certificate_matching_with_dn_normalization()
   {
   Test::Result result("macOS Certificate Store - normalization of X.509 DN (regression test)");

   try
      {
      auto dn  = get_skewed_dn();

      result.start_timer();
      Botan::Certificate_Store_MacOS certstore;

      auto certs = certstore.find_all_certs(dn, std::vector<uint8_t>());
      auto cert = certstore.find_cert(dn, std::vector<uint8_t>());
      result.end_timer();

      if(result.confirm("find_all_certs did find the skewed DN", !certs.empty()) &&
            result.confirm("find_cert did find the skewed DN", cert != nullptr))
         {
         result.test_eq("it is the correct cert", certs.front()->subject_dn().get_first_attribute("CN"), "DST Root CA X3");
         result.test_eq("it is the correct cert", cert->subject_dn().get_first_attribute("CN"), "DST Root CA X3");
         }
      }
   catch(std::exception& e)
      {
      result.test_failure(e.what());
      }

   return result;
   }

class Certstor_macOS_Tests final : public Test
   {
   public:
      std::vector<Test::Result> run() override
         {
         std::vector<Test::Result> results;

         results.push_back(open_certificate_store());
         results.push_back(find_certificate_by_pubkey_sha1());
         results.push_back(find_cert_by_subject_dn());
         results.push_back(find_cert_by_subject_dn_and_key_id());
         results.push_back(find_certs_by_subject_dn_and_key_id());
         results.push_back(find_all_subjects());
         results.push_back(no_certificate_matches());
         results.push_back(certificate_matching_with_dn_normalization());

         return results;
         }
   };

BOTAN_REGISTER_TEST("certstor_macos", Certstor_macOS_Tests);

}

}

#endif
