/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/ber_dec.h>
   #include <botan/der_enc.h>
   #include <botan/pkix_types.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_X509_CERTIFICATES)
class X509_Alt_Name_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X509 AlternativeName tests");

         const std::vector<std::string> uri_names = {
            "https://example.com", "https://example.org", "https://sub.example.net"};

         const std::vector<std::string> dns_names = {
            "dns1.example.com",
            "dns2.example.org",
         };

         const std::vector<std::string> email_names = {
            "test@example.org",
            "admin@example.com",
            "root@example.net",
         };

         const std::vector<uint32_t> ipv4_names = {
            0xC0A80101,
            0xC0A80102,
         };

         Botan::AlternativeName alt_name;
         for(const auto& uri : uri_names) {
            alt_name.add_uri(uri);
         }
         for(const auto& dns : dns_names) {
            alt_name.add_dns(dns);
         }
         for(const auto ipv4 : ipv4_names) {
            alt_name.add_ipv4_address(ipv4);
         }
         for(const auto& email : email_names) {
            alt_name.add_email(email);
         }

         alt_name.add_other_name(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10000, 1}, Botan::ASN1_String("foof"));
         alt_name.add_other_name(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10000, 2}, Botan::ASN1_String("yow"));

         Botan::X509_DN bonus_dn1;
         bonus_dn1.add_attribute("X520.CommonName", "cn1");
         alt_name.add_dn(bonus_dn1);

         Botan::X509_DN bonus_dn2;
         bonus_dn2.add_attribute("X520.CommonName", "cn2");
         alt_name.add_dn(bonus_dn2);

         std::vector<uint8_t> der;
         Botan::DER_Encoder enc(der);
         enc.encode(alt_name);

         Botan::AlternativeName recoded;
         Botan::BER_Decoder dec(der);
         dec.decode(recoded);

         result.test_eq("Expected number of domains", recoded.dns().size(), dns_names.size());
         for(const auto& name : dns_names) {
            result.confirm("Has expected DNS name", recoded.dns().contains(name));
         }

         result.test_eq("Expected number of URIs", recoded.uris().size(), uri_names.size());
         for(const auto& name : uri_names) {
            result.confirm("Has expected URI name", recoded.uris().contains(name));
         }

         result.test_eq("Expected number of email", recoded.email().size(), email_names.size());
         for(const auto& name : email_names) {
            result.confirm("Has expected email name", recoded.email().contains(name));
         }

         result.test_eq("Expected number of DNs", recoded.directory_names().size(), 2);
         result.test_eq("Expected number of Othernames", recoded.other_names().size(), 2);

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_alt_name", X509_Alt_Name_Tests);

#endif

}  // namespace Botan_Tests
