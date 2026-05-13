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

namespace {

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
            "*.wildcard.example.com",
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

         const std::vector<Botan::IPv6Address> ipv6_names = {
            Botan::IPv6Address({0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
            Botan::IPv6Address({0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}),
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
         for(const auto& ipv6 : ipv6_names) {
            alt_name.add_ipv6_address(ipv6);
         }
         for(const auto& email : email_names) {
            alt_name.add_email(email);
         }

         alt_name.add_other_name(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10000, 1}, Botan::ASN1_String("foof"));
         alt_name.add_other_name(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10000, 2}, Botan::ASN1_String("yow"));

         // Raw OtherName whose inner value is a SEQUENCE (i.e. not an ASN1_String).
         const Botan::OID raw_other_oid{1, 3, 6, 1, 4, 1, 25258, 10000, 3};
         const std::vector<uint8_t> raw_other_value = {0x30, 0x03, 0x02, 0x01, 0x2A};
         alt_name.add_other_name_value(raw_other_oid, raw_other_value);

         alt_name.add_registered_id(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10001, 1});
         alt_name.add_registered_id(Botan::OID{1, 3, 6, 1, 4, 1, 25258, 10001, 2});

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

         result.test_sz_eq("Expected number of domains", recoded.dns_names().size(), dns_names.size());
         for(const auto& name : dns_names) {
            // SAN dnsName entries can be wildcards, so use from_san_string.
            auto parsed = Botan::DNSName::from_san_string(name);
            result.test_is_true("DNS name parses: " + name, parsed.has_value());
            if(parsed.has_value()) {
               result.test_is_true("Has expected DNS name: " + name, recoded.dns_names().contains(*parsed));
            }
         }

         result.test_sz_eq("Expected number of URIs", recoded.uri_names().size(), uri_names.size());
         for(const auto& name : uri_names) {
            auto parsed = Botan::URI::parse(name);
            result.test_is_true("URI parses: " + name, parsed.has_value());
            if(parsed.has_value()) {
               result.test_is_true("Has expected URI name: " + name, recoded.uri_names().contains(*parsed));
            }
         }

         result.test_sz_eq("Expected number of email", recoded.email_addresses().size(), email_names.size());
         for(const auto& name : email_names) {
            auto parsed = Botan::EmailAddress::from_string(name);
            result.test_is_true("Email name parses: " + name, parsed.has_value());
            if(parsed.has_value()) {
               result.test_is_true("Has expected email name: " + name, recoded.email_addresses().contains(*parsed));
            }
         }

         result.test_sz_eq("Expected number of IPv4", recoded.ipv4_address().size(), ipv4_names.size());
         for(const auto ipv4 : ipv4_names) {
            result.test_is_true("Has expected IPv4 name", recoded.ipv4_address().contains(ipv4));
         }

         result.test_sz_eq("Expected number of IPv6", recoded.ipv6_address().size(), ipv6_names.size());
         for(const auto& ipv6 : ipv6_names) {
            result.test_is_true("Has expected IPv6 name", recoded.ipv6_address().contains(ipv6));
         }

         result.test_sz_eq("Expected number of DNs", recoded.directory_names().size(), 2);
         result.test_sz_eq("Expected number of Othernames", recoded.other_names().size(), 2);
         result.test_sz_eq("Expected number of OtherName values", recoded.other_name_values().size(), 3);
         result.test_sz_eq("Expected number of registeredIDs", recoded.registered_ids().size(), 2);

         // The raw-bytes OtherName roundtripped verbatim.
         const auto& on_set = recoded.other_name_values();
         auto raw_match = on_set.end();
         for(auto it = on_set.begin(); it != on_set.end(); ++it) {
            if(it->oid() == raw_other_oid) {
               raw_match = it;
               break;
            }
         }
         result.test_is_true("raw OtherName preserved", raw_match != on_set.end());
         if(raw_match != on_set.end()) {
            result.test_bin_eq("raw OtherName value bytes match", raw_match->value(), raw_other_value);
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_alt_name", X509_Alt_Name_Tests);

class X509_Alt_Name_SmtpUtf8_Wire_Type_Test final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("X509 AlternativeName SmtpUTF8Mailbox wire-type guard");

         std::vector<uint8_t> ia5_inner;
         Botan::DER_Encoder(ia5_inner).encode(Botan::ASN1_String("alice@evil.com", Botan::ASN1_Type::Ia5String));

         Botan::AlternativeName crafted;
         crafted.add_other_name_value(Botan::OID::from_string("PKIX.SmtpUTF8Mailbox"), ia5_inner);

         std::vector<uint8_t> der;
         Botan::DER_Encoder(der).encode(crafted);

         Botan::AlternativeName recoded;
         Botan::BER_Decoder dec(der);
         result.test_throws<Botan::Decoding_Error>("SmtpUTF8Mailbox with non-UTF8String inner is rejected",
                                                   [&] { dec.decode(recoded); });

         // Check that the valid type is accepted
         std::vector<uint8_t> utf8_inner;
         Botan::DER_Encoder(utf8_inner).encode(Botan::ASN1_String("alicé@example.com", Botan::ASN1_Type::Utf8String));

         Botan::AlternativeName ok;
         ok.add_other_name_value(Botan::OID::from_string("PKIX.SmtpUTF8Mailbox"), utf8_inner);

         std::vector<uint8_t> ok_der;
         Botan::DER_Encoder(ok_der).encode(ok);

         Botan::AlternativeName ok_recoded;
         Botan::BER_Decoder ok_dec(ok_der);
         try {
            ok_dec.decode(ok_recoded);
            result.test_sz_eq(
               "UTF8String inner surfaces in smtp_utf8_mailboxes", ok_recoded.smtp_utf8_mailboxes().size(), 1);
         } catch(const std::exception& e) {
            result.test_failure(std::string("UTF8String inner round-trip threw: ") + e.what());
         }

         return {result};
      }
};

BOTAN_REGISTER_TEST("x509", "x509_alt_name_smtputf8_wire_type", X509_Alt_Name_SmtpUtf8_Wire_Type_Test);

#endif

}  // namespace

}  // namespace Botan_Tests
