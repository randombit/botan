/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DNS_NAME)
   #include <botan/dns_name.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_DNS_NAME)

namespace {

class DNS_Wildcard_Tests final : public Text_Based_Test {
   public:
      DNS_Wildcard_Tests() : Text_Based_Test("utils/dns_wildcards.vec", "Issued,Hostname") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("DNS wildcard matching");

         const auto issued = vars.get_req_str("Issued");
         const auto hostname = vars.get_req_str("Hostname");
         const bool should_accept = (type == "Invalid") ? false : true;

         result.test_bool_eq("match", Botan::DNSName::host_wildcard_match(issued, hostname), should_accept);

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "dns_wildcard", DNS_Wildcard_Tests);

class DNS_Check_Tests final : public Text_Based_Test {
   public:
      DNS_Check_Tests() : Text_Based_Test("utils/dns.vec", "DNS") {}

      Test::Result run_one_test(const std::string& type, const VarMap& vars) override {
         Test::Result result("DNS name validation");

         const std::string name = vars.get_req_str("DNS");
         const bool from_string_ok = Botan::DNSName::from_string(name).has_value();
         const bool from_san_string_ok = Botan::DNSName::from_san_string(name).has_value();

         if(type == "Valid") {
            // Both factories accept literal hostnames.
            result.test_is_true("from_string accepts: " + name, from_string_ok);
            result.test_is_true("from_san_string accepts: " + name, from_san_string_ok);
         } else if(type == "ValidWildcard") {
            // Wildcard label: strict from_string rejects, from_san_string accepts.
            result.test_is_false("from_string rejects wildcard: " + name, from_string_ok);
            result.test_is_true("from_san_string accepts wildcard: " + name, from_san_string_ok);
         } else {
            // Invalid syntactic form: both reject.
            result.test_is_false("from_string rejects: " + name, from_string_ok);
            result.test_is_false("from_san_string rejects: " + name, from_san_string_ok);
         }

         return result;
      }
};

BOTAN_REGISTER_TEST("utils", "dns_check", DNS_Check_Tests);

class DNSName_Tests final : public Test {
   private:
      static Test::Result test_parse_valid() {
         Test::Result result("DNSName::from_string valid");

         const std::vector<std::pair<std::string, std::string>> cases{
            {"example.com", "example.com"},
            {"Example.COM", "example.com"},
            {"a.b.c.example.org", "a.b.c.example.org"},
            {"sub-domain.example.com", "sub-domain.example.com"},
         };

         for(const auto& [input, expected] : cases) {
            const auto parsed = Botan::DNSName::from_string(input);
            if(!result.test_is_true("DNSName accepted valid", parsed.has_value())) {
               continue;
            }
            result.test_str_eq("DNSName canonical", parsed->to_string(), expected);
         }

         return result;
      }

      static Test::Result test_parse_invalid() {
         Test::Result result("DNSName::from_string invalid");

         const std::vector<std::string> invalid = {
            "",
            ".leading.dot",
            "double..dot",
            "trailing.dot.",
            "with space.example.com",
            "label-",
            std::string("evil.com\0.example.com", 21),
            std::string("a\0b", 3),
            // All-numeric names are rejected
            "1.2.3.4",
            "123.456.789",
            "12345",
            "999.999.999.999",
         };

         for(const auto& s : invalid) {
            result.test_is_false("rejects '" + s + "'", Botan::DNSName::from_string(s).has_value());
            result.test_is_false("from_san_string also rejects '" + s + "'",
                                 Botan::DNSName::from_san_string(s).has_value());
         }

         return result;
      }

      static Test::Result test_wildcard_factories() {
         Test::Result result("DNSName::from_san_string and is_wildcard");

         // RFC 6125 6.4.3 wildcard form (single "*" in the leftmost label,
         // complete or partial): from_string rejects, from_san_string accepts,
         // is_wildcard reports true.
         const std::vector<std::string> usable_wildcards = {
            "*.example.com",
            "*.sub.example.org",
            "foo*.example.com",
            "*bar.example.com",
            "foo*bar.example.com",
         };
         for(const auto& w : usable_wildcards) {
            result.test_is_false("from_string rejects: " + w, Botan::DNSName::from_string(w).has_value());

            const auto parsed = Botan::DNSName::from_san_string(w);
            if(result.test_is_true("from_san_string accepts: " + w, parsed.has_value())) {
               result.test_is_true("is_wildcard true for: " + w, parsed->is_wildcard());
            }
         }

         // Invalid wildcards: multiple "*", "*" outside the leftmost label,
         // too few labels to ever match, or "*" within an IDNA A-label.
         const std::vector<std::string> malformed = {
            "*.*.example.com",
            "foo.*.example.com",
            "*foo.*.example.com",
            "bar.foo*.example.com",
            "*",
            "*.com",
            "foo*.com",
            "xn--f*.example.com",
            "xn--*.example.com",
         };
         for(const auto& w : malformed) {
            result.test_is_false("from_san_string rejects malformed: " + w,
                                 Botan::DNSName::from_san_string(w).has_value());
         }

         // Both constructors accept a plain hostname; is_wildcard is false.
         const auto literal = Botan::DNSName::from_san_string("example.com");
         if(result.test_is_true("from_san_string accepts literal", literal.has_value())) {
            result.test_is_false("is_wildcard false for literal", literal->is_wildcard());
         }

         return result;
      }

      static Test::Result test_wildcard() {
         Test::Result result("DNSName::matches_wildcard");

         const auto sub = Botan::DNSName::from_string("foo.example.com").value();
         result.test_is_true("*.example.com matches foo.example.com", sub.matches_wildcard("*.example.com"));
         result.test_is_false("*.other.com does not match foo.example.com", sub.matches_wildcard("*.other.com"));

         const auto deeper = Botan::DNSName::from_string("a.b.example.com").value();
         result.test_is_false("*.example.com does not match a.b.example.com", deeper.matches_wildcard("*.example.com"));

         // Invalid hosts are rejected even when the pattern would otherwise match
         result.test_is_false("host with leading dot rejected",
                              Botan::DNSName::host_wildcard_match("*.example.com", ".example.com"));
         result.test_is_false("identical invalid host rejected",
                              Botan::DNSName::host_wildcard_match(".example.com", ".example.com"));
         result.test_is_false(
            "host with embedded NUL rejected",
            Botan::DNSName::host_wildcard_match("*.example.com", std::string("ev\0il.example.com", 17)));

         // RFC 6125 6.4.3: no wildcard matching within IDNA A-labels
         result.test_is_false("wildcard inside A-label rejected",
                              Botan::DNSName::host_wildcard_match("xn--b*r.example.com", "xn--bar.example.com"));
         result.test_is_false("partial wildcard cannot match into an A-label",
                              Botan::DNSName::host_wildcard_match("x*.example.com", "xn--bcher-kva.example.com"));
         result.test_is_true("whole-label wildcard still matches an A-label",
                             Botan::DNSName::host_wildcard_match("*.example.com", "xn--bcher-kva.example.com"));

         return result;
      }

      static Test::Result test_length_limits() {
         Test::Result result("DNSName length limits");

         const std::string label63(63, 'a');
         const std::string label64(64, 'a');

         result.test_is_true("63 char label accepted", Botan::DNSName::from_string(label63 + ".com").has_value());
         result.test_is_false("64 char label rejected", Botan::DNSName::from_string(label64 + ".com").has_value());

         // Maximum presentation form length is 253 characters
         const std::string name253 = label63 + "." + label63 + "." + label63 + "." + std::string(61, 'a');
         const std::string name254 = label63 + "." + label63 + "." + label63 + "." + std::string(62, 'a');
         result.test_u16_eq("test name has expected length", static_cast<uint16_t>(name253.size()), 253);

         result.test_is_true("253 char name accepted", Botan::DNSName::from_string(name253).has_value());
         result.test_is_false("254 char name rejected", Botan::DNSName::from_string(name254).has_value());

         // A 253 char name is also matchable
         const auto long_name = Botan::DNSName::from_string(name253).value();
         result.test_is_true("253 char name matches itself",
                             Botan::DNSName::host_wildcard_match(name253, long_name.to_string()));

         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         return {
            test_parse_valid(), test_parse_invalid(), test_wildcard_factories(), test_wildcard(), test_length_limits()};
      }
};

BOTAN_REGISTER_TEST("utils", "dns_name", DNSName_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
