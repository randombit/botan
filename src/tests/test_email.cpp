/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_EMAIL_ADDRESS)
   #include <botan/email.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_EMAIL_ADDRESS)

namespace {

class Email_Address_Tests final : public Test {
   private:
      static Test::Result test_parse_valid() {
         Test::Result result("EmailAddress::from_string valid");

         struct Case {
               std::string input;
               std::string local_part;
               std::string domain;
         };

         const std::vector<Case> cases{
            {"user@example.com", "user", "example.com"},
            // Per RFC 5280 7.5 the local part is preserved as given;
            // only the domain is canonicalized to lowercase.
            {"Alice@Example.COM", "Alice", "example.com"},
            {"x@a.b.c.example.org", "x", "a.b.c.example.org"},
            {"first.last@example.com", "first.last", "example.com"},
            {"user+tag@example.com", "user+tag", "example.com"},
            // The full RFC 5322 atext-special set should round-trip.
            {"!#$%&'*+-/=?^_`{|}~@example.com", "!#$%&'*+-/=?^_`{|}~", "example.com"},
         };

         for(const auto& c : cases) {
            const auto parsed = Botan::EmailAddress::from_string(c.input);
            if(!result.test_is_true("parsed " + c.input, parsed.has_value())) {
               continue;
            }
            result.test_str_eq("local_part " + c.input, parsed->local_part(), c.local_part);
            result.test_str_eq("domain " + c.input, parsed->domain().to_string(), c.domain);
         }

         return result;
      }

      static Test::Result test_parse_invalid() {
         Test::Result result("EmailAddress::from_string invalid");

         const std::vector<std::string> invalid = {
            "",
            "no-at-sign",
            "@example.com",
            "user@",
            "user@@example.com",
            "user@.example.com",
            "user name@example.com",
            "user@example..com",
            // RFC 3696 section 3 placement rules on '.' in the local part.
            ".leading-dot@example.com",
            "trailing-dot.@example.com",
            "double..dot@example.com",
            // Outside the RFC 5322 atext set: would need RFC 5322
            // quoted-string / comment / domain-literal forms, which we
            // deliberately reject.
            "angle<bracket@example.com",
            "angle>bracket@example.com",
            "double\"quote@example.com",
            "comma,sep@example.com",
            "semi;colon@example.com",
            "colon:char@example.com",
            "back\\slash@example.com",
            "(comment)user@example.com",
            "user(comment)@example.com",
            "[bracket@example.com",
            "tab\there@example.com",
         };

         for(const auto& s : invalid) {
            result.test_is_false("reject '" + s + "'", Botan::EmailAddress::from_string(s).has_value());
         }

         return result;
      }

      static Test::Result test_round_trip() {
         Test::Result result("EmailAddress round-trip");

         const auto parsed = Botan::EmailAddress::from_string("Alice@Example.COM");
         if(result.test_is_true("parsed", parsed.has_value())) {
            // Domain canonicalized to lowercase; local part preserved
            // (RFC 5280 7.5 specifies exact match on the local part).
            result.test_str_eq("to_string", parsed->to_string(), "Alice@example.com");
         }

         return result;
      }

   public:
      std::vector<Test::Result> run() override { return {test_parse_valid(), test_parse_invalid(), test_round_trip()}; }
};

BOTAN_REGISTER_TEST("utils", "email", Email_Address_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
