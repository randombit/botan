/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*     2023,2024,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_URI)
   #include <botan/uri.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_URI)

namespace {

class URI_Tests final : public Test {
   private:
      using HostKind = Botan::URI::Authority::HostKind;

      static void test_port(Test::Result& result,
                            std::string_view what,
                            const std::optional<uint16_t>& got,
                            const std::optional<uint16_t>& expected) {
         if(got.has_value() != expected.has_value()) {
            result.test_failure(std::string(what) + ": port presence mismatch");
         } else if(got.has_value()) {
            result.test_u16_eq(what, *got, *expected);
         } else {
            result.test_success(std::string(what) + ": both nullopt");
         }
      }

      static Test::Result test_authority_parse() {
         Test::Result result("URI::Authority::parse");

         struct Case {
               std::string input;
               std::string host;
               std::optional<uint16_t> port;
               HostKind kind;
         };

         const std::vector<Case> cases{
            {"localhost:80", "localhost", 80, HostKind::DNS},
            {"www.example.com", "www.example.com", std::nullopt, HostKind::DNS},
            {"192.168.1.1", "192.168.1.1", std::nullopt, HostKind::IPv4},
            {"192.168.1.1:34567", "192.168.1.1", 34567, HostKind::IPv4},
            {"[::1]:61234", "0:0:0:0:0:0:0:1", 61234, HostKind::IPv6},
            {"[::1]", "0:0:0:0:0:0:0:1", std::nullopt, HostKind::IPv6},
            {"Example.COM:443", "example.com", 443, HostKind::DNS},
         };

         for(const auto& c : cases) {
            const auto authority = Botan::URI::Authority::parse(c.input);
            if(!result.test_is_true("Authority::parse succeeds: " + c.input, authority.has_value())) {
               continue;
            }
            result.test_str_eq("host: " + c.input, authority->host_to_string(), c.host);
            test_port(result, "port: " + c.input, authority->port(), c.port);
            result.test_is_true("host kind: " + c.input, authority->host_kind() == c.kind);
            result.test_str_eq("original input: " + c.input, authority->original_input(), c.input);
         }

         const std::vector<std::string> invalid = {
            "",
            "localhost::80",
            "localhost:80aa",
            "localhost:%50",
            "localhost:70000",
            "[::1]:a",
            "[::1]:70000",
            "hello..com",
            ".leading.dot",
            "[not-an-ipv6]:80",
            "[::1",
            "::1]:80",
            "host space:80",
            // Trailing dot is theoretically valid, but rejected
            "host.example.com.",
            "192.168.1.1.",
            "192.168.1.1.:8080",
            // _ not valid in host names, only DNS SRV records which is not relevant here
            "_acme-challenge.example.com",
         };
         for(const auto& s : invalid) {
            result.test_is_false("rejects invalid authority '" + s + "'", Botan::URI::Authority::parse(s).has_value());
         }

         return result;
      }

      static Test::Result test_parse() {
         Test::Result result("URI::parse");

         struct Case {
               std::string input;
               std::string scheme;
               std::string host;
               std::optional<uint16_t> port;
               HostKind kind;
         };

         const std::vector<Case> cases{
            {"https://foo.example.com/", "https", "foo.example.com", std::nullopt, HostKind::DNS},
            {"http://foo.example.com:8080/path?q=1#frag", "http", "foo.example.com", 8080, HostKind::DNS},
            {"https://[2001:db8::1]/", "https", "2001:db8:0:0:0:0:0:1", std::nullopt, HostKind::IPv6},
            {"https://10.0.0.1/", "https", "10.0.0.1", std::nullopt, HostKind::IPv4},
            {"https://user:pw@sub.example.com:8443/path", "https", "sub.example.com", 8443, HostKind::DNS},
            {"HTTPS://Example.COM/", "https", "example.com", std::nullopt, HostKind::DNS},
         };

         for(const auto& c : cases) {
            const auto uri = Botan::URI::parse(c.input);
            if(!result.test_is_true("parse succeeds: " + c.input, uri.has_value())) {
               continue;
            }
            result.test_str_eq("scheme: " + c.input, uri->scheme(), c.scheme);
            result.test_str_eq("host: " + c.input, uri->host_to_string(), c.host);
            test_port(result, "port: " + c.input, uri->port(), c.port);
            result.test_is_true("host kind: " + c.input, uri->host_kind() == c.kind);
         }

         const std::vector<std::string> invalid = {
            "",
            "://no.scheme/",
            "1http://host/",
            "https//no-colon/",
            "https://",
            "https:///path",
            "https://[not-an-ip]/",
            // URIs without an authority are valid per RFC 5280 but seem unnecessary to support
            "urn:ashes",
            "mailto:root@attacker.com",
            "tel:867-5309",
            // Path/query/fragment must use RFC 3986 character set.
            "https://example.com/has space",
            "https://example.com/path<bracket>",
            "https://example.com/%G0",
            "https://example.com/%2",
            // Percent encoded embedded nulls are rejected
            "https://example.com/embedded/null/%00/surprise",
            // Fragment delimiter may appear at most once
            "https://example.com/path#frag#extra",
            "https://example.com/#a#b",
            // RFC 3986 userinfo does not allow unencoded '@'.
            "https://user@bad@example.com/",
            // Userinfo character set validation:
            "https://user name@example.com/",
            "https://user<x>@example.com/",
            "https://user\xff@example.com/",
            "https://user%G0@example.com/",
            "https://user%00null@example.com/",
         };
         for(const auto& s : invalid) {
            result.test_is_false("rejects invalid URI '" + s + "'", Botan::URI::parse(s).has_value());
         }

         return result;
      }

      static Test::Result test_equality() {
         Test::Result result("URI equality semantics");

         // Two URIs that share scheme + host + port but differ in path
         // are distinct identities. Critical for SPIFFE-style workload
         // IDs encoded as URI SANs - otherwise `uri_names().contains()`
         // could be satisfied by the wrong workload identity.
         const auto a = Botan::URI::parse("spiffe://trust.example/ns/dev/sa/attacker").value();
         const auto b = Botan::URI::parse("spiffe://trust.example/ns/prod/sa/server").value();
         result.test_is_false("SPIFFE: differing paths are not equal", a == b);
         result.test_is_true("SPIFFE: equal with the same path",
                             a == Botan::URI::parse("spiffe://trust.example/ns/dev/sa/attacker").value());

         // Scheme and host casing don't break equality (we canonicalize).
         result.test_is_true("scheme/host case folded for equality",
                             Botan::URI::parse("HTTPS://Example.COM/path").value() ==
                                Botan::URI::parse("https://example.com/path").value());

         // Path case IS significant (RFC 3986 - paths are not
         // case-canonicalized).
         result.test_is_false("path case is significant",
                              Botan::URI::parse("https://example.com/Path").value() ==
                                 Botan::URI::parse("https://example.com/path").value());

         // Userinfo is preserved verbatim and participates in identity
         // (RFC 3986 6.2 case-normalizes only scheme and host; RFC 5280
         // 7.4 requires URI comparison to be exact-match after that).
         result.test_is_false("userinfo distinguishes identity",
                              Botan::URI::parse("https://alice:s3cret@example.com/").value() ==
                                 Botan::URI::parse("https://example.com/").value());
         result.test_is_true("userinfo equal when matching",
                             Botan::URI::parse("https://alice:s3cret@example.com/").value() ==
                                Botan::URI::parse("https://alice:s3cret@example.com/").value());
         // Userinfo case IS significant (no case normalization).
         result.test_is_false("userinfo case is significant",
                              Botan::URI::parse("https://Alice@example.com/").value() ==
                                 Botan::URI::parse("https://alice@example.com/").value());
         // Empty userinfo is distinct from no userinfo (RFC 3986
         // authority grammar: "@" delimiter presence is significant).
         const auto absent = Botan::URI::parse("https://example.com/").value();
         const auto empty = Botan::URI::parse("https://@example.com/").value();
         result.test_is_false("empty userinfo != absent userinfo", absent == empty);
         result.test_is_false("absent userinfo: accessor reports nullopt", absent.authority().userinfo().has_value());
         result.test_is_true("empty userinfo: accessor reports present", empty.authority().userinfo().has_value());
         result.test_str_eq("empty userinfo: accessor reports empty string", *empty.authority().userinfo(), "");

         // path_query_fragment exposes the verbatim tail.
         const auto with_query = Botan::URI::parse("https://example.com/path?q=1#frag").value();
         result.test_str_eq("path_query_fragment preserved", with_query.path_query_fragment(), "/path?q=1#frag");

         return result;
      }

   public:
      std::vector<Test::Result> run() override { return {test_authority_parse(), test_parse(), test_equality()}; }
};

BOTAN_REGISTER_TEST("utils", "uri", URI_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
