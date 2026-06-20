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
            {"[::1]:61234", "::1", 61234, HostKind::IPv6},
            {"[::1]", "::1", std::nullopt, HostKind::IPv6},
            {"Example.COM:443", "example.com", 443, HostKind::DNS},
            // Userinfo is preserved in original_input()
            {"user:pw@example.com:8443", "example.com", 8443, HostKind::DNS},
            {"alice@example.com", "example.com", std::nullopt, HostKind::DNS},
         };

         for(const auto& c : cases) {
            const auto authority = Botan::URI::Authority::parse(c.input);
            if(!result.test_is_true("Authority::parse succeeds: " + c.input, authority.has_value())) {
               continue;
            }
            result.test_str_eq("host: " + c.input, authority->host_to_string(), c.host);
            result.test_opt_u16_eq("port: " + c.input, authority->port(), c.port);
            result.test_is_true("host kind: " + c.input, authority->host_kind() == c.kind);
            result.test_str_eq("original input: " + c.input, authority->original_input(), c.input);
         }

         const std::vector<std::string> invalid = {
            "",
            "localhost::80",
            "localhost:80aa",
            "localhost:%50",
            "localhost:70000",
            "localhost:0",
            // Ports may not have leading zeros
            "localhost:0080",
            "localhost:007",
            "192.168.1.1:08080",
            "[::1]:0443",
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
            {"https://[2001:db8::1]/", "https", "2001:db8::1", std::nullopt, HostKind::IPv6},
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
            if(result.test_is_true("authority present: " + c.input, uri->authority().has_value())) {
               const auto authority = uri->authority().value();
               const auto raw_authority = uri->raw_authority();
               result.test_is_true("raw authority present: " + c.input, raw_authority.has_value());
               if(raw_authority.has_value()) {
                  result.test_str_eq(
                     "raw authority: " + c.input, std::string(*raw_authority), authority.original_input());
               }
               result.test_str_eq("host: " + c.input, authority.host_to_string(), c.host);
               result.test_opt_u16_eq("port: " + c.input, authority.port(), c.port);
               result.test_enum_eq("host kind: " + c.input, authority.host_kind(), c.kind);
            }
         }

         struct NoAuthorityCase {
               std::string input;
               std::string scheme;
               std::string path;
               std::optional<std::string> query;
               std::optional<std::string> fragment;
         };

         const std::vector<NoAuthorityCase> no_authority_cases{
            {"urn:ashes", "urn", "ashes", std::nullopt, std::nullopt},
            {"mailto:root@attacker.com", "mailto", "root@attacker.com", std::nullopt, std::nullopt},
            {"tel:867-5309", "tel", "867-5309", std::nullopt, std::nullopt},
            {"foo:", "foo", "", std::nullopt, std::nullopt},
            {"foo:/path?q=1#frag", "foo", "/path", "q=1", "frag"},
         };

         for(const auto& c : no_authority_cases) {
            const auto uri = Botan::URI::parse(c.input);
            if(!result.test_is_true("parse succeeds without authority: " + c.input, uri.has_value())) {
               continue;
            }
            result.test_is_false("authority absent: " + c.input, uri->authority().has_value());
            result.test_is_false("raw authority absent: " + c.input, uri->raw_authority().has_value());
            result.test_str_eq("scheme: " + c.input, uri->scheme(), c.scheme);
            result.test_is_false("host absent: " + c.input, uri->host().has_value());
            result.test_str_eq("path: " + c.input, uri->path(), c.path);
            result.test_bool_eq("query presence: " + c.input, uri->query().has_value(), c.query.has_value());
            if(c.query.has_value() && uri->query().has_value()) {
               result.test_str_eq("query: " + c.input, *uri->query(), *c.query);
            }
            result.test_bool_eq("fragment presence: " + c.input, uri->fragment().has_value(), c.fragment.has_value());
            if(c.fragment.has_value() && uri->fragment().has_value()) {
               result.test_str_eq("fragment: " + c.input, *uri->fragment(), *c.fragment);
            }
         }

         const std::vector<NoAuthorityCase> empty_authority_cases{
            {"ldap:///CN=Example,C=US?cACertificate?base?objectClass=certificationAuthority",
             "ldap",
             "/CN=Example,C=US",
             "cACertificate?base?objectClass=certificationAuthority",
             std::nullopt},
            {"ldaps:///CN=Example", "ldaps", "/CN=Example", std::nullopt, std::nullopt},
            {"file:///tmp/cert.pem", "file", "/tmp/cert.pem", std::nullopt, std::nullopt},
            {"http:///path", "http", "/path", std::nullopt, std::nullopt},
            {"https://", "https", "", std::nullopt, std::nullopt},
            {"https:///path", "https", "/path", std::nullopt, std::nullopt},
         };

         for(const auto& c : empty_authority_cases) {
            const auto uri = Botan::URI::parse(c.input);
            if(!result.test_is_true("parse succeeds with empty authority: " + c.input, uri.has_value())) {
               continue;
            }
            result.test_is_false("parsed authority absent: " + c.input, uri->authority().has_value());
            const auto raw_authority = uri->raw_authority();
            result.test_is_true("raw authority present: " + c.input, raw_authority.has_value());
            if(raw_authority.has_value()) {
               result.test_str_eq("raw authority is empty: " + c.input, std::string(*raw_authority), "");
            }
            result.test_str_eq("scheme: " + c.input, uri->scheme(), c.scheme);
            result.test_is_false("host absent: " + c.input, uri->host().has_value());
            result.test_str_eq("path: " + c.input, uri->path(), c.path);
            result.test_bool_eq("query presence: " + c.input, uri->query().has_value(), c.query.has_value());
            if(c.query.has_value() && uri->query().has_value()) {
               result.test_str_eq("query: " + c.input, *uri->query(), *c.query);
            }
            result.test_bool_eq("fragment presence: " + c.input, uri->fragment().has_value(), c.fragment.has_value());
            if(c.fragment.has_value() && uri->fragment().has_value()) {
               result.test_str_eq("fragment: " + c.input, *uri->fragment(), *c.fragment);
            }
         }

         const std::vector<std::string> invalid = {
            "",
            "://no.scheme/",
            "1http://host/",
            "https//no-colon/",
            "https://[not-an-ip]/",
            "https://example.com:0443/",
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
         const auto uri_with_userinfo = Botan::URI::parse("https://alice:s3cret@example.com/").value();

         result.test_is_true("userinfo distinguishes identity",
                             uri_with_userinfo != Botan::URI::parse("https://example.com/").value());
         result.test_is_true("userinfo equal when matching",
                             uri_with_userinfo == Botan::URI::parse("https://alice:s3cret@example.com/").value());
         // The authority's original_input() includes the userinfo
         result.test_is_true("authority present with userinfo", uri_with_userinfo.authority().has_value());
         result.test_str_eq("authority original_input preserves userinfo",
                            uri_with_userinfo.authority()->original_input(),
                            "alice:s3cret@example.com");
         // Userinfo case IS significant (no case normalization).
         result.test_is_false("userinfo case is significant",
                              Botan::URI::parse("https://Alice@example.com/").value() ==
                                 Botan::URI::parse("https://alice@example.com/").value());
         // Empty userinfo is distinct from no userinfo (RFC 3986
         // authority grammar: "@" delimiter presence is significant).
         const auto absent = Botan::URI::parse("https://example.com/").value();
         const auto empty = Botan::URI::parse("https://@example.com/").value();
         result.test_is_true("empty userinfo != absent userinfo", absent != empty);
         result.test_is_false("absent userinfo: accessor reports nullopt", absent.authority()->userinfo().has_value());
         result.test_is_true("empty userinfo: accessor reports present", empty.authority()->userinfo().has_value());
         result.test_str_eq("empty userinfo: accessor reports empty string", *empty.authority()->userinfo(), "");

         // Path, query, and fragment are split out and exposed separately.
         const auto full = Botan::URI::parse("https://example.com/path?q=1#frag").value();
         result.test_str_eq("path component", full.path(), "/path");
         result.test_is_true("query present", full.query().has_value());
         result.test_str_eq("query component", *full.query(), "q=1");
         result.test_is_true("fragment present", full.fragment().has_value());
         result.test_str_eq("fragment component", *full.fragment(), "frag");

         // Empty path is preserved as empty (not defaulted to "/").
         const auto no_path = Botan::URI::parse("https://example.com").value();
         result.test_str_eq("empty path stays empty", no_path.path(), "");
         result.test_is_false("no query", no_path.query().has_value());
         result.test_is_false("no fragment", no_path.fragment().has_value());

         const auto mailto = Botan::URI::parse("mailto:root@example.com").value();
         result.test_is_false("mailto has no authority", mailto.authority().has_value());
         result.test_is_false("mailto has no raw authority", mailto.raw_authority().has_value());
         result.test_is_false(
            "authorityful URI differs from authorityless URI",
            Botan::URI::parse("foo://example.com/path").value() == Botan::URI::parse("foo:/path").value());
         result.test_is_false("empty authority differs from absent authority",
                              Botan::URI::parse("foo:///path").value() == Botan::URI::parse("foo:/path").value());

         // Query without path: empty path, present query.
         const auto query_only = Botan::URI::parse("https://example.com?q=1").value();
         result.test_str_eq("query-only: path is empty", query_only.path(), "");
         result.test_is_true("query-only: query present", query_only.query().has_value());
         result.test_str_eq("query-only: query value", *query_only.query(), "q=1");

         // Present-but-empty query / fragment are distinct from absent.
         const auto empty_query = Botan::URI::parse("https://example.com/p?").value();
         result.test_is_true("empty query: present", empty_query.query().has_value());
         result.test_str_eq("empty query: value", *empty_query.query(), "");
         const auto empty_frag = Botan::URI::parse("https://example.com/p#").value();
         result.test_is_true("empty fragment: present", empty_frag.fragment().has_value());
         result.test_str_eq("empty fragment: value", *empty_frag.fragment(), "");

         return result;
      }

   public:
      std::vector<Test::Result> run() override { return {test_authority_parse(), test_parse(), test_equality()}; }
};

BOTAN_REGISTER_TEST("utils", "uri", URI_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
