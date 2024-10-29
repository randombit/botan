/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*     2023,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SOCKETS) && (defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2))

   #include <botan/internal/uri.h>

namespace Botan_Tests {

class URI_Tests final : public Test {
   private:
      static Test::Result test_uri_ctor() {
         Test::Result result("URI constructors");
         Botan::URI uri(Botan::URI::Type::Domain, "localhost", 9000);
         result.confirm("type", uri.type() == Botan::URI::Type::Domain);
         result.test_eq("host", uri.host(), "localhost");
         result.test_eq("post", size_t(uri.port()), 9000);
         return result;
      }

      static Test::Result test_uri_tostring() {
         Test::Result result("URI to_string");

         result.test_eq("domain", Botan::URI(Botan::URI::Type::Domain, "localhost", 23).to_string(), "localhost:23");
         result.test_eq("IPv4", Botan::URI(Botan::URI::Type::IPv4, "192.168.1.1", 25).to_string(), "192.168.1.1:25");
         result.test_eq("IPv6", Botan::URI(Botan::URI::Type::IPv6, "::1", 65535).to_string(), "[::1]:65535");
         result.test_eq("IPv6 no port", Botan::URI(Botan::URI::Type::IPv6, "::1", 0).to_string(), "::1");

         return result;
      }

      static Test::Result test_uri_parsing() {
         Test::Result result("URI parsing");

         struct {
               std::string uri;
               std::string host;
               Botan::URI::Type type;
               uint16_t port;
         } tests[]{
            {"localhost:80", "localhost", Botan::URI::Type::Domain, 80},
            {"www.example.com", "www.example.com", Botan::URI::Type::Domain, 0},
            {"192.168.1.1", "192.168.1.1", Botan::URI::Type::IPv4, 0},
            {"192.168.1.1:34567", "192.168.1.1", Botan::URI::Type::IPv4, 34567},
            {"[::1]:61234", "::1", Botan::URI::Type::IPv6, 61234},
         };

         for(const auto& t : tests) {
            auto test_URI = [&result](const Botan::URI& uri, const std::string& host, const uint16_t port) {
               result.test_eq("host", uri.host(), host);
               result.test_int_eq("port", uri.port(), port);
            };

            if(t.type != Botan::URI::Type::IPv4) {
               result.test_throws("invalid", [&t]() { Botan::URI::from_ipv4(t.uri); });
            }
            if(t.type != Botan::URI::Type::IPv6) {
               result.test_throws("invalid", [&t]() { Botan::URI::from_ipv6(t.uri); });
            }
            if(t.type != Botan::URI::Type::Domain) {
               result.test_throws("invalid", [&t]() { Botan::URI::from_domain(t.uri); });
            }

            const auto any = Botan::URI::from_any(t.uri);
            result.confirm("from_any type is expected", any.type() == t.type);
            test_URI(any, t.host, t.port);
            if(t.type == Botan::URI::Type::Domain) {
               test_URI(Botan::URI::from_domain(t.uri), t.host, t.port);
            } else if(t.type == Botan::URI::Type::IPv4) {
               test_URI(Botan::URI::from_ipv4(t.uri), t.host, t.port);
            } else if(t.type == Botan::URI::Type::IPv6) {
               test_URI(Botan::URI::from_ipv6(t.uri), t.host, t.port);
            }
         }

         //since GCC 4.8 does not support regex this would possibly be acceped as valid domains,
         //but we just want to test IPv6 parsing, so the test needs to be individual
         result.test_throws("invalid IPv6", []() { Botan::URI::from_ipv6("]"); });
         result.test_throws("invalid IPv6", []() { Botan::URI::from_ipv6("[::1]1"); });

         return result;
      }

      static Test::Result test_uri_parsing_invalid() {
         Test::Result result("URI parsing invalid");

         const std::vector<std::string> invalid_uris = {
            "localhost::80",
            "localhost:70000",
            "[::1]:a",
            "[::1]:70000",
            "hello..com",
            ".leading.dot",
            "yeah.i.thought.so.",
         };

         for(const auto& invalid_uri : invalid_uris) {
            try {
               auto uri = Botan::URI::from_any(invalid_uri);
               result.test_failure("Failed to reject invalid URI '" + invalid_uri + "'");
            } catch(Botan::Invalid_Argument&) {
               result.test_success("Rejected invalid URI");
            }
         }
         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_uri_ctor());
         results.push_back(test_uri_tostring());
         results.push_back(test_uri_parsing());
         results.push_back(test_uri_parsing_invalid());

         return results;
      }
};

BOTAN_REGISTER_TEST("utils", "uri", URI_Tests);

}  // namespace Botan_Tests

#endif
