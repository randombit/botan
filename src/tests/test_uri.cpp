/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_SOCKETS) && (defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2))

   #include <botan/internal/uri.h>

namespace Botan_Tests {

class URI_Tests final : public Test {
      static void test_uri_ctor(std::vector<Test::Result>& results) {
         Test::Result result("uri constructors");
         Botan::URI uri(Botan::URI::Type::Domain, "localhost", 80);
         result.confirm("type", uri.type == Botan::URI::Type::Domain);
         result.test_eq("host", uri.host, "localhost");
         result.confirm("post", uri.port == 80);
         results.push_back(result);
      }

      static void test_uri_tostring(std::vector<Test::Result>& results) {
         Test::Result result("uri to_string");

         result.test_eq("domain", Botan::URI(Botan::URI::Type::Domain, "localhost", 80).to_string(), "localhost:80");
         result.test_eq("IPv4", Botan::URI(Botan::URI::Type::IPv4, "192.168.1.1", 80).to_string(), "192.168.1.1:80");
         result.test_eq("IPv6", Botan::URI(Botan::URI::Type::IPv6, "::1", 80).to_string(), "[::1]:80");
         result.test_eq("IPv6 no port", Botan::URI(Botan::URI::Type::IPv6, "::1", 0).to_string(), "::1");
         result.test_throws("invalid", []() { Botan::URI(Botan::URI::Type::NotSet, "", 0).to_string(); });

         results.push_back(result);
      }

      static void test_uri_factories(std::vector<Test::Result>& results) {
         Test::Result result("uri factories");

         struct {
               std::string uri;
               std::string host;
               Botan::URI::Type type;
               unsigned port;
         } tests[]{
            {"localhost::80", {}, Botan::URI::Type::NotSet, 0},
            {"localhost:70000", {}, Botan::URI::Type::NotSet, 0},
            {"[::1]:a", {}, Botan::URI::Type::NotSet, 0},
            {"[::1]:70000", {}, Botan::URI::Type::NotSet, 0},
            {"localhost:80", "localhost", Botan::URI::Type::Domain, 80},
            {"www.example.com", "www.example.com", Botan::URI::Type::Domain, 0},
            {"192.168.1.1", "192.168.1.1", Botan::URI::Type::IPv4, 0},
            {"192.168.1.1:34567", "192.168.1.1", Botan::URI::Type::IPv4, 34567},
            {"[::1]:61234", "::1", Botan::URI::Type::IPv6, 61234},
         };

         for(const auto& t : tests) {
            auto test_URI = [&result](const Botan::URI& uri, const std::string& host, const unsigned port) {
               result.test_eq("host", uri.host, host);
               result.confirm("port", uri.port == port);
            };

            if(t.type != Botan::URI::Type::IPv4) {
               result.test_throws("invalid", [&t]() { Botan::URI::fromIPv4(t.uri); });
            }
            if(t.type != Botan::URI::Type::IPv6) {
               result.test_throws("invalid", [&t]() { Botan::URI::fromIPv6(t.uri); });
            }
            if(t.type != Botan::URI::Type::Domain) {
               result.test_throws("invalid", [&t]() { Botan::URI::fromDomain(t.uri); });
            }
            if(t.type == Botan::URI::Type::NotSet) {
               result.test_throws("invalid", [&t]() { Botan::URI::fromAny(t.uri); });
            } else {
               const auto any = Botan::URI::fromAny(t.uri);
               result.confirm("type any", any.type == t.type);
               test_URI(any, t.host, t.port);
               if(t.type == Botan::URI::Type::Domain) {
                  test_URI(Botan::URI::fromDomain(t.uri), t.host, t.port);
               } else if(t.type == Botan::URI::Type::IPv4) {
                  test_URI(Botan::URI::fromIPv4(t.uri), t.host, t.port);
               } else if(t.type == Botan::URI::Type::IPv6) {
                  test_URI(Botan::URI::fromIPv6(t.uri), t.host, t.port);
               }
            }
         }

         //since GCC 4.8 does not support regex this would possibly be acceped as valid domains,
         //but we just want to test IPv6 parsing, so the test needs to be individual
         result.test_throws("invalid IPv6", []() { Botan::URI::fromIPv6("]"); });
         result.test_throws("invalid IPv6", []() { Botan::URI::fromIPv6("[::1]1"); });

         results.push_back(result);
      }

   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         test_uri_ctor(results);
         test_uri_tostring(results);
         test_uri_factories(results);

         return results;
      }
};

BOTAN_REGISTER_TEST("utils", "uri", URI_Tests);

}  // namespace Botan_Tests

#endif
