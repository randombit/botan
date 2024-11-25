/*
* (C) 2025 Jack Lloyd
* (C) 2025 Anton Einax, Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/pk_algs.h>
   #include <botan/x509_ca.h>
   #include <botan/x509_ext.h>
   #include <botan/x509self.h>
   #include <botan/internal/calendar.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)

Botan::X509_Time from_date(const int y, const int m, const int d) {
   const size_t this_year = Botan::calendar_point(std::chrono::system_clock::now()).year();

   Botan::calendar_point t(static_cast<uint32_t>(this_year + y), m, d, 0, 0, 0);
   return Botan::X509_Time(t.to_std_timepoint());
}

std::unique_ptr<Botan::Private_Key> generate_key(const std::string& algo, Botan::RandomNumberGenerator& rng) {
   std::string params;
   if(algo == "ECDSA") {
      params = "secp256r1";
   } else if(algo == "Ed25519") {
      params = "";
   } else if(algo == "RSA") {
      params = "1536";
   }

   return Botan::create_private_key(algo, rng, params);
}

Botan::X509_Cert_Options ca_opts(const std::string& sig_padding = "") {
   Botan::X509_Cert_Options opts("Test CA/US/Botan Project/Testing");

   opts.uri = "https://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";
   opts.set_padding_scheme(sig_padding);

   opts.CA_key(1);

   return opts;
}

Botan::X509_Cert_Options req_opts1(const std::string& algo, const std::string& sig_padding = "") {
   Botan::X509_Cert_Options opts("Test User 1/US/Botan Project/Testing");

   opts.uri = "https://botan.randombit.net";
   opts.dns = "botan.randombit.net";
   opts.email = "testing@randombit.net";
   opts.set_padding_scheme(sig_padding);

   opts.not_before("160101200000Z");
   opts.not_after("300101200000Z");

   opts.challenge = "zoom";

   if(algo == "RSA") {
      opts.constraints = Botan::Key_Constraints::KeyEncipherment;
   } else if(algo == "DSA" || algo == "ECDSA" || algo == "ECGDSA" || algo == "ECKCDSA") {
      opts.constraints = Botan::Key_Constraints::DigitalSignature;
   }

   return opts;
}

std::tuple<std::string, std::string, std::string> get_sig_algo_padding() {
   const std::string hash_fn{"SHA-256"};
   #if defined(BOTAN_HAS_ECDSA)
   const std::string sig_algo{"ECDSA"};
   const std::string padding_method;
   #elif defined(BOTAN_HAS_ED25519)
   const std::string sig_algo{"Ed25519"};
   const std::string padding_method;
   #elif defined(BOTAN_HAS_RSA)
   const std::string sig_algo{"RSA"};
   const std::string padding_method{"EMSA3(SHA-256)"};
   #endif

   return std::make_tuple(sig_algo, padding_method, hash_fn);
}

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

Test::Result test_x509_ip_addr_blocks_extension_decode() {
   Test::Result result("X509 IP Address Block decode");
   result.start_timer();
   const std::string filename("IPAddrBlocksAll.pem");

   Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));

   using Botan::Cert_Extension::IPAddressBlocks;

   auto ip_addr_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();

   const auto& addr_blocks = ip_addr_blocks->addr_blocks();
   result.confirm("cert has IPAddrBlocks extension", ip_addr_blocks != nullptr, true);
   result.test_eq("cert has two IpAddrBlocks", addr_blocks.size(), 2);

   const auto& ipv4block =
      std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>>(addr_blocks[0].addr_choice());
   const auto& ipv6block =
      std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>>(addr_blocks[1].addr_choice());

   auto& v4_blocks = ipv4block.ranges().value();

   // 192.168.0.0
   result.test_eq("ipv4 block 0 min", v4_blocks[0].min().value(), "C0A80000");
   // 192.168.127.255
   result.test_eq("ipv4 block 0 max", v4_blocks[0].max().value(), "C0A87FFF");

   // 193.168.0.0
   result.test_eq("ipv4 block 1 min", v4_blocks[1].min().value(), "C1A80000");
   // 193.169.255.255
   result.test_eq("ipv4 block 1 max", v4_blocks[1].max().value(), "C1A9FFFF");

   // 194.168.0.0
   result.test_eq("ipv4 block 2 min", v4_blocks[2].min().value(), "C2A80000");
   // 195.175.1.2
   result.test_eq("ipv4 block 2 max", v4_blocks[2].max().value(), "C3AF0102");

   // 196.168.0.1
   result.test_eq("ipv4 block 3 min", v4_blocks[3].min().value(), "C4A80001");
   // 196.168.0.1
   result.test_eq("ipv4 block 3 max", v4_blocks[3].max().value(), "C4A80001");

   auto& v6_blocks = ipv6block.ranges().value();

   result.test_eq("ipv6 block 0 min", v6_blocks[0].min().value(), "FA800000000000000000000000000000");
   result.test_eq("ipv6 block 0 max", v6_blocks[0].max().value(), "FA800000000000007FFFFFFFFFFFFFFF");
   result.test_eq("ipv6 block 1 min", v6_blocks[1].min().value(), "FE200000000000000000000000000000");
   result.test_eq("ipv6 block 1 max", v6_blocks[1].max().value(), "FE20000007FFFFFFFFFFFFFFFFFFFFFF");
   result.test_eq("ipv6 block 2 min", v6_blocks[2].min().value(), "2003000068293435042010C5000000C4");
   result.test_eq("ipv6 block 2 max", v6_blocks[2].max().value(), "2003000068293435042010C5000000C4");
   result.test_eq("ipv6 block 3 min", v6_blocks[3].min().value(), "AB010000000000000000000000000001");
   result.test_eq("ipv6 block 3 max", v6_blocks[3].max().value(), "CD020000000000000000000000000002");

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_extension_decode() {
   Test::Result result("X509 AS Block decode");
   result.start_timer();
   using Botan::Cert_Extension::ASBlocks;

   {
      const std::string filename("ASNumberCert.pem");
      Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));

      auto as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

      const auto& identifier = as_blocks->as_identifiers();
      result.confirm("cert has ASBlock extension", as_blocks != nullptr, true);

      const auto& asnum = identifier.asnum().value().ranges().value();
      const auto& rdi = identifier.rdi().value().ranges().value();

      // cert contains asnum 0-999, 5042, 0-4294967295
      result.confirm("asnum entry 0 min", asnum[0].min() == 0, true);
      result.confirm("asnum entry 0 max", asnum[0].max() == 4294967295, true);

      // and rdi 1234-5678, 32768, 0-4294967295
      result.confirm("rdi entry 0 min", rdi[0].min() == 0, true);
      result.confirm("rdi entry 0 max", rdi[0].max() == 4294967295, true);
   }
   {
      const std::string filename("ASNumberOnly.pem");
      Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));

      auto as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

      const auto& identifier = as_blocks->as_identifiers();
      result.confirm("cert has ASBlock extension", as_blocks != nullptr, true);

      const auto& asnum = identifier.asnum().value().ranges().value();
      result.confirm("cert has no RDI entries", identifier.rdi().has_value(), false);

      // contains 0-999, 0-4294967295
      result.confirm("asnum entry 0 min", asnum[0].min() == 0, true);
      result.confirm("asnum entry 0 max", asnum[0].max() == 4294967295, true);
   }
   {
      const std::string filename("ASRdiOnly.pem");
      Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));

      auto as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

      const auto& identifier = as_blocks->as_identifiers();
      result.confirm("cert has ASBlock extension", as_blocks != nullptr, true);

      result.confirm("cert has no ASNUM entries", identifier.asnum().has_value(), false);
      const auto& rdi = identifier.rdi().value().ranges().value();

      // contains 1234-5678, 0-4294967295
      result.confirm("rdi entry 0 min", rdi[0].min() == 0, true);
      result.confirm("rdi entry 0 max", rdi[0].max() == 4294967295, true);
   }
   {
      const std::string filename("ASNumberInherit.pem");
      Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));

      auto as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

      const auto& identifier = as_blocks->as_identifiers();
      result.confirm("cert has ASBlock extension", as_blocks != nullptr, true);

      result.confirm("asnum has no entries", identifier.asnum().value().ranges().has_value(), false);
      const auto& rdi = identifier.rdi().value().ranges().value();

      // contains 1234-5678, 0-4294967295
      result.confirm("rdi entry 0 min", rdi[0].min() == 0, true);
      result.confirm("rdi entry 0 max", rdi[0].max() == 4294967295, true);
   }

   result.end_timer();
   return result;
}

   #endif

Test::Result test_x509_ip_addr_blocks_extension_encode() {
   Test::Result result("X509 IP Address Block encode");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;

   auto rng = Test::new_rng(__func__);

   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto ca_key = generate_key(sig_algo, *rng);
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts(), *ca_key, hash_fn, *rng);
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, padding_method, *rng);
   auto key = generate_key(sig_algo, *rng);

   for(size_t i = 0; i < 64; i++) {
      bool push_ipv4_ranges = i & 1;
      bool push_ipv6_ranges = i >> 1 & 1;
      bool inherit_ipv4 = i >> 2 & 1;
      bool inherit_ipv6 = i >> 3 & 1;
      bool push_ipv4_family = i >> 4 & 1;
      bool push_ipv6_family = i >> 5 & 1;

      Botan::X509_Cert_Options opts = req_opts1(sig_algo);

      std::vector<uint8_t> a = {123, 123, 2, 1};
      auto ipv4_1 = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(a);
      a = {255, 255, 255, 255};
      auto ipv4_2 = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(a);

      // encoded as min, max
      a = {127, 0, 0, 1};
      auto ipv4_range_1_min = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(a);
      a = {189, 5, 7, 255};
      auto ipv4_range_1_max = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(a);

      // encoded as prefix
      a = {190, 5, 0, 0};
      auto ipv4_range_2_min = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(a);
      a = {190, 5, 127, 255};
      auto ipv4_range_2_max = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(a);

      a = {0xab, 0xcd, 0xde, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      auto ipv6_1 = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(a);
      a = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
      auto ipv6_2 = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(a);

      // encoded as min, max
      a = {0xaf, 0x23, 0x34, 0x45, 0x67, 0x2a, 0x7d, 0xef, 0x8c, 0x00, 0x00, 0x00, 0x66, 0x00, 0x52, 0x00};
      auto ipv6_range_1_min = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(a);

      a = {0xaf, 0xcd, 0xde, 0xf0, 0x00, 0x0f, 0xee, 0x00, 0xbb, 0x4a, 0x9b, 0x00, 0x00, 0x4c, 0x00, 0xcc};
      auto ipv6_range_1_max = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(a);

      // encoded as prefix
      a = {0xbf, 0xcd, 0xde, 0xf0, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      auto ipv6_range_2_min = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(a);
      a = {0xbf, 0xcd, 0xde, 0xf0, 0x00, 0x00, 0x00, 0x07, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
      auto ipv6_range_2_max = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(a);

      auto ipv4_range_1 = IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>(ipv4_1);
      auto ipv4_range_2 =
         IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>(ipv4_range_1_min, ipv4_range_1_max);
      auto ipv4_range_3 =
         IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>(ipv4_range_2_min, ipv4_range_2_max);
      auto ipv4_range_4 = IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>(ipv4_2);

      auto ipv6_range_1 = IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>(ipv6_1);
      auto ipv6_range_2 =
         IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>(ipv6_range_1_min, ipv6_range_1_max);
      auto ipv6_range_3 =
         IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>(ipv6_range_2_min, ipv6_range_2_max);
      auto ipv6_range_4 = IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>(ipv6_2);

      std::vector<IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>> ipv4_ranges;
      if(push_ipv4_ranges) {
         ipv4_ranges.push_back(ipv4_range_1);
         ipv4_ranges.push_back(ipv4_range_2);
         ipv4_ranges.push_back(ipv4_range_3);
         ipv4_ranges.push_back(ipv4_range_4);
      }

      std::vector<IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>> ipv6_ranges;
      if(push_ipv6_ranges) {
         ipv6_ranges.push_back(ipv6_range_1);
         ipv6_ranges.push_back(ipv6_range_2);
         ipv6_ranges.push_back(ipv6_range_3);
         ipv6_ranges.push_back(ipv6_range_4);
      }

      auto ipv4_addr_choice = IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>();
      if(!inherit_ipv4) {
         ipv4_addr_choice = IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>(ipv4_ranges);
      }

      auto ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>();
      if(!inherit_ipv6) {
         ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>(ipv6_ranges);
      }

      auto ipv4_addr_family = IPAddressBlocks::IPAddressFamily(ipv4_addr_choice);
      auto ipv6_addr_family = IPAddressBlocks::IPAddressFamily(ipv6_addr_choice);

      std::vector<IPAddressBlocks::IPAddressFamily> addr_blocks;
      if(push_ipv4_family) {
         addr_blocks.push_back(ipv4_addr_family);
      }
      if(push_ipv6_family) {
         addr_blocks.push_back(ipv6_addr_family);
      }

      std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>(addr_blocks);

      opts.extensions.add(std::move(blocks));

      Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, hash_fn, *rng);
      Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
      {
         auto ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
         result.confirm("cert has IPAddrBlocks extension", ip_blocks != nullptr, true);

         const auto& dec_addr_blocks = ip_blocks->addr_blocks();
         if(!push_ipv4_family && !push_ipv6_family) {
            result.confirm("no address family entries", dec_addr_blocks.empty(), true);
            continue;
         }

         if(push_ipv4_family) {
            auto family = dec_addr_blocks[0];
            result.confirm("ipv4 family afi", ipv4_addr_family.afi() == family.afi(), true);
            result.confirm("ipv4 family safi", ipv4_addr_family.safi() == family.safi(), true);
            auto choice =
               std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>>(family.addr_choice());

            if(!inherit_ipv4) {
               auto ranges = choice.ranges().value();
               if(push_ipv4_ranges) {
                  result.confirm("ipv4 entry 0 min", ranges[0].min().value() == ipv4_range_1.min().value(), true);
                  result.confirm("ipv4 entry 0 max", ranges[0].max().value() == ipv4_range_1.max().value(), true);
                  result.confirm("ipv4 entry 1 min", ranges[1].min().value() == ipv4_range_2.min().value(), true);
                  result.confirm("ipv4 entry 1 max", ranges[1].max().value() == ipv4_range_2.max().value(), true);
                  result.confirm("ipv4 entry 2 min", ranges[2].min().value() == ipv4_range_3.min().value(), true);
                  result.confirm("ipv4 entry 2 max", ranges[2].max().value() == ipv4_range_3.max().value(), true);
                  result.confirm("ipv4 entry 3 min", ranges[3].min().value() == ipv4_range_4.min().value(), true);
                  result.confirm("ipv4 entry 3 max", ranges[3].max().value() == ipv4_range_4.max().value(), true);
               } else {
                  result.confirm("ipv4 range has no entries", ranges.empty(), true);
               }
            } else {
               result.confirm("ipv4 family inherit", choice.ranges().has_value(), false);
            }
         }

         if(push_ipv6_family) {
            auto family = dec_addr_blocks[dec_addr_blocks.size() - 1];
            result.confirm("ipv6 family afi", ipv6_addr_family.afi() == family.afi(), true);
            result.confirm("ipv6 family safi", ipv6_addr_family.safi() == family.safi(), true);
            auto choice =
               std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>>(family.addr_choice());
            if(!inherit_ipv6) {
               auto ranges = choice.ranges().value();
               if(push_ipv6_ranges) {
                  result.confirm("ipv6 entry 0 min", ranges[0].min().value() == ipv6_range_1.min().value(), true);
                  result.confirm("ipv6 entry 0 max", ranges[0].max().value() == ipv6_range_1.max().value(), true);
                  result.confirm("ipv6 entry 1 min", ranges[1].min().value() == ipv6_range_2.min().value(), true);
                  result.confirm("ipv6 entry 1 max", ranges[1].max().value() == ipv6_range_2.max().value(), true);
                  result.confirm("ipv6 entry 2 min", ranges[2].min().value() == ipv6_range_3.min().value(), true);
                  result.confirm("ipv6 entry 2 max", ranges[2].max().value() == ipv6_range_3.max().value(), true);
                  result.confirm("ipv6 entry 3 min", ranges[3].min().value() == ipv6_range_4.min().value(), true);
                  result.confirm("ipv6 entry 3 max", ranges[3].max().value() == ipv6_range_4.max().value(), true);
               } else {
                  result.confirm("ipv6 range has no entries", ranges.empty(), true);
               }
            } else {
               result.confirm("ipv6 family inherit", choice.ranges().has_value(), false);
            }
         }
      }
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_extension_encode_edge_cases() {
   Test::Result result("X509 IP Address Block encode edge cases");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;

   auto rng = Test::new_rng(__func__);

   // trailing 0s, trailing 1s, and some arbitrary values
   std::vector<uint8_t> edge_values = {2, 4, 8, 16, 32, 64, 128, 0, 1, 3, 7, 15, 31, 63, 127, 255, 12, 46, 123, 234};

   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto ca_key = generate_key(sig_algo, *rng);
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts(), *ca_key, hash_fn, *rng);
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, padding_method, *rng);
   auto key = generate_key(sig_algo, *rng);

   for(size_t i = 0; i < edge_values.size(); i++) {
      for(size_t j = 0; j < 18; j++) {
         Botan::X509_Cert_Options opts = req_opts1(sig_algo);

         std::vector<uint8_t> min_bytes(16, 0x00);
         std::vector<uint8_t> max_bytes(16, 0xFF);

         min_bytes[15 - (j < 2 ? 0 : j - 2)] = edge_values[i];
         max_bytes[15 - (j > 15 ? 15 : j)] = edge_values[i];

         auto address_min = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(min_bytes);
         auto address_max = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6>(max_bytes);

         auto ipv6_range = IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>(address_min, address_max);

         std::vector<IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv6>> ipv6_ranges;
         ipv6_ranges.push_back(ipv6_range);

         auto ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>(ipv6_ranges);

         auto ipv6_addr_family = IPAddressBlocks::IPAddressFamily(ipv6_addr_choice);

         std::vector<IPAddressBlocks::IPAddressFamily> addr_blocks;
         addr_blocks.push_back(ipv6_addr_family);

         std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>(addr_blocks);

         opts.extensions.add(std::move(blocks));

         Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, hash_fn, *rng);
         Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
         {
            auto ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
            result.confirm("cert has IPAddrBlocks extension", ip_blocks != nullptr, true);
            const auto& dec_addr_blocks = ip_blocks->addr_blocks();
            auto family = dec_addr_blocks[0];
            result.confirm("ipv6 family afi", ipv6_addr_family.afi() == family.afi(), true);
            result.confirm("ipv6 family safi", ipv6_addr_family.safi() == family.safi(), true);
            auto choice =
               std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>>(family.addr_choice());
            auto ranges = choice.ranges().value();

            result.confirm("ipv6 edge case min", ranges[0].min().value() == ipv6_range.min().value(), true);
            result.confirm("ipv6 edge case max", ranges[0].max().value() == ipv6_range.max().value(), true);
         }
      }
   }
   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_range_merge() {
   Test::Result result("X509 IP Address Block range merge");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;

   auto rng = Test::new_rng(__func__);

   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto ca_key = generate_key(sig_algo, *rng);
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts(), *ca_key, hash_fn, *rng);
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, padding_method, *rng);
   auto key = generate_key(sig_algo, *rng);
   Botan::X509_Cert_Options opts = req_opts1(sig_algo);

   std::vector<std::vector<std::vector<uint8_t>>> addresses = {
      {{11, 0, 0, 0}, {{11, 0, 0, 0}}},
      {{123, 123, 123, 123}, {123, 123, 123, 123}},
      {{10, 4, 5, 9}, {{10, 255, 0, 0}}},
      {{12, 0, 0, 0}, {191, 0, 0, 1}},
      {{190, 0, 0, 0}, {193, 0, 255, 255}},
      {{10, 10, 10, 10}, {10, 20, 20, 20}},
      {{5, 0, 0, 0}, {10, 255, 255, 255}},
      {{192, 0, 0, 0}, {192, 255, 255, 255}},
      {{11, 0, 0, 1}, {11, 255, 255, 255}},
   };

   std::vector<IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>> ipv6_ranges;
   for(auto pair : addresses) {
      auto address_min = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(pair[0]);
      auto address_max = IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4>(pair[1]);
      auto range = IPAddressBlocks::IPAddressOrRange<IPAddressBlocks::Version::IPv4>(address_min, address_max);
      ipv6_ranges.push_back(range);
   }

   auto ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>(ipv6_ranges);
   auto ipv6_addr_family = IPAddressBlocks::IPAddressFamily(ipv6_addr_choice);

   std::vector<IPAddressBlocks::IPAddressFamily> addr_blocks;
   addr_blocks.push_back(ipv6_addr_family);

   std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>(addr_blocks);

   opts.extensions.add(std::move(blocks));

   Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, hash_fn, *rng);
   Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
   {
      auto ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
      result.confirm("cert has IPAddrBlocks extension", ip_blocks != nullptr, true);
      const auto& dec_addr_blocks = ip_blocks->addr_blocks();
      auto family = dec_addr_blocks[0];
      auto choice = std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>>(family.addr_choice());
      auto ranges = choice.ranges().value();

      std::array<uint8_t, 4> expected_min = {5, 0, 0, 0};
      std::array<uint8_t, 4> expected_max = {193, 0, 255, 255};

      result.test_eq("range expected min", ranges[0].min().value(), expected_min);
      result.test_eq("range expected max", ranges[0].max().value(), expected_max);
      result.test_eq("range length", ranges.size(), 1);
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_extension_encode() {
   Test::Result result("X509 AS Number encode");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;

   auto rng = Test::new_rng(__func__);

   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto ca_key = generate_key(sig_algo, *rng);
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts(), *ca_key, hash_fn, *rng);
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, padding_method, *rng);
   auto key = generate_key(sig_algo, *rng);

   for(size_t i = 0; i < 16; i++) {
      bool push_asnum = i & 1;
      bool push_rdi = i >> 1 & 1;
      bool include_asnum = i >> 2 & 1;
      bool include_rdi = i >> 3 & 1;

      ASBlocks::ASIdOrRange asnum_id_or_range0 = ASBlocks::ASIdOrRange(0, 999);
      ASBlocks::ASIdOrRange asnum_id_or_range1 = ASBlocks::ASIdOrRange(5042);
      ASBlocks::ASIdOrRange asnum_id_or_range2 = ASBlocks::ASIdOrRange(5043, 4294967295);

      ASBlocks::ASIdOrRange rdi_id_or_range0 = ASBlocks::ASIdOrRange(1234, 5678);
      ASBlocks::ASIdOrRange rdi_id_or_range1 = ASBlocks::ASIdOrRange(32768);
      ASBlocks::ASIdOrRange rdi_id_or_range2 = ASBlocks::ASIdOrRange(32769, 4294967295);

      std::vector<ASBlocks::ASIdOrRange> as_ranges;
      if(push_asnum) {
         as_ranges.push_back(asnum_id_or_range0);
         as_ranges.push_back(asnum_id_or_range1);
         as_ranges.push_back(asnum_id_or_range2);
      }

      std::vector<ASBlocks::ASIdOrRange> rdi_ranges;
      if(push_rdi) {
         rdi_ranges.push_back(rdi_id_or_range0);
         rdi_ranges.push_back(rdi_id_or_range1);
         rdi_ranges.push_back(rdi_id_or_range2);
      }

      ASBlocks::ASIdentifierChoice asnum = ASBlocks::ASIdentifierChoice(as_ranges);
      ASBlocks::ASIdentifierChoice rdi = ASBlocks::ASIdentifierChoice(rdi_ranges);

      ASBlocks::ASIdentifiers ident = ASBlocks::ASIdentifiers(include_asnum ? std::optional(asnum) : std::nullopt,
                                                              include_rdi ? std::optional(rdi) : std::nullopt);

      std::unique_ptr<ASBlocks> blocks = std::make_unique<ASBlocks>(ident);

      Botan::X509_Cert_Options opts = req_opts1(sig_algo);
      opts.extensions.add(std::move(blocks));

      Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, hash_fn, *rng);
      Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      {
         auto as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();
         result.confirm("cert has ASBlock extension", as_blocks != nullptr, true);

         const auto& identifier = as_blocks->as_identifiers();

         if(include_asnum) {
            const auto& asnum_entries = identifier.asnum().value().ranges().value();

            if(push_asnum) {
               result.confirm("asnum entry 0 min", asnum_entries[0].min() == 0, true);
               result.confirm("asnum entry 0 max", asnum_entries[0].max() == 999, true);

               result.confirm("asnum entry 1 min", asnum_entries[1].min() == 5042, true);
               result.confirm("asnum entry 1 max", asnum_entries[1].max() == 4294967295, true);
            } else {
               result.confirm("asnum has no entries", asnum_entries.empty(), true);
            }
         } else {
            result.confirm("no asnum entry", identifier.asnum().has_value(), false);
         }

         if(include_rdi) {
            const auto& rdi_entries = identifier.rdi().value().ranges().value();

            if(push_rdi) {
               result.confirm("rdi entry 0 min", rdi_entries[0].min() == 1234, true);
               result.confirm("rdi entry 0 max", rdi_entries[0].max() == 5678, true);

               result.confirm("rdi entry 1 min", rdi_entries[1].min() == 32768, true);
               result.confirm("rdi entry 1 max", rdi_entries[1].max() == 4294967295, true);
            } else {
               result.confirm("rdi has no entries", rdi_entries.empty(), true);
            }
         } else {
            result.confirm("rdi has no entry", identifier.rdi().has_value(), false);
         }
      }
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_as_blocks_range_merge() {
   Test::Result result("X509 IP Address Block range merge");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;

   auto rng = Test::new_rng(__func__);

   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto ca_key = generate_key(sig_algo, *rng);
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts(), *ca_key, hash_fn, *rng);
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, padding_method, *rng);
   auto key = generate_key(sig_algo, *rng);
   Botan::X509_Cert_Options opts = req_opts1(sig_algo);

   std::vector<std::vector<uint16_t>> ranges = {
      {2005, 37005},
      {60, 70},
      {22, 50},
      {35, 2000},
      {2001, 2004},
      {21, 21},
      {0, 20},
   };

   std::vector<ASBlocks::ASIdOrRange> as_ranges;
   for(auto pair : ranges) {
      auto range = ASBlocks::ASIdOrRange(pair[0], pair[1]);
      as_ranges.push_back(range);
   }

   ASBlocks::ASIdentifierChoice asnum = ASBlocks::ASIdentifierChoice(as_ranges);

   ASBlocks::ASIdentifiers ident = ASBlocks::ASIdentifiers(std::optional(asnum), std::nullopt);

   std::unique_ptr<ASBlocks> blocks = std::make_unique<ASBlocks>(ident);

   opts.extensions.add(std::move(blocks));

   Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, hash_fn, *rng);
   Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
   {
      auto as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();
      result.confirm("cert has ASBlock extension", as_blocks != nullptr, true);

      const auto& identifier = as_blocks->as_identifiers();

      const auto& asnum_entries = identifier.asnum().value().ranges().value();

      result.confirm("asnum entry 0 min", asnum_entries[0].min() == 0, true);
      result.confirm("asnum entry 0 max", asnum_entries[0].max() == 37005, true);
      result.confirm("asnum length", asnum_entries.size() == 1, true);
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_family_merge() {
   Test::Result result("X509 IP Address Block family merge");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;

   auto rng = Test::new_rng(__func__);

   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto ca_key = generate_key(sig_algo, *rng);
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts(), *ca_key, hash_fn, *rng);
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, padding_method, *rng);
   auto key = generate_key(sig_algo, *rng);
   Botan::X509_Cert_Options opts = req_opts1(sig_algo);

   std::vector<IPAddressBlocks::IPAddressFamily> addr_blocks;

   IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4> v4_empty_choice;
   IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6> v6_empty_choice;

   uint8_t v4_bytes_1[4] = {123, 123, 123, 123};
   IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv4> v4_addr_1(v4_bytes_1);
   // create 2 prefixes from the v4 addresses -> they should be merged
   IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4> v4_choice_dupl({{{v4_addr_1}, {v4_addr_1}}});
   result.confirm(
      "IPAddressChoice v4 merges ranges already in constructor", v4_choice_dupl.ranges().value().size() == 1, true);
   IPAddressBlocks::IPAddressFamily v4_fam_dupl(v4_choice_dupl, 0);

   uint8_t v6_bytes_1[16] = {123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123};
   IPAddressBlocks::IPAddress<IPAddressBlocks::Version::IPv6> v6_addr_1(v6_bytes_1);
   IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6> v6_choice_dupl({{{v6_addr_1}, {v6_addr_1}}});
   result.confirm(
      "IPAddressChoice v6 merges already in constructor", v6_choice_dupl.ranges().value().size() == 1, true);
   IPAddressBlocks::IPAddressFamily v6_fam_dupl(v6_choice_dupl, 0);

   IPAddressBlocks::IPAddressFamily v4_empty_fam(v4_empty_choice);
   IPAddressBlocks::IPAddressFamily v6_empty_fam(v6_empty_choice);

   IPAddressBlocks::IPAddressFamily v4_empty_fam_safi(v4_empty_choice, 2);
   IPAddressBlocks::IPAddressFamily v6_empty_fam_safi(v6_empty_choice, 2);

   /*
   considering the push order, the resulting order should be
   [0] v4 no safi
   [1] v6 no safi
   [2] v4 safi
   [3] v6 safi
   */
   for(size_t i = 0; i < 3; i++) {
      addr_blocks.push_back(v4_empty_fam_safi);
      addr_blocks.push_back(v6_empty_fam);
      addr_blocks.push_back(v4_fam_dupl);
      addr_blocks.push_back(v6_empty_fam_safi);
      addr_blocks.push_back(v6_fam_dupl);
      addr_blocks.push_back(v4_empty_fam);
   }

   std::vector<IPAddressBlocks::IPAddressFamily> expected_blocks = {
      v4_empty_fam, v6_empty_fam, v4_fam_dupl, v4_empty_fam_safi, v6_fam_dupl, v6_empty_fam_safi};

   std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>(addr_blocks);

   opts.extensions.add(std::move(blocks));

   Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, hash_fn, *rng);
   Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

   auto ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
   result.confirm("cert has IPAddrBlocks extension", ip_blocks != nullptr, true);
   const auto& dec_blocks = ip_blocks->addr_blocks();

   result.confirm("blocks got merged lengthwise", dec_blocks.size() == expected_blocks.size(), true);

   bool sorted = true;
   for(size_t i = 0; i < dec_blocks.size() - 1; i++) {
      const IPAddressBlocks::IPAddressFamily& a = dec_blocks[i];
      const IPAddressBlocks::IPAddressFamily& b = dec_blocks[i + 1];

      uint32_t afam_a = a.afi();
      if(a.safi().has_value()) {
         afam_a = static_cast<uint32_t>(afam_a << 8) | a.safi().value();
      }

      uint32_t afam_b = b.afi();
      if(b.safi().has_value()) {
         afam_b = static_cast<uint32_t>(afam_b << 8) | b.safi().value();
      }

      if(afam_a > afam_b) {
         sorted = false;
         break;
      }
   }

   result.confirm("blocks got sorted", sorted, true);

   for(size_t i = 0; i < dec_blocks.size(); i++) {
      const IPAddressBlocks::IPAddressFamily& dec = dec_blocks[i];
      const IPAddressBlocks::IPAddressFamily& exp = expected_blocks[i];

      result.confirm("blocks match push order by afi at index " + std::to_string(i), dec.afi() == exp.afi(), true);
      result.confirm("blocks match push order by safi at index " + std::to_string(i), dec.safi() == exp.safi(), true);

      if((exp.afi() == 1) && (dec.afi() == 1)) {
         auto dec_choice =
            std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>>(dec.addr_choice());
         auto exp_choice =
            std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv4>>(exp.addr_choice());

         if(!exp_choice.ranges().has_value()) {
            result.confirm(
               "block ranges should inherit at index " + std::to_string(i), dec_choice.ranges().has_value(), false);
         } else {
            result.confirm(
               "block ranges should not inherit at index " + std::to_string(i), dec_choice.ranges().has_value(), true);

            if(dec_choice.ranges().has_value() == false) {
               continue;
            }

            auto dec_ranges = dec_choice.ranges().value();
            auto exp_ranges = exp_choice.ranges().value();
            result.confirm("block ranges got merged lengthwise at index " + std::to_string(i),
                           dec_ranges.size() == exp_ranges.size(),
                           true);

            if(dec_ranges.size() != exp_ranges.size()) {
               continue;
            }

            for(size_t j = 0; j < exp_ranges.size(); j++) {
               result.confirm(
                  "block ranges min got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].min() == dec_ranges[j].min(),
                  true);
               result.confirm(
                  "block ranges max got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].max() == dec_ranges[j].max(),
                  true);
            }
         }
      } else if((exp.afi() == 2) && (dec.afi() == 2)) {
         auto dec_choice =
            std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>>(dec.addr_choice());
         auto exp_choice =
            std::get<IPAddressBlocks::IPAddressChoice<IPAddressBlocks::Version::IPv6>>(exp.addr_choice());

         if(!exp_choice.ranges().has_value()) {
            result.confirm(
               "block ranges should inherit at index " + std::to_string(i), dec_choice.ranges().has_value(), false);
         } else {
            result.confirm(
               "block ranges should not inherit at index " + std::to_string(i), dec_choice.ranges().has_value(), true);

            if(dec_choice.ranges().has_value() == false) {
               continue;
            }

            auto dec_ranges = dec_choice.ranges().value();
            auto exp_ranges = exp_choice.ranges().value();
            result.confirm("block ranges got merged lengthwise at index " + std::to_string(i),
                           dec_ranges.size() == exp_ranges.size(),
                           true);

            if(dec_ranges.size() != exp_ranges.size()) {
               continue;
            }

            for(size_t j = 0; j < exp_ranges.size(); j++) {
               result.confirm(
                  "block ranges min got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].min() == dec_ranges[j].min(),
                  true);
               result.confirm(
                  "block ranges max got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].max() == dec_ranges[j].max(),
                  true);
            }
         }
      }
   }

   result.end_timer();
   return result;
}

class X509_RPKI_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
         results.push_back(test_x509_ip_addr_blocks_extension_decode());
         results.push_back(test_x509_as_blocks_extension_decode());
   #endif

         results.push_back(test_x509_ip_addr_blocks_extension_encode());
         results.push_back(test_x509_ip_addr_blocks_extension_encode_edge_cases());
         results.push_back(test_x509_ip_addr_blocks_range_merge());
         results.push_back(test_x509_ip_as_blocks_range_merge());
         results.push_back(test_x509_ip_addr_blocks_family_merge());
         results.push_back(test_x509_as_blocks_extension_encode());
         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_rpki", X509_RPKI_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
