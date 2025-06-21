/*
* (C) 2025 Jack Lloyd
* (C) 2025 Anton Einax, Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/certstor.h>
   #include <botan/pk_algs.h>
   #include <botan/pubkey.h>
   #include <botan/x509_ca.h>
   #include <botan/x509_ext.h>
   #include <botan/x509path.h>
   #include <botan/x509self.h>
   #include <botan/internal/calendar.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES)

struct CA_Creation_Result {
      Botan::X509_Certificate ca_cert;
      Botan::X509_CA ca;
      std::unique_ptr<Botan::Private_Key> sub_key;
      std::string sig_algo;
      std::string hash_fn;
};

Botan::X509_Time from_date(const int y, const int m, const int d) {
   const size_t this_year = Botan::calendar_point(std::chrono::system_clock::now()).year();

   Botan::calendar_point t(static_cast<uint32_t>(this_year + y), m, d, 0, 0, 0);
   return Botan::X509_Time(t.to_std_timepoint());
}

std::unique_ptr<Botan::Private_Key> generate_key(const std::string& algo, Botan::RandomNumberGenerator& rng) {
   std::string params;
   if(algo == "ECDSA") {
      params = "secp256r1";

   #if defined(BOTAN_HAS_ECC_GROUP)
      if(Botan::EC_Group::supports_named_group("secp192r1")) {
         params = "secp192r1";
      }
   #endif
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

Botan::X509_Cert_Options req_opts(const std::string& algo, const std::string& sig_padding = "") {
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
   #if defined(BOTAN_HAS_ECDSA)
   const std::string sig_algo{"ECDSA"};
   const std::string padding_method;
   const std::string hash_fn{"SHA-256"};
   #elif defined(BOTAN_HAS_ED25519)
   const std::string sig_algo{"Ed25519"};
   const std::string padding_method;
   const std::string hash_fn{"SHA-512"};
   #elif defined(BOTAN_HAS_RSA)
   const std::string sig_algo{"RSA"};
   const std::string padding_method{"EMSA3(SHA-256)"};
   const std::string hash_fn{"SHA-256"};
   #endif

   return std::make_tuple(sig_algo, padding_method, hash_fn);
}

Botan::X509_Certificate make_self_signed(std::unique_ptr<Botan::RandomNumberGenerator>& rng,
                                         const Botan::X509_Cert_Options& opts = std::move(ca_opts())) {
   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto key = generate_key(sig_algo, *rng);
   const auto cert = Botan::X509::create_self_signed_cert(opts, *key, hash_fn, *rng);

   return cert;
}

CA_Creation_Result make_ca(std::unique_ptr<Botan::RandomNumberGenerator>& rng,
                           const Botan::X509_Cert_Options& opts = std::move(ca_opts())) {
   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();
   auto ca_key = generate_key(sig_algo, *rng);
   const auto ca_cert = Botan::X509::create_self_signed_cert(opts, *ca_key, hash_fn, *rng);
   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, padding_method, *rng);
   auto sub_key = generate_key(sig_algo, *rng);

   return CA_Creation_Result{ca_cert, std::move(ca), std::move(sub_key), sig_algo, hash_fn};
}

std::pair<Botan::X509_Certificate, Botan::X509_CA> make_and_sign_ca(
   std::unique_ptr<Botan::Certificate_Extension> ext,
   Botan::X509_CA& parent_ca,
   std::unique_ptr<Botan::RandomNumberGenerator>& rng) {
   auto [sig_algo, padding_method, hash_fn] = get_sig_algo_padding();

   Botan::X509_Cert_Options opts = ca_opts();
   opts.extensions.add(std::move(ext));

   std::unique_ptr<Botan::Private_Key> key = generate_key(sig_algo, *rng);

   Botan::PKCS10_Request req = Botan::X509::create_cert_req(opts, *key, hash_fn, *rng);
   Botan::X509_Certificate cert = parent_ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
   Botan::X509_CA ca(cert, *key, hash_fn, padding_method, *rng);

   return std::make_pair(std::move(cert), std::move(ca));
}

constexpr auto IPv4 = Botan::Cert_Extension::IPAddressBlocks::Version::IPv4;
constexpr auto IPv6 = Botan::Cert_Extension::IPAddressBlocks::Version::IPv6;

   #if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

Test::Result test_x509_ip_addr_blocks_extension_decode() {
   Test::Result result("X509 IP Address Block decode");
   result.start_timer();
   using Botan::Cert_Extension::IPAddressBlocks;

   {
      const std::string filename("IPAddrBlocksAll.pem");
      Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));
      auto ip_addr_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();

      const auto& addr_blocks = ip_addr_blocks->addr_blocks();
      result.confirm("cert has IPAddrBlocks extension", ip_addr_blocks != nullptr, true);
      result.test_eq("cert has two IpAddrBlocks", addr_blocks.size(), 2);

      const auto& ipv4block = std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(addr_blocks[0].addr_choice());
      const auto& ipv6block = std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(addr_blocks[1].addr_choice());

      auto& v4_blocks = ipv4block.ranges().value();

      // cert contains (in this order)
      // 192.168.0.0 - 192.168.127.255 (192.168.0.0/17)
      // 193.168.0.0 - 193.169.255.255 (193.168.0.0/15)
      // 194.168.0.0 - 195.175.1.2
      // 196.168.0.1 - 196.168.0.1 (196.168.0.1/32)

      result.test_eq("ipv4 block 0 min", v4_blocks[0].min().value(), {192, 168, 0, 0});
      result.test_eq("ipv4 block 0 max", v4_blocks[0].max().value(), {192, 168, 127, 255});

      result.test_eq("ipv4 block 1 min", v4_blocks[1].min().value(), {193, 168, 0, 0});
      result.test_eq("ipv4 block 1 max", v4_blocks[1].max().value(), {193, 169, 255, 255});
      result.test_eq("ipv4 block 2 min", v4_blocks[2].min().value(), {194, 168, 0, 0});
      result.test_eq("ipv4 block 2 max", v4_blocks[2].max().value(), {195, 175, 1, 2});

      result.test_eq("ipv4 block 3 min", v4_blocks[3].min().value(), {196, 168, 0, 1});
      result.test_eq("ipv4 block 3 max", v4_blocks[3].max().value(), {196, 168, 0, 1});

      auto& v6_blocks = ipv6block.ranges().value();

      // cert contains (in this order)
      // fa80::/65
      // fe20::/37
      // 2003:0:6829:3435:420:10c5:0:c4/128
      // ab01:0:0:0:0:0:0:1-cd02:0:0:0:0:0:0:2

      result.test_eq("ipv6 block 0 min",
                     v6_blocks[0].min().value(),
                     {0x20, 0x03, 0x00, 0x00, 0x68, 0x29, 0x34, 0x35, 0x04, 0x20, 0x10, 0xc5, 0x00, 0x00, 0x00, 0xc4});
      result.test_eq("ipv6 block 0 max",
                     v6_blocks[0].max().value(),
                     {0x20, 0x03, 0x00, 0x00, 0x68, 0x29, 0x34, 0x35, 0x04, 0x20, 0x10, 0xc5, 0x00, 0x00, 0x00, 0xc4});
      result.test_eq("ipv6 block 1 min",
                     v6_blocks[1].min().value(),
                     {0xab, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
      result.test_eq("ipv6 block 1 max",
                     v6_blocks[1].max().value(),
                     {0xcd, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02});
      result.test_eq("ipv6 block 2 min",
                     v6_blocks[2].min().value(),
                     {0xfa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
      result.test_eq("ipv6 block 2 max",
                     v6_blocks[2].max().value(),
                     {0xfa, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
      result.test_eq("ipv6 block 3 min",
                     v6_blocks[3].min().value(),
                     {0xfe, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
      result.test_eq("ipv6 block 3 max",
                     v6_blocks[3].max().value(),
                     {0xfe, 0x20, 0x00, 0x00, 0x07, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
   }
   {
      const std::string filename("IPAddrBlocksUnsorted.pem");
      Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));
      auto ip_addr_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();

      // cert contains (in this order)
      // IPv6 (1) inherit
      // IPv6 0xff....0xff
      // IPv4 (2) inherit
      // IPv4 (1) 192.168.0.0 - 192.168.2.1
      // IPv4 (1) 192.168.2.2 - 200.0.0.0
      // IPv4 inherit

      // IPv4 ranges should be merged, IPv4 should come before IPv6, all should be sorted by safi

      const auto& addr_blocks = ip_addr_blocks->addr_blocks();
      result.test_eq("cert has two IpAddrBlocks", addr_blocks.size(), 5);

      result.test_eq("block 0 has no safi", addr_blocks[0].safi(), std::optional<uint8_t>{std::nullopt});
      result.confirm(
         "block 0 is inherited",
         !std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(addr_blocks[0].addr_choice()).ranges().has_value());

      result.test_eq("block 1 has correct safi", addr_blocks[1].safi(), std::optional<uint8_t>{1});
      const auto& block_1 =
         std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(addr_blocks[1].addr_choice()).ranges().value();

      result.confirm("block 1 has correct size", block_1.size() == 1);
      result.test_eq("block 1 min is correct", block_1[0].min().value(), {192, 168, 0, 0});
      result.test_eq("block 1 max is correct", block_1[0].max().value(), {200, 0, 0, 0});

      result.test_eq("block 2 has correct safi", addr_blocks[2].safi(), std::optional<uint8_t>{2});
      result.confirm(
         "block 2 is inherited",
         !std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(addr_blocks[2].addr_choice()).ranges().has_value());

      result.test_eq("block 3 has no safi", addr_blocks[3].safi(), std::optional<uint8_t>{std::nullopt});
      const auto& block_3 =
         std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(addr_blocks[3].addr_choice()).ranges().value();

      result.confirm("block 3 has correct size", block_3.size() == 1);
      result.test_eq("block 3 min is correct",
                     block_3[0].min().value(),
                     {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
      result.test_eq("block 3 max is correct",
                     block_3[0].max().value(),
                     {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});

      result.test_eq("block 24 has correct safi", addr_blocks[4].safi(), std::optional<uint8_t>{1});
      result.confirm(
         "block 4 is inherited",
         !std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(addr_blocks[4].addr_choice()).ranges().has_value());
   }
   {
      const std::string filename("InvalidIPAddrBlocks.pem");
      Botan::X509_Certificate cert(Test::data_file("x509/x509test/" + filename));

      // cert contains the 10.0.32.0/20 prefix, but with a 9 for the unused bits

      result.confirm("extension is present", cert.v3_extensions().extension_set(IPAddressBlocks::static_oid()));

      auto ext = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
      result.confirm("extension is not decoded", ext == nullptr);
   }

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

Test::Result test_x509_ip_addr_blocks_rfc3779_example() {
   Test::Result result("X509 IP Address Blocks rfc3779 example");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;
   auto rng = Test::new_rng(__func__);

   // construct like in https://datatracker.ietf.org/doc/html/rfc3779#page-18
   std::unique_ptr<IPAddressBlocks> blocks_1 = std::make_unique<IPAddressBlocks>();
   blocks_1->add_address<IPv4>({10, 0, 32, 0}, {10, 0, 47, 255}, 1);
   blocks_1->add_address<IPv4>({10, 0, 64, 0}, {10, 0, 64, 255}, 1);
   blocks_1->add_address<IPv4>({10, 1, 0, 0}, {10, 1, 255, 255}, 1);
   blocks_1->add_address<IPv4>({10, 2, 48, 0}, {10, 2, 63, 255}, 1);
   blocks_1->add_address<IPv4>({10, 2, 64, 0}, {10, 2, 64, 255}, 1);
   blocks_1->add_address<IPv4>({10, 3, 0, 0}, {10, 3, 255, 255}, 1);
   blocks_1->inherit<IPv6>();

   Botan::X509_Cert_Options opts_1 = ca_opts();
   opts_1.extensions.add(std::move(blocks_1));

   auto cert_1 = make_self_signed(rng, opts_1);

   auto bits_1 = cert_1.v3_extensions().get_extension_bits(IPAddressBlocks::static_oid());

   result.test_eq(
      "extension is encoded as specified",
      bits_1,
      "3035302B040300010130240304040A00200304000A00400303000A01300C0304040A02300304000A02400303000A033006040200020500");

   auto ext_1 = cert_1.v3_extensions().get_extension_object_as<IPAddressBlocks>();

   auto ext_1_addr_fam_1 = ext_1->addr_blocks()[0];
   result.test_eq("extension 1 ipv4 safi", ext_1_addr_fam_1.safi(), std::optional<uint8_t>(1));
   auto ext_1_ranges =
      std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(ext_1_addr_fam_1.addr_choice()).ranges().value();
   result.test_eq("extension 1 range 1 min", ext_1_ranges[0].min().value(), {10, 0, 32, 0});
   result.test_eq("extension 1 range 1 max", ext_1_ranges[0].max().value(), {10, 0, 47, 255});

   result.test_eq("extension 1 range 2 min", ext_1_ranges[1].min().value(), {10, 0, 64, 0});
   result.test_eq("extension 1 range 2 max", ext_1_ranges[1].max().value(), {10, 0, 64, 255});

   result.test_eq("extension 1 range 3 min", ext_1_ranges[2].min().value(), {10, 1, 0, 0});
   result.test_eq("extension 1 range 3 max", ext_1_ranges[2].max().value(), {10, 1, 255, 255});

   result.test_eq("extension 1 range 4 min", ext_1_ranges[3].min().value(), {10, 2, 48, 0});
   result.test_eq("extension 1 range 4 max", ext_1_ranges[3].max().value(), {10, 2, 64, 255});

   result.test_eq("extension 1 range 5 min", ext_1_ranges[4].min().value(), {10, 3, 0, 0});
   result.test_eq("extension 1 range 5 max", ext_1_ranges[4].max().value(), {10, 3, 255, 255});

   result.test_eq("extension 1 ipv6 safi", ext_1->addr_blocks()[1].safi(), std::optional<uint8_t>{std::nullopt});
   result.confirm(
      "extension 1 ipv6 inherited",
      !std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(ext_1->addr_blocks()[1].addr_choice()).ranges().has_value());

   // https://datatracker.ietf.org/doc/html/rfc3779#page-20
   std::unique_ptr<IPAddressBlocks> blocks_2 = std::make_unique<IPAddressBlocks>();
   blocks_2->add_address<IPv6>(
      {0x20, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
      {0x20, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});
   blocks_2->add_address<IPv4>({10, 0, 0, 0}, {10, 255, 255, 255}, 1);
   blocks_2->add_address<IPv4>({172, 16, 0, 0}, {172, 31, 255, 255}, 1);
   blocks_2->inherit<IPv4>(2);

   Botan::X509_Cert_Options opts_2 = ca_opts();
   opts_2.extensions.add(std::move(blocks_2));

   auto cert_2 = make_self_signed(rng, opts_2);

   auto bits_2 = cert_2.v3_extensions().get_extension_bits(IPAddressBlocks::static_oid());

   // see https://www.rfc-editor.org/errata/eid6792 as to why the B0 specified in the RFC is a AC here
   result.test_eq("extension is encoded as specified",
                  bits_2,
                  "302C3010040300010130090302000A030304AC10300704030001020500300F040200023009030700200100000002");

   auto ext_2 = cert_2.v3_extensions().get_extension_object_as<IPAddressBlocks>();

   auto ext_2_addr_fam_1 = ext_2->addr_blocks()[0];
   result.test_eq("extension 2 ipv4 1 safi", ext_2_addr_fam_1.safi(), std::optional<uint8_t>(1));
   auto ext_2_ranges_1 =
      std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(ext_2_addr_fam_1.addr_choice()).ranges().value();
   result.test_eq("extension 2 fam 1 range 1 min", ext_2_ranges_1[0].min().value(), {10, 0, 0, 0});
   result.test_eq("extension 2 fam 1 range 1 max", ext_2_ranges_1[0].max().value(), {10, 255, 255, 255});

   result.test_eq("extension 2 fam 1 range 2 min", ext_2_ranges_1[1].min().value(), {172, 16, 0, 0});
   result.test_eq("extension 2 fam 1 range 2 max", ext_2_ranges_1[1].max().value(), {172, 31, 255, 255});

   result.test_eq("extension 2 ipv4 2 safi", ext_2->addr_blocks()[1].safi(), std::optional<uint8_t>{2});
   result.confirm(
      "extension 2 ipv4 2 inherited",
      !std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(ext_2->addr_blocks()[1].addr_choice()).ranges().has_value());

   auto ext_2_addr_fam_3 = ext_2->addr_blocks()[2];
   result.test_eq("extension 2 ipv4 1 safi", ext_2_addr_fam_3.safi(), std::optional<uint8_t>(std::nullopt));
   auto ext_2_ranges_3 =
      std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(ext_2_addr_fam_3.addr_choice()).ranges().value();
   result.test_eq("extension 2 fam 3 range 1 min",
                  ext_2_ranges_3[0].min().value(),
                  {0x20, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
   result.test_eq("extension 2 fam 3 range 1 max",
                  ext_2_ranges_3[0].max().value(),
                  {0x20, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff});

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_encoding() {
   Test::Result result("X509 IP Address Blocks encoding");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;
   auto rng = Test::new_rng(__func__);

   std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>();

   // 64 - 127
   blocks->add_address<IPv4>({192, 168, 0b01000000, 0}, {192, 168, 0b01111111, 255}, 2);

   blocks->add_address<IPv4>({255, 255, 255, 255});
   // encoded as prefix
   blocks->add_address<IPv4>({190, 5, 0, 0}, {190, 5, 0b01111111, 255});
   // encoded as min, max
   blocks->add_address<IPv4>({127, 0, 0, 1}, {189, 5, 7, 255});

   // full address range
   blocks->add_address<IPv4>({0, 0, 0, 0}, {255, 255, 255, 255}, 1);

   blocks->add_address<IPv4>({123, 123, 2, 1});

   Botan::X509_Cert_Options opts = ca_opts();
   opts.extensions.add(std::move(blocks));

   auto cert = make_self_signed(rng, opts);
   auto bits = cert.v3_extensions().get_extension_bits(IPAddressBlocks::static_oid());

   // hand validated with https://lapo.it/asn1js/
   result.test_eq(
      "extension is encoded as specified",
      bits,
      "304630290402000130230305007B7B0201300D0305007F000001030403BD0500030407BE0500030500FFFFFFFF300A04030001013003030100300D04030001023006030406C0A840");

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_path_validation_success() {
   Test::Result result("X509 IP Address Blocks path validation success");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;
   auto rng = Test::new_rng(__func__);

   /*
   Creates a certificate chain of length 4.
   Root: ipv4 and ipv6
   Inherit: has both values as 'inherit'
   Dynamic: has either both 'inherit', both with values, or just one with a value
   Subject: both ipv4 and ipv6 as a subset of Root / Dynamic
   */

   // Root cert
   std::unique_ptr<IPAddressBlocks> root_blocks = std::make_unique<IPAddressBlocks>();

   root_blocks->add_address<IPv4>({120, 0, 0, 1}, {130, 140, 150, 160}, 42);
   root_blocks->add_address<IPv4>({10, 0, 0, 1}, {10, 255, 255, 255}, 42);

   root_blocks->add_address<IPv6>(
      {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
      {0xA0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});
   root_blocks->add_address<IPv6>(
      {0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
      {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF});

   // Inherit cert
   std::unique_ptr<IPAddressBlocks> inherit_blocks = std::make_unique<IPAddressBlocks>();

   inherit_blocks->inherit<IPv4>(42);
   inherit_blocks->inherit<IPv6>();

   // Subject cert
   std::unique_ptr<IPAddressBlocks> sub_blocks = std::make_unique<IPAddressBlocks>();

   sub_blocks->add_address<IPv4>({124, 0, 255, 0}, {126, 0, 0, 1}, 42);
   sub_blocks->add_address<IPv4>({10, 0, 2, 1}, {10, 42, 0, 255}, 42);

   sub_blocks->add_address<IPv6>(
      {0x00, 0x00, 0x00, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
      {0x0D, 0x00, 0x00, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});

   Botan::X509_Cert_Options root_opts = ca_opts();
   root_opts.extensions.add(std::move(root_blocks));
   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(rng, root_opts);
   Botan::X509_Cert_Options sub_opts = req_opts(sig_algo);
   sub_opts.extensions.add(std::move(sub_blocks));
   auto [inherit_cert, inherit_ca] = make_and_sign_ca(std::move(inherit_blocks), root_ca, rng);

   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root_cert);

   for(size_t i = 0; i < 4; i++) {
      bool include_v4 = i & 1;
      bool include_v6 = (i >> 1) & 1;

      // Dynamic Cert
      std::unique_ptr<IPAddressBlocks> dyn_blocks = std::make_unique<IPAddressBlocks>();
      if(include_v4) {
         dyn_blocks->add_address<IPv4>({122, 0, 0, 255}, {128, 255, 255, 255}, 42);
         dyn_blocks->add_address<IPv4>({10, 0, 0, 255}, {10, 255, 0, 1}, 42);
      } else {
         dyn_blocks->inherit<IPv4>(42);
      }

      if(include_v6) {
         dyn_blocks->add_address<IPv6>(
            {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
            {0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
      } else {
         dyn_blocks->inherit<IPv6>();
      }

      auto [dyn_cert, dyn_ca] = make_and_sign_ca(std::move(dyn_blocks), inherit_ca, rng);

      Botan::PKCS10_Request sub_req = Botan::X509::create_cert_req(sub_opts, *sub_key, hash_fn, *rng);
      Botan::X509_Certificate sub_cert =
         dyn_ca.sign_request(sub_req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      const Botan::Path_Validation_Restrictions restrictions(false, 80);
      std::vector<Botan::X509_Certificate> certs = {sub_cert, dyn_cert, inherit_cert};

      Botan::Path_Validation_Result path_result = Botan::x509_path_validate(certs, restrictions, trusted);
      result.require("path validation succeeds", path_result.successful_validation());
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_path_validation_failure() {
   Test::Result result("X509 IP Address Blocks path validation failure");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;
   auto rng = Test::new_rng(__func__);

   for(size_t i = 0; i < 7; i++) {
      bool all_inherit = (i == 0);
      bool different_safi = (i == 1);
      bool too_small_subrange = (i == 2);
      bool too_large_subrange = (i == 3);
      bool no_more_issuer_ranges = (i == 4);
      bool empty_issuer_ranges = (i == 5);
      bool nullptr_extensions = (i == 6);

      // Root cert
      std::unique_ptr<IPAddressBlocks> root_blocks = std::make_unique<IPAddressBlocks>();
      if(!all_inherit) {
         root_blocks->add_address<IPv4>({120, 0, 0, 1}, {130, 140, 150, 160}, 42);
      } else {
         root_blocks->inherit<IPv4>(42);
      }

      Botan::X509_Cert_Options root_opts = ca_opts();
      if(!nullptr_extensions) {
         root_opts.extensions.add(std::move(root_blocks));
      }
      auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(rng, root_opts);

      // Issuer Cert
      std::unique_ptr<IPAddressBlocks> iss_blocks = std::make_unique<IPAddressBlocks>();
      if(!all_inherit) {
         if(empty_issuer_ranges) {
            iss_blocks->restrict<IPv4>(42);
         } else {
            iss_blocks->add_address<IPv4>({122, 0, 0, 255}, {128, 255, 255, 255}, 42);
         }
      } else {
         iss_blocks->inherit<IPv4>(42);
      }

      auto [iss_cert, iss_ca] = make_and_sign_ca(std::move(iss_blocks), root_ca, rng);

      // Subject cert
      std::unique_ptr<IPAddressBlocks> sub_blocks = std::make_unique<IPAddressBlocks>();

      uint8_t safi = different_safi ? 41 : 42;

      if(!all_inherit) {
         if(too_small_subrange) {
            sub_blocks->add_address<IPv4>({118, 0, 255, 0}, {126, 0, 0, 1}, safi);
         } else if(too_large_subrange) {
            sub_blocks->add_address<IPv4>({124, 0, 255, 0}, {134, 0, 0, 1}, safi);
         } else if(no_more_issuer_ranges) {
            sub_blocks->add_address<IPv4>({140, 0, 0, 1}, {150, 0, 0, 1}, safi);
         } else {
            sub_blocks->add_address<IPv4>({124, 0, 255, 0}, {126, 0, 0, 1}, safi);
         }
      } else {
         sub_blocks->inherit<IPv4>(safi);
      }

      Botan::X509_Cert_Options sub_opts = req_opts(sig_algo);
      sub_opts.extensions.add(std::move(sub_blocks));

      Botan::PKCS10_Request sub_req = Botan::X509::create_cert_req(sub_opts, *sub_key, hash_fn, *rng);
      Botan::X509_Certificate sub_cert =
         iss_ca.sign_request(sub_req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      const Botan::Path_Validation_Restrictions restrictions(false, 80);
      std::vector<Botan::X509_Certificate> certs = {sub_cert, iss_cert};

      Botan::Certificate_Store_In_Memory trusted;
      trusted.add_certificate(root_cert);

      Botan::Path_Validation_Result path_result = Botan::x509_path_validate(certs, restrictions, trusted);
      result.require("path validation fails", !path_result.successful_validation());
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_rfc3779_example() {
   Test::Result result("X509 AS Blocks rfc3779 example");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;
   auto rng = Test::new_rng(__func__);

   // construct like in https://datatracker.ietf.org/doc/html/rfc3779#page-21
   std::unique_ptr<ASBlocks> blocks = std::make_unique<ASBlocks>();
   blocks->add_asnum(135);
   blocks->add_asnum(3000, 3999);
   blocks->add_asnum(5001);
   blocks->inherit_rdi();

   Botan::X509_Cert_Options opts = ca_opts();
   opts.extensions.add(std::move(blocks));

   auto cert = make_self_signed(rng, opts);
   auto bits = cert.v3_extensions().get_extension_bits(ASBlocks::static_oid());

   result.test_eq(
      "extension is encoded as specified", bits, "301AA014301202020087300802020BB802020F9F02021389A1020500");

   auto as_idents = cert.v3_extensions().get_extension_object_as<ASBlocks>()->as_identifiers();
   auto as_ids = as_idents.asnum().value().ranges().value();

   result.confirm("", as_ids[0].min() == 135);

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_encoding() {
   Test::Result result("X509 IP Address Blocks encoding");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;
   auto rng = Test::new_rng(__func__);

   std::unique_ptr<ASBlocks> blocks = std::make_unique<ASBlocks>();

   blocks->add_rdi(10);
   blocks->add_rdi(20, 30);
   blocks->add_rdi(42, 300);
   blocks->add_rdi(9, 301);

   blocks->inherit_asnum();
   blocks->add_asnum(20);
   // this overwrites the previous two
   blocks->restrict_asnum();

   Botan::X509_Cert_Options opts = ca_opts();
   opts.extensions.add(std::move(blocks));

   auto cert = make_self_signed(rng, opts);
   auto bits = cert.v3_extensions().get_extension_bits(ASBlocks::static_oid());

   result.test_eq("extension is encoded as specified", bits, "3011A0023000A10B300930070201090202012D");

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_path_validation_success() {
   Test::Result result("X509 AS Block path validation success");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;
   auto rng = Test::new_rng(__func__);

   /*
   Creates a certificate chain of length 4.
   Root: both asnum and rdi
   Inherit: has both values as 'inherit'
   Dynamic: has either both 'inherit', both with values, or just one with a value
   Subject: both asnum and rdi as a subset of Root / Dynamic
   */

   // Root Cert, both as and rdi

   std::unique_ptr<ASBlocks> root_blocks = std::make_unique<ASBlocks>();

   root_blocks->add_asnum(0, 999);
   root_blocks->add_asnum(5042);
   root_blocks->add_asnum(5043, 4294967295);

   root_blocks->add_rdi(1234, 5678);
   root_blocks->add_rdi(32768);
   root_blocks->add_rdi(32769, 4294967295);

   // Inherit cert, both as 'inherit'
   std::unique_ptr<ASBlocks> inherit_blocks = std::make_unique<ASBlocks>();
   inherit_blocks->inherit_asnum();
   inherit_blocks->inherit_rdi();

   // Subject cert

   std::unique_ptr<ASBlocks> sub_blocks = std::make_unique<ASBlocks>();

   sub_blocks->add_asnum(120, 180);
   sub_blocks->add_asnum(220, 240);
   sub_blocks->add_asnum(260, 511);
   sub_blocks->add_asnum(678);
   sub_blocks->add_asnum(5043, 5100);

   sub_blocks->add_rdi(1500, 2300);
   sub_blocks->add_rdi(2500, 4000);
   sub_blocks->add_rdi(1567);
   sub_blocks->add_rdi(33100, 40000);

   Botan::X509_Cert_Options root_opts = ca_opts();
   root_opts.extensions.add(std::move(root_blocks));
   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(rng, root_opts);
   Botan::X509_Cert_Options sub_opts = req_opts(sig_algo);
   sub_opts.extensions.add(std::move(sub_blocks));
   auto [inherit_cert, inherit_ca] = make_and_sign_ca(std::move(inherit_blocks), root_ca, rng);

   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root_cert);

   for(size_t i = 0; i < 4; i++) {
      bool include_asnum = i & 1;
      bool include_rdi = (i >> 1) & 1;

      std::unique_ptr<ASBlocks> dyn_blocks = std::make_unique<ASBlocks>();
      if(include_asnum) {
         dyn_blocks->add_asnum(100, 600);
         dyn_blocks->add_asnum(678);
         dyn_blocks->add_asnum(5042, 5101);
      } else {
         dyn_blocks->inherit_asnum();
      }

      if(include_rdi) {
         dyn_blocks->add_rdi(1500, 5000);
         dyn_blocks->add_rdi(33000, 60000);
      } else {
         dyn_blocks->inherit_rdi();
      }

      auto [dyn_cert, dyn_ca] = make_and_sign_ca(std::move(dyn_blocks), inherit_ca, rng);

      Botan::PKCS10_Request sub_req = Botan::X509::create_cert_req(sub_opts, *sub_key, hash_fn, *rng);
      Botan::X509_Certificate sub_cert =
         dyn_ca.sign_request(sub_req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      const Botan::Path_Validation_Restrictions restrictions(false, 80);
      std::vector<Botan::X509_Certificate> certs = {sub_cert, dyn_cert, inherit_cert};

      Botan::Path_Validation_Result path_result = Botan::x509_path_validate(certs, restrictions, trusted);
      result.require("path validation succeeds", path_result.successful_validation());
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_path_validation_extension_not_present() {
   Test::Result result("X509 AS Block path validation extension not present");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;
   auto rng = Test::new_rng(__func__);

   std::unique_ptr<ASBlocks> sub_blocks = std::make_unique<ASBlocks>();
   sub_blocks->add_asnum(120, 180);
   sub_blocks->add_asnum(220, 224);
   sub_blocks->add_asnum(260, 511);
   sub_blocks->add_asnum(678);
   sub_blocks->add_asnum(5043, 5100);

   sub_blocks->add_rdi(1500, 2300);
   sub_blocks->add_rdi(2500, 4000);
   sub_blocks->add_rdi(1567);
   sub_blocks->add_rdi(33100, 40000);

   // create a root ca that does not have any extension
   Botan::X509_Cert_Options root_opts = ca_opts();
   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(rng, root_opts);
   Botan::X509_Cert_Options sub_opts = req_opts(sig_algo);
   sub_opts.extensions.add(std::move(sub_blocks));
   Botan::PKCS10_Request sub_req = Botan::X509::create_cert_req(sub_opts, *sub_key, hash_fn, *rng);
   Botan::X509_Certificate sub_cert = root_ca.sign_request(sub_req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root_cert);

   const Botan::Path_Validation_Restrictions restrictions(false, 80);
   const std::vector<Botan::X509_Certificate> certs = {sub_cert};

   Botan::Path_Validation_Result path_result = Botan::x509_path_validate(certs, restrictions, trusted);
   result.require("path validation fails", !path_result.successful_validation());

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_path_validation_failure() {
   Test::Result result("X509 AS Block path validation failure");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;
   auto rng = Test::new_rng(__func__);

   /*
   This executes a few permutations, messing around with edge cases when it comes to constructing ranges.

   Each test is expected to fail and creates the following certificate chain:
   Root -> Issuer -> Subject

   00: set all the asnum choices to 'inherit' for each cert
   01: 00 but for rdis
   02: make smallest min asnum of the subject smaller than the smallest min asnum of the issuer
   03: 02 but for rdis
   04: both 02 and 03
   05: make largest max asnum of the subject larger than the largest max asnum of the issuer
   06: 05 but for rdis
   07: both 05 and 06
   08: make the certs have multiple ranges and make one asnum range that is not the smallest and not the largest overlap with it's maximum
   09: 08 but for rdis
   10: both 08 and 09
   11: same as 08 but the range in the subject is not contiguous, instead it is the issuers range but split into two ranges (e.g issuer range is 40-60, subject ranges are 40-49 and 51-61)
   12: 11 but for rdis
   13: both 11 and 12
   14: 08 but using the minimum instead of the maximum
   15: 14 but for rdis
   16: both 14 and 15
   17: same as 11 but using the minimum instead of the maximum
   18: 17 but for rdis
   19: both 18 and 19
   20: make the issuer ranges empty but have an entry in the subject ranges
   */
   for(size_t i = 0; i < 21; i++) {
      // enable / disable all the different edge cases
      bool inherit_all_asnums = (i == 0);
      bool inherit_all_rdis = (i == 1);
      bool push_asnum_min_edge_ranges = (i == 2) || (i == 4);
      bool push_rdi_min_edge_ranges = (i == 3) || (i == 4);
      bool push_asnum_max_edge_ranges = (i == 5) || (i == 7);
      bool push_rdi_max_edge_ranges = (i == 6) || (i == 7);
      bool push_asnum_max_middle_ranges = (i == 8) || (i == 10);
      bool push_rdi_max_middle_ranges = (i == 9) || (i == 10);
      bool push_asnum_max_split_ranges = (i == 11) || (i == 13);
      bool push_rdi_max_split_ranges = (i == 12) || (i == 13);
      bool push_asnum_min_middle_ranges = (i == 14) || (i == 16);
      bool push_rdi_min_middle_ranges = (i == 15) || (i == 16);
      bool push_asnum_min_split_ranges = (i == 17) || (i == 19);
      bool push_rdi_min_split_ranges = (i == 18) || (i == 19);
      bool empty_issuer_non_empty_subject = (i == 20);

      // Root cert
      std::unique_ptr<ASBlocks> root_blocks = std::make_unique<ASBlocks>();

      if(!inherit_all_asnums) {
         if(push_asnum_min_edge_ranges || push_asnum_max_edge_ranges) {
            // 100-200 for 02,03,04
            root_blocks->add_asnum(100, 200);
         } else if(push_asnum_max_middle_ranges || push_asnum_min_middle_ranges) {
            // 10-20,30-40,50-60 for 08,09,10
            root_blocks->add_asnum(10, 20);
            root_blocks->add_asnum(30, 40);
            root_blocks->add_asnum(50, 60);
         } else if(push_asnum_max_split_ranges || push_asnum_min_split_ranges) {
            // 10-20,30-50,60-70 for 11,12,13
            root_blocks->add_asnum(10, 20);
            root_blocks->add_asnum(30, 50);
            root_blocks->add_asnum(60, 70);
         }
      } else {
         root_blocks->inherit_asnum();
      }

      // same values but for rdis
      if(!inherit_all_rdis) {
         if(push_rdi_min_edge_ranges || push_rdi_max_edge_ranges) {
            root_blocks->add_rdi(100, 200);
         } else if(push_rdi_max_middle_ranges || push_rdi_min_middle_ranges) {
            root_blocks->add_rdi(10, 20);
            root_blocks->add_rdi(30, 40);
            root_blocks->add_rdi(50, 60);
         } else if(push_rdi_max_split_ranges || push_rdi_min_split_ranges) {
            root_blocks->add_rdi(10, 20);
            root_blocks->add_rdi(30, 50);
            root_blocks->add_rdi(60, 70);
         }
      } else {
         root_blocks->inherit_rdi();
      }

      if(empty_issuer_non_empty_subject) {
         root_blocks->restrict_asnum();
         root_blocks->restrict_rdi();
      }

      // Issuer cert
      // the issuer cert has the same ranges as the root cert
      // it is used to check that the 'inherit' check is bubbled up until the root cert is hit
      auto issu_blocks = root_blocks->copy();

      // Subject cert
      std::unique_ptr<ASBlocks> sub_blocks = std::make_unique<ASBlocks>();

      std::vector<ASBlocks::ASIdOrRange> sub_as_ranges;
      std::vector<ASBlocks::ASIdOrRange> sub_rdi_ranges;

      if(!inherit_all_asnums) {
         // assign the subject asnum ranges
         if(push_asnum_min_edge_ranges) {
            // 99-200 for 02 (so overlapping to the left)
            sub_blocks->add_asnum(99, 200);
         } else if(push_asnum_max_edge_ranges) {
            // 100-201 for 03 (so overlapping to the right)
            sub_blocks->add_asnum(100, 201);
         } else if(push_asnum_max_middle_ranges) {
            // same as root, but change the range in the middle to overlap to the right for 08
            sub_blocks->add_asnum(10, 20);
            sub_blocks->add_asnum(30, 41);
            sub_blocks->add_asnum(50, 60);
         } else if(push_asnum_max_split_ranges) {
            // change the range in the middle to be cut at 45 for case 11
            // the left range is 30-44
            // the right range is 46-51 (overlapping the issuer range to the right)
            sub_blocks->add_asnum(10, 20);
            sub_blocks->add_asnum(30, 44);
            sub_blocks->add_asnum(46, 51);
            sub_blocks->add_asnum(60, 70);
         } else if(push_asnum_min_middle_ranges) {
            // just change the test in the middle to overlap to the left for case 14
            sub_blocks->add_asnum(10, 20);
            sub_blocks->add_asnum(29, 40);
            sub_blocks->add_asnum(50, 60);
         } else if(push_asnum_min_split_ranges) {
            // again split the range in the middle at 45 for case 17
            // creating two ranges 29-44 and 46-50 (so overlapping to the left)
            sub_blocks->add_asnum(10, 20);
            sub_blocks->add_asnum(29, 44);
            sub_blocks->add_asnum(46, 50);
            sub_blocks->add_asnum(60, 70);
         } else if(empty_issuer_non_empty_subject) {
            sub_blocks->add_asnum(50);
         }
      } else {
         sub_blocks->inherit_asnum();
      }

      if(!inherit_all_rdis) {
         // same values but for rdis
         if(push_rdi_min_edge_ranges) {
            sub_blocks->add_rdi(99, 200);
         } else if(push_rdi_max_edge_ranges) {
            sub_blocks->add_rdi(100, 201);
         } else if(push_rdi_max_middle_ranges) {
            sub_blocks->add_rdi(10, 20);
            sub_blocks->add_rdi(30, 41);
            sub_blocks->add_rdi(50, 60);
         } else if(push_rdi_max_split_ranges) {
            sub_blocks->add_rdi(10, 20);
            sub_blocks->add_rdi(30, 44);
            sub_blocks->add_rdi(46, 51);
            sub_blocks->add_rdi(60, 70);
         } else if(push_rdi_min_middle_ranges) {
            sub_blocks->add_rdi(10, 20);
            sub_blocks->add_rdi(29, 40);
            sub_blocks->add_rdi(50, 60);
         } else if(push_rdi_min_split_ranges) {
            sub_blocks->add_rdi(10, 20);
            sub_blocks->add_rdi(29, 44);
            sub_blocks->add_rdi(46, 50);
            sub_blocks->add_rdi(60, 70);
         }
      } else {
         sub_blocks->inherit_rdi();
      }

      Botan::X509_Cert_Options root_opts = ca_opts();
      root_opts.extensions.add(std::move(root_blocks));
      auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(rng, root_opts);
      auto [issu_cert, issu_ca] = make_and_sign_ca(std::move(issu_blocks), root_ca, rng);

      Botan::X509_Cert_Options sub_opts = req_opts(sig_algo);
      sub_opts.extensions.add(std::move(sub_blocks));
      Botan::PKCS10_Request sub_req = Botan::X509::create_cert_req(sub_opts, *sub_key, hash_fn, *rng);
      Botan::X509_Certificate sub_cert =
         issu_ca.sign_request(sub_req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      Botan::Certificate_Store_In_Memory trusted;
      trusted.add_certificate(root_cert);

      const Botan::Path_Validation_Restrictions restrictions(false, 80);
      const std::vector<Botan::X509_Certificate> certs = {sub_cert, issu_cert};

      Botan::Path_Validation_Result path_result = Botan::x509_path_validate(certs, restrictions, trusted);
      // in all cases, the validation should fail, since we are creating invalid scenarios
      result.confirm("path validation fails at iteration " + std::to_string(i), !path_result.successful_validation());
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
         results.push_back(test_x509_ip_addr_blocks_rfc3779_example());
         results.push_back(test_x509_ip_addr_blocks_encoding());
         results.push_back(test_x509_ip_addr_blocks_path_validation_success());
         results.push_back(test_x509_ip_addr_blocks_path_validation_failure());
         results.push_back(test_x509_as_blocks_rfc3779_example());
         results.push_back(test_x509_as_blocks_encoding());
         results.push_back(test_x509_as_blocks_path_validation_success());
         results.push_back(test_x509_as_blocks_path_validation_extension_not_present());
         results.push_back(test_x509_as_blocks_path_validation_failure());
         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_rpki", X509_RPKI_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
