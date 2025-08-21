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
   #include <botan/x509_builder.h>
   #include <botan/x509_ca.h>
   #include <botan/x509_ext.h>
   #include <botan/x509path.h>
   #include <botan/internal/calendar.h>
#endif

#if defined(BOTAN_HAS_ECC_GROUP)
   #include <botan/ec_group.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_X509_CERTIFICATES) && \
   (defined(BOTAN_HAS_ECDSA) || defined(BOTAN_HAS_RSA) || defined(BOTAN_HAS_ED25519))

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
      params = "1024";
   }

   return Botan::create_private_key(algo, rng, params);
}

Botan::CertificateParametersBuilder ca_params() {
   Botan::CertificateParametersBuilder builder;

   builder.add_common_name("RPKI Test CA")
      .add_country("US")
      .add_organization("Botan")
      .add_dns("botan.randombit.net")
      .set_as_ca_certificate(1);

   return builder;
}

Botan::CertificateParametersBuilder user_params() {
   Botan::CertificateParametersBuilder builder;

   builder.add_common_name("RPKI Test User")
      .add_country("US")
      .add_organization("Botan")
      .add_allowed_usage(Botan::Key_Constraints::DigitalSignature);

   return builder;
}

std::pair<std::string, std::string> get_sig_algo() {
   #if defined(BOTAN_HAS_ECDSA)
   const std::string sig_algo{"ECDSA"};
   const std::string hash_fn{"SHA-256"};
   #elif defined(BOTAN_HAS_ED25519)
   const std::string sig_algo{"Ed25519"};
   const std::string hash_fn{"SHA-512"};
   #elif defined(BOTAN_HAS_RSA)
   const std::string sig_algo{"RSA"};
   const std::string padding_method{"PKCS1v15(SHA-256)"};
   const std::string hash_fn{"SHA-256"};
   #endif

   return std::make_pair(sig_algo, hash_fn);
}

Botan::X509_Certificate make_self_signed(Botan::RandomNumberGenerator& rng,
                                         const Botan::CertificateParametersBuilder& params) {
   auto [sig_algo, hash_fn] = get_sig_algo();
   auto key = generate_key(sig_algo, rng);

   const auto now = std::chrono::system_clock::now();
   const auto not_before = now - std::chrono::seconds(180);
   const auto not_after = now + std::chrono::seconds(86400);

   return params.into_self_signed_cert(not_before, not_after, *key, rng, hash_fn);
}

CA_Creation_Result make_ca(Botan::RandomNumberGenerator& rng, const Botan::CertificateParametersBuilder& params) {
   auto [sig_algo, hash_fn] = get_sig_algo();
   auto ca_key = generate_key(sig_algo, rng);

   const auto now = std::chrono::system_clock::now();
   const auto not_before = now - std::chrono::seconds(180);
   const auto not_after = now + std::chrono::seconds(86400);

   const auto ca_cert = params.into_self_signed_cert(not_before, not_after, *ca_key, rng, hash_fn);

   Botan::X509_CA ca(ca_cert, *ca_key, hash_fn, rng);
   auto sub_key = generate_key(sig_algo, rng);

   return CA_Creation_Result{ca_cert, std::move(ca), std::move(sub_key), sig_algo, hash_fn};
}

CA_Creation_Result make_ca(Botan::RandomNumberGenerator& rng) {
   return make_ca(rng, ca_params());
}

std::pair<Botan::X509_Certificate, Botan::X509_CA> make_and_sign_ca(std::unique_ptr<Botan::Certificate_Extension> ext,
                                                                    Botan::X509_CA& parent_ca,
                                                                    Botan::RandomNumberGenerator& rng) {
   auto [sig_algo, hash_fn] = get_sig_algo();

   auto params = ca_params();
   params.add_extension(std::move(ext));

   std::unique_ptr<Botan::Private_Key> key = generate_key(sig_algo, rng);

   Botan::PKCS10_Request req = params.into_pkcs10_request(*key, rng, hash_fn);

   Botan::X509_Certificate cert = parent_ca.sign_request(req, rng, from_date(-1, 01, 01), from_date(2, 01, 01));
   Botan::X509_CA ca(cert, *key, hash_fn, rng);

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
      const auto* ip_addr_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();

      const auto& addr_blocks = ip_addr_blocks->addr_blocks();
      result.confirm("cert has IPAddrBlocks extension", ip_addr_blocks != nullptr, true);
      result.test_eq("cert has two IpAddrBlocks", addr_blocks.size(), 2);

      const auto& ipv4block = std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(addr_blocks[0].addr_choice());
      const auto& ipv6block = std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(addr_blocks[1].addr_choice());

      const auto& v4_blocks = ipv4block.ranges().value();

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

      const auto& v6_blocks = ipv6block.ranges().value();

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
      const auto* ip_addr_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();

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

      const auto* ext = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
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

      const auto* as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

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

      const auto* as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

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

      const auto* as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

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

      const auto* as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();

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

   auto cert_1 = make_self_signed(*rng, ca_params().add_extension(std::move(blocks_1)));

   auto bits_1 = cert_1.v3_extensions().get_extension_bits(IPAddressBlocks::static_oid());

   result.test_eq(
      "extension is encoded as specified",
      bits_1,
      "3035302B040300010130240304040A00200304000A00400303000A01300C0304040A02300304000A02400303000A033006040200020500");

   const auto* ext_1 = cert_1.v3_extensions().get_extension_object_as<IPAddressBlocks>();

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

   auto cert_2 = make_self_signed(*rng, ca_params().add_extension(std::move(blocks_2)));

   auto bits_2 = cert_2.v3_extensions().get_extension_bits(IPAddressBlocks::static_oid());

   // see https://www.rfc-editor.org/errata/eid6792 as to why the B0 specified in the RFC is a AC here
   result.test_eq("extension is encoded as specified",
                  bits_2,
                  "302C3010040300010130090302000A030304AC10300704030001020500300F040200023009030700200100000002");

   const auto* ext_2 = cert_2.v3_extensions().get_extension_object_as<IPAddressBlocks>();

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

Test::Result test_x509_ip_addr_blocks_encode_builder() {
   Test::Result result("X509 IP Address Blocks encode (builder)");
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

   auto cert = make_self_signed(*rng, ca_params().add_extension(std::move(blocks)));
   auto bits = cert.v3_extensions().get_extension_bits(IPAddressBlocks::static_oid());

   // hand validated with https://lapo.it/asn1js/
   result.test_eq(
      "extension is encoded as specified",
      bits,
      "304630290402000130230305007B7B0201300D0305007F000001030403BD0500030407BE0500030500FFFFFFFF300A04030001013003030100300D04030001023006030406C0A840");

   result.end_timer();
   return result;
}

namespace {

template <size_t I>
bool bit_set(size_t v) {
   if(((v >> I) & 1) == 1) {
      return true;
   } else {
      return false;
   }
}

}  // namespace

Test::Result test_x509_ip_addr_blocks_extension_encode_ctor() {
   Test::Result result("X509 IP Address Block encode (ctor)");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;

   auto rng = Test::new_rng(__func__);

   auto [ca_cert, ca, sub_key, sig_algo, hash_fn] = make_ca(*rng);

   for(size_t i = 0; i < 64; i++) {
      bool push_ipv4_ranges = bit_set<0>(i);
      bool push_ipv6_ranges = bit_set<1>(i);
      bool inherit_ipv4 = bit_set<2>(i);
      bool inherit_ipv6 = bit_set<3>(i);
      bool push_ipv4_family = bit_set<4>(i);
      bool push_ipv6_family = bit_set<5>(i);

      std::vector<uint8_t> a = {123, 123, 2, 1};
      auto ipv4_1 = IPAddressBlocks::IPAddress<IPv4>(a);
      a = {255, 255, 255, 255};
      auto ipv4_2 = IPAddressBlocks::IPAddress<IPv4>(a);

      // encoded as min, max
      a = {127, 0, 0, 1};
      auto ipv4_range_1_min = IPAddressBlocks::IPAddress<IPv4>(a);
      a = {189, 5, 7, 255};
      auto ipv4_range_1_max = IPAddressBlocks::IPAddress<IPv4>(a);

      // encoded as prefix
      a = {190, 5, 0, 0};
      auto ipv4_range_2_min = IPAddressBlocks::IPAddress<IPv4>(a);
      a = {190, 5, 127, 255};
      auto ipv4_range_2_max = IPAddressBlocks::IPAddress<IPv4>(a);

      a = {0xAB, 0xCD, 0xDE, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      auto ipv6_1 = IPAddressBlocks::IPAddress<IPv6>(a);
      a = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      auto ipv6_2 = IPAddressBlocks::IPAddress<IPv6>(a);

      // encoded as min, max
      a = {0xAF, 0x23, 0x34, 0x45, 0x67, 0x2A, 0x7A, 0xEF, 0x8C, 0x00, 0x00, 0x00, 0x66, 0x00, 0x52, 0x00};
      auto ipv6_range_1_min = IPAddressBlocks::IPAddress<IPv6>(a);

      a = {0xAF, 0xCD, 0xDE, 0xF0, 0x00, 0x0F, 0xEE, 0x00, 0xBB, 0x4A, 0x9B, 0x00, 0x00, 0x4C, 0x00, 0xCC};
      auto ipv6_range_1_max = IPAddressBlocks::IPAddress<IPv6>(a);

      // encoded as prefix
      a = {0xBF, 0xCD, 0xDE, 0xF0, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
      auto ipv6_range_2_min = IPAddressBlocks::IPAddress<IPv6>(a);
      a = {0xBF, 0xCD, 0xDE, 0xF0, 0x00, 0x00, 0x00, 0x07, 0x1F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      auto ipv6_range_2_max = IPAddressBlocks::IPAddress<IPv6>(a);

      auto ipv4_range_1 = IPAddressBlocks::IPAddressOrRange<IPv4>(ipv4_1);
      auto ipv4_range_2 = IPAddressBlocks::IPAddressOrRange<IPv4>(ipv4_range_1_min, ipv4_range_1_max);
      auto ipv4_range_3 = IPAddressBlocks::IPAddressOrRange<IPv4>(ipv4_range_2_min, ipv4_range_2_max);
      auto ipv4_range_4 = IPAddressBlocks::IPAddressOrRange<IPv4>(ipv4_2);

      auto ipv6_range_1 = IPAddressBlocks::IPAddressOrRange<IPv6>(ipv6_1);
      auto ipv6_range_2 = IPAddressBlocks::IPAddressOrRange<IPv6>(ipv6_range_1_min, ipv6_range_1_max);
      auto ipv6_range_3 = IPAddressBlocks::IPAddressOrRange<IPv6>(ipv6_range_2_min, ipv6_range_2_max);
      auto ipv6_range_4 = IPAddressBlocks::IPAddressOrRange<IPv6>(ipv6_2);

      std::vector<IPAddressBlocks::IPAddressOrRange<IPv4>> ipv4_ranges;
      if(push_ipv4_ranges) {
         ipv4_ranges.push_back(ipv4_range_1);
         ipv4_ranges.push_back(ipv4_range_2);
         ipv4_ranges.push_back(ipv4_range_3);
         ipv4_ranges.push_back(ipv4_range_4);
      }

      std::vector<IPAddressBlocks::IPAddressOrRange<IPv6>> ipv6_ranges;
      if(push_ipv6_ranges) {
         ipv6_ranges.push_back(ipv6_range_1);
         ipv6_ranges.push_back(ipv6_range_2);
         ipv6_ranges.push_back(ipv6_range_3);
         ipv6_ranges.push_back(ipv6_range_4);
      }

      auto ipv4_addr_choice = IPAddressBlocks::IPAddressChoice<IPv4>();
      if(!inherit_ipv4) {
         ipv4_addr_choice = IPAddressBlocks::IPAddressChoice<IPv4>(ipv4_ranges);
      }

      auto ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPv6>();
      if(!inherit_ipv6) {
         ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPv6>(ipv6_ranges);
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

      auto req = user_params().add_extension(std::move(blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
      Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
      {
         const auto* ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
         result.confirm("cert has IPAddrBlocks extension", ip_blocks != nullptr, true);

         const auto& dec_addr_blocks = ip_blocks->addr_blocks();
         if(!push_ipv4_family && !push_ipv6_family) {
            result.confirm("no address family entries", dec_addr_blocks.empty(), true);
            continue;
         }

         if(push_ipv4_family) {
            auto family = dec_addr_blocks[0];
            result.confirm("ipv4 family afi", ipv4_addr_family.afi() == family.afi(), true);
            result.test_eq("ipv4 family safi", ipv4_addr_family.safi(), family.safi());
            auto choice = std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(family.addr_choice());

            if(!inherit_ipv4) {
               auto ranges = choice.ranges().value();
               if(push_ipv4_ranges) {
                  result.test_eq("ipv4 entry 0 min", ranges[0].min().value(), ipv4_range_1.min().value());
                  result.test_eq("ipv4 entry 0 max", ranges[0].max().value(), ipv4_range_1.max().value());
                  result.test_eq("ipv4 entry 1 min", ranges[1].min().value(), ipv4_range_2.min().value());
                  result.test_eq("ipv4 entry 1 max", ranges[1].max().value(), ipv4_range_2.max().value());
                  result.test_eq("ipv4 entry 2 min", ranges[2].min().value(), ipv4_range_3.min().value());
                  result.test_eq("ipv4 entry 2 max", ranges[2].max().value(), ipv4_range_3.max().value());
                  result.test_eq("ipv4 entry 3 min", ranges[3].min().value(), ipv4_range_4.min().value());
                  result.test_eq("ipv4 entry 3 max", ranges[3].max().value(), ipv4_range_4.max().value());
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
            result.test_eq("ipv6 family safi", ipv6_addr_family.safi(), family.safi());
            auto choice = std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(family.addr_choice());
            if(!inherit_ipv6) {
               auto ranges = choice.ranges().value();
               if(push_ipv6_ranges) {
                  result.test_eq("ipv6 entry 0 min", ranges[0].min().value(), ipv6_range_1.min().value());
                  result.test_eq("ipv6 entry 0 max", ranges[0].max().value(), ipv6_range_1.max().value());
                  result.test_eq("ipv6 entry 1 min", ranges[1].min().value(), ipv6_range_2.min().value());
                  result.test_eq("ipv6 entry 1 max", ranges[1].max().value(), ipv6_range_2.max().value());
                  result.test_eq("ipv6 entry 2 min", ranges[2].min().value(), ipv6_range_3.min().value());
                  result.test_eq("ipv6 entry 2 max", ranges[2].max().value(), ipv6_range_3.max().value());
                  result.test_eq("ipv6 entry 3 min", ranges[3].min().value(), ipv6_range_4.min().value());
                  result.test_eq("ipv6 entry 3 max", ranges[3].max().value(), ipv6_range_4.max().value());
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

Test::Result test_x509_ip_addr_blocks_extension_encode_edge_cases_ctor() {
   Test::Result result("X509 IP Address Block encode edge cases (ctor)");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;

   auto rng = Test::new_rng(__func__);

   // trailing 0s, trailing 1s, and some arbitrary values
   std::vector<uint8_t> edge_values = {0,  2,  4,  8,   16,  32, 64, 128, 1,   3,  7,
                                       15, 31, 63, 127, 255, 12, 46, 123, 160, 234};

   auto [ca_cert, ca, sub_key, sig_algo, hash_fn] = make_ca(*rng);

   for(size_t i = 0; i < edge_values.size(); i++) {
      for(size_t j = 0; j < 4; j++) {
         bool modify_min = bit_set<0>(j);
         bool modify_max = bit_set<1>(j);

         for(size_t k = 0; k < 18; k++) {
            if(!modify_min && !modify_max && (k > 0 || i > 0)) {
               // we don't modify anything, this is the extreme edge case of 0.0 ... - 255.255. ...
               // so we only need to do this once
               break;
            }

            std::vector<uint8_t> min_bytes(16, 0x00);
            std::vector<uint8_t> max_bytes(16, 0xFF);

            if(modify_min) {
               min_bytes[15 - (k < 2 ? 0 : k - 2)] = edge_values[i];
            }
            if(modify_max) {
               max_bytes[15 - (k > 15 ? 15 : k)] = edge_values[i];
            }

            auto address_min = IPAddressBlocks::IPAddress<IPv6>(min_bytes);
            auto address_max = IPAddressBlocks::IPAddress<IPv6>(max_bytes);

            auto ipv6_range = IPAddressBlocks::IPAddressOrRange<IPv6>(address_min, address_max);

            std::vector<IPAddressBlocks::IPAddressOrRange<IPv6>> ipv6_ranges;
            ipv6_ranges.push_back(ipv6_range);

            auto ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPv6>(ipv6_ranges);

            auto ipv6_addr_family = IPAddressBlocks::IPAddressFamily(ipv6_addr_choice);

            std::vector<IPAddressBlocks::IPAddressFamily> addr_blocks;
            addr_blocks.push_back(ipv6_addr_family);

            std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>(addr_blocks);

            auto req = user_params().add_extension(std::move(blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
            Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
            {
               const auto* ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
               result.confirm("cert has IPAddrBlocks extension", ip_blocks != nullptr, true);
               const auto& dec_addr_blocks = ip_blocks->addr_blocks();
               auto family = dec_addr_blocks[0];
               result.confirm("ipv6 family afi", ipv6_addr_family.afi() == family.afi(), true);
               result.test_eq("ipv6 family safi", ipv6_addr_family.safi(), family.safi());
               auto choice = std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(family.addr_choice());
               auto ranges = choice.ranges().value();

               result.test_eq("ipv6 edge case min", ranges[0].min().value(), ipv6_range.min().value());
               result.test_eq("ipv6 edge case max", ranges[0].max().value(), ipv6_range.max().value());
            }
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

   auto [ca_cert, ca, sub_key, sig_algo, hash_fn] = make_ca(*rng);

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

   std::vector<IPAddressBlocks::IPAddressOrRange<IPv4>> ipv6_ranges;
   for(auto pair : addresses) {
      auto address_min = IPAddressBlocks::IPAddress<IPv4>(pair[0]);
      auto address_max = IPAddressBlocks::IPAddress<IPv4>(pair[1]);
      auto range = IPAddressBlocks::IPAddressOrRange<IPv4>(address_min, address_max);
      ipv6_ranges.push_back(range);
   }

   auto ipv6_addr_choice = IPAddressBlocks::IPAddressChoice<IPv4>(ipv6_ranges);
   auto ipv6_addr_family = IPAddressBlocks::IPAddressFamily(ipv6_addr_choice);

   std::vector<IPAddressBlocks::IPAddressFamily> addr_blocks;
   addr_blocks.push_back(ipv6_addr_family);

   std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>(addr_blocks);

   auto req = user_params().add_extension(std::move(blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
   Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
   {
      const auto* ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
      result.confirm("cert has IPAddrBlocks extension", ip_blocks != nullptr, true);
      const auto& dec_addr_blocks = ip_blocks->addr_blocks();
      auto family = dec_addr_blocks[0];
      auto choice = std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(family.addr_choice());
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

Test::Result test_x509_ip_addr_blocks_family_merge() {
   Test::Result result("X509 IP Address Block family merge");
   result.start_timer();

   using Botan::Cert_Extension::IPAddressBlocks;

   auto rng = Test::new_rng(__func__);

   auto [ca_cert, ca, sub_key, sig_algo, hash_fn] = make_ca(*rng);

   std::vector<IPAddressBlocks::IPAddressFamily> addr_blocks;

   IPAddressBlocks::IPAddressChoice<IPv4> v4_empty_choice;
   IPAddressBlocks::IPAddressChoice<IPv6> v6_empty_choice;

   uint8_t v4_bytes_1[4] = {123, 123, 123, 123};
   IPAddressBlocks::IPAddress<IPv4> v4_addr_1(v4_bytes_1);
   // create 2 prefixes from the v4 addresses -> they should be merged

   std::vector<IPAddressBlocks::IPAddressOrRange<IPv4>> v4_choice_vec{
      IPAddressBlocks::IPAddressOrRange<IPv4>(IPAddressBlocks::IPAddress<IPv4>({v4_addr_1}))};
   IPAddressBlocks::IPAddressChoice<IPv4> v4_choice_dupl(v4_choice_vec);
   result.confirm(
      "IPAddressChoice v4 merges ranges already in constructor", v4_choice_dupl.ranges().value().size() == 1, true);
   IPAddressBlocks::IPAddressFamily v4_fam_dupl(v4_choice_dupl, 0);

   uint8_t v6_bytes_1[16] = {123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123, 123};
   IPAddressBlocks::IPAddress<IPv6> v6_addr_1(v6_bytes_1);

   std::vector<IPAddressBlocks::IPAddressOrRange<IPv6>> v6_choice_vec{
      IPAddressBlocks::IPAddressOrRange<IPv6>(IPAddressBlocks::IPAddress<IPv6>({v6_addr_1}))};
   IPAddressBlocks::IPAddressChoice<IPv6> v6_choice_dupl(v6_choice_vec);
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
   [2] v4 safi
   [1] v6 no safi
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
      v4_empty_fam, v4_fam_dupl, v4_empty_fam_safi, v6_empty_fam, v6_fam_dupl, v6_empty_fam_safi};

   std::unique_ptr<IPAddressBlocks> blocks = std::make_unique<IPAddressBlocks>(addr_blocks);

   auto req = user_params().add_extension(std::move(blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
   Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

   const auto* ip_blocks = cert.v3_extensions().get_extension_object_as<IPAddressBlocks>();
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
      } else {
         afam_a = static_cast<uint32_t>(afam_a << 8);
      }

      uint32_t afam_b = b.afi();
      if(b.safi().has_value()) {
         afam_b = static_cast<uint32_t>(afam_b << 8) | b.safi().value();
      } else {
         afam_b = static_cast<uint32_t>(afam_b << 8);
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
      result.test_eq("blocks match push order by safi at index " + std::to_string(i), dec.safi(), exp.safi());

      if((exp.afi() == 1) && (dec.afi() == 1)) {
         auto dec_choice = std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(dec.addr_choice());
         auto exp_choice = std::get<IPAddressBlocks::IPAddressChoice<IPv4>>(exp.addr_choice());

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
               result.test_eq(
                  "block ranges min got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].min().value(),
                  dec_ranges[j].min().value());
               result.test_eq(
                  "block ranges max got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].max().value(),
                  dec_ranges[j].max().value());
            }
         }
      } else if((exp.afi() == 2) && (dec.afi() == 2)) {
         auto dec_choice = std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(dec.addr_choice());
         auto exp_choice = std::get<IPAddressBlocks::IPAddressChoice<IPv6>>(exp.addr_choice());

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
               result.test_eq(
                  "block ranges min got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].min().value(),
                  dec_ranges[j].min().value());
               result.test_eq(
                  "block ranges max got merged valuewise at indices " + std::to_string(i) + "," + std::to_string(j),
                  exp_ranges[j].max().value(),
                  dec_ranges[j].max().value());
            }
         }
      }
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_path_validation_success_builder() {
   Test::Result result("X509 IP Address Blocks path validation success (builder)");
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

   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] =
      make_ca(*rng, ca_params().add_extension(std::move(root_blocks)));
   auto [inherit_cert, inherit_ca] = make_and_sign_ca(std::move(inherit_blocks), root_ca, *rng);

   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root_cert);

   for(size_t i = 0; i < 4; i++) {
      bool include_v4 = bit_set<0>(i);
      bool include_v6 = bit_set<1>(i);

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

      auto [dyn_cert, dyn_ca] = make_and_sign_ca(std::move(dyn_blocks), inherit_ca, *rng);

      const auto sub_req = user_params().add_extension(sub_blocks->copy()).into_pkcs10_request(*sub_key, *rng, hash_fn);

      const auto sub_cert = dyn_ca.sign_request(sub_req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      const Botan::Path_Validation_Restrictions restrictions(false, 80);
      std::vector<Botan::X509_Certificate> certs = {sub_cert, dyn_cert, inherit_cert};

      Botan::Path_Validation_Result path_result = Botan::x509_path_validate(certs, restrictions, trusted);
      result.require("path validation succeeds", path_result.successful_validation());
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_path_validation_success_ctor() {
   Test::Result result("X509 IP Address Block path validation success (ctor)");
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
   std::vector<uint8_t> a = {120, 0, 0, 1};
   auto root_ipv4_range_1_min = IPAddressBlocks::IPAddress<IPv4>{a};
   a = {130, 140, 150, 160};
   auto root_ipv4_range_1_max = IPAddressBlocks::IPAddress<IPv4>{a};

   a = {10, 0, 0, 1};
   auto root_ipv4_range_2_min = IPAddressBlocks::IPAddress<IPv4>(a);
   a = {10, 255, 255, 255};
   auto root_ipv4_range_2_max = IPAddressBlocks::IPAddress<IPv4>(a);

   a = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   auto root_ipv6_range_1_min = IPAddressBlocks::IPAddress<IPv6>(a);
   a = {0xA0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
   auto root_ipv6_range_1_max = IPAddressBlocks::IPAddress<IPv6>(a);

   a = {0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   auto root_ipv6_range_2_min = IPAddressBlocks::IPAddress<IPv6>(a);
   a = {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
   auto root_ipv6_range_2_max = IPAddressBlocks::IPAddress<IPv6>(a);

   auto root_ipv4_range_1 = IPAddressBlocks::IPAddressOrRange<IPv4>(root_ipv4_range_1_min, root_ipv4_range_1_max);
   auto root_ipv4_range_2 = IPAddressBlocks::IPAddressOrRange<IPv4>(root_ipv4_range_2_min, root_ipv4_range_2_max);
   auto root_ipv6_range_1 = IPAddressBlocks::IPAddressOrRange<IPv6>(root_ipv6_range_1_min, root_ipv6_range_1_max);
   auto root_ipv6_range_2 = IPAddressBlocks::IPAddressOrRange<IPv6>(root_ipv6_range_2_min, root_ipv6_range_2_max);

   auto root_ipv4_ranges = {root_ipv4_range_1, root_ipv4_range_2};
   auto root_ipv6_ranges = {root_ipv6_range_1, root_ipv6_range_2};

   auto root_ipv4_choice = IPAddressBlocks::IPAddressChoice<IPv4>(root_ipv4_ranges);
   auto root_ipv6_choice = IPAddressBlocks::IPAddressChoice<IPv6>(root_ipv6_ranges);

   auto root_ipv4_family = IPAddressBlocks::IPAddressFamily(root_ipv4_choice, 42);
   auto root_ipv6_family = IPAddressBlocks::IPAddressFamily(root_ipv6_choice);

   auto root_addr_blocks = {root_ipv4_family, root_ipv6_family};
   std::unique_ptr<IPAddressBlocks> root_blocks = std::make_unique<IPAddressBlocks>(root_addr_blocks);

   // Inherit cert
   auto inherit_ipv4_choice = IPAddressBlocks::IPAddressChoice<IPv4>();
   auto inherit_ipv6_choice = IPAddressBlocks::IPAddressChoice<IPv6>();

   auto inherit_ipv4_family = IPAddressBlocks::IPAddressFamily(inherit_ipv4_choice, 42);
   auto inherit_ipv6_family = IPAddressBlocks::IPAddressFamily(inherit_ipv6_choice);

   auto inherit_addr_blocks = {inherit_ipv4_family, inherit_ipv6_family};
   std::unique_ptr<IPAddressBlocks> inherit_blocks = std::make_unique<IPAddressBlocks>(inherit_addr_blocks);

   // Dynamic Cert
   a = {122, 0, 0, 255};
   auto dyn_ipv4_range_1_min = IPAddressBlocks::IPAddress<IPv4>(a);
   a = {128, 255, 255, 255};
   auto dyn_ipv4_range_1_max = IPAddressBlocks::IPAddress<IPv4>(a);
   a = {10, 0, 0, 255};
   auto dyn_ipv4_range_2_min = IPAddressBlocks::IPAddress<IPv4>(a);
   a = {10, 255, 0, 1};
   auto dyn_ipv4_range_2_max = IPAddressBlocks::IPAddress<IPv4>(a);

   a = {0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
   auto dyn_ipv6_range_1_min = IPAddressBlocks::IPAddress<IPv6>(a);
   a = {0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   auto dyn_ipv6_range_1_max = IPAddressBlocks::IPAddress<IPv6>(a);

   auto dyn_ipv4_range_1 = IPAddressBlocks::IPAddressOrRange<IPv4>(dyn_ipv4_range_1_min, dyn_ipv4_range_1_max);
   auto dyn_ipv4_range_2 = IPAddressBlocks::IPAddressOrRange<IPv4>(dyn_ipv4_range_2_min, dyn_ipv4_range_2_max);
   auto dyn_ipv6_range = IPAddressBlocks::IPAddressOrRange<IPv6>(dyn_ipv6_range_1_min, dyn_ipv6_range_1_max);

   auto dyn_ipv4_ranges = {dyn_ipv4_range_1, dyn_ipv4_range_2};
   auto dyn_ipv6_ranges = {dyn_ipv6_range};

   // Subject cert
   a = {124, 0, 255, 0};
   auto sub_ipv4_range_1_min = IPAddressBlocks::IPAddress<IPv4>(a);
   a = {126, 0, 0, 1};
   auto sub_ipv4_range_1_max = IPAddressBlocks::IPAddress<IPv4>(a);

   a = {10, 0, 2, 1};
   auto sub_ipv4_range_2_min = IPAddressBlocks::IPAddress<IPv4>(a);
   a = {10, 42, 0, 255};
   auto sub_ipv4_range_2_max = IPAddressBlocks::IPAddress<IPv4>(a);

   a = {0x00, 0x00, 0x00, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   auto sub_ipv6_range_1_min = IPAddressBlocks::IPAddress<IPv6>(a);
   a = {0x0D, 0x00, 0x00, 0xAB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   auto sub_ipv6_range_1_max = IPAddressBlocks::IPAddress<IPv6>(a);

   auto sub_ipv4_range_1 = IPAddressBlocks::IPAddressOrRange<IPv4>(sub_ipv4_range_1_min, sub_ipv4_range_1_max);
   auto sub_ipv4_range_2 = IPAddressBlocks::IPAddressOrRange<IPv4>(sub_ipv4_range_2_min, sub_ipv4_range_2_max);
   auto sub_ipv6_range = IPAddressBlocks::IPAddressOrRange<IPv6>(sub_ipv6_range_1_min, sub_ipv6_range_1_max);

   auto sub_ipv4_ranges = {sub_ipv4_range_1, sub_ipv4_range_2};
   auto sub_ipv6_ranges = {sub_ipv6_range};

   auto sub_ipv4_choice = IPAddressBlocks::IPAddressChoice<IPv4>(sub_ipv4_ranges);
   auto sub_ipv6_choice = IPAddressBlocks::IPAddressChoice<IPv6>(sub_ipv6_ranges);

   auto sub_ipv4_family = IPAddressBlocks::IPAddressFamily(sub_ipv4_choice, 42);
   auto sub_ipv6_family = IPAddressBlocks::IPAddressFamily(sub_ipv6_choice);

   auto sub_addr_blocks = {sub_ipv4_family, sub_ipv6_family};
   std::unique_ptr<IPAddressBlocks> sub_blocks = std::make_unique<IPAddressBlocks>(sub_addr_blocks);

   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] =
      make_ca(*rng, ca_params().add_extension(std::move(root_blocks)));
   auto [inherit_cert, inherit_ca] = make_and_sign_ca(std::move(inherit_blocks), root_ca, *rng);

   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root_cert);

   for(size_t i = 0; i < 4; i++) {
      bool include_v4 = bit_set<0>(i);
      bool include_v6 = bit_set<1>(i);

      auto dyn_ipv4_choice =
         IPAddressBlocks::IPAddressChoice<IPv4>(include_v4 ? std::optional(dyn_ipv4_ranges) : std::nullopt);
      auto dyn_ipv6_choice =
         IPAddressBlocks::IPAddressChoice<IPv6>(include_v6 ? std::optional(dyn_ipv6_ranges) : std::nullopt);

      auto dyn_ipv4_family = IPAddressBlocks::IPAddressFamily(dyn_ipv4_choice, 42);
      auto dyn_ipv6_family = IPAddressBlocks::IPAddressFamily(dyn_ipv6_choice);

      auto dyn_addr_blocks = {dyn_ipv4_family, dyn_ipv6_family};
      std::unique_ptr<IPAddressBlocks> dyn_blocks = std::make_unique<IPAddressBlocks>(dyn_addr_blocks);

      auto [dyn_cert, dyn_ca] = make_and_sign_ca(std::move(dyn_blocks), inherit_ca, *rng);

      const auto sub_req = user_params().add_extension(sub_blocks->copy()).into_pkcs10_request(*sub_key, *rng, hash_fn);
      const auto sub_cert = dyn_ca.sign_request(sub_req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      const Botan::Path_Validation_Restrictions restrictions(false, 80);
      std::vector<Botan::X509_Certificate> certs = {sub_cert, dyn_cert, inherit_cert};

      Botan::Path_Validation_Result path_result = Botan::x509_path_validate(certs, restrictions, trusted);
      result.require("path validation succeeds", path_result.successful_validation());
   }

   result.end_timer();
   return result;
}

Test::Result test_x509_ip_addr_blocks_path_validation_failure_builder() {
   Test::Result result("X509 IP Address Blocks path validation failure (builder)");
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

      auto root_params = ca_params();
      if(!nullptr_extensions) {
         root_params.add_extension(std::move(root_blocks));
      }
      auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(*rng, root_params);

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

      auto [iss_cert, iss_ca] = make_and_sign_ca(std::move(iss_blocks), root_ca, *rng);

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

      auto sub_req = user_params().add_extension(std::move(sub_blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
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

Test::Result test_x509_ip_addr_blocks_path_validation_failure_ctor() {
   Test::Result result("X509 IP Address Block path validation failure (ctor)");
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
      std::vector<uint8_t> a = {120, 0, 0, 1};
      auto root_range_1_min = IPAddressBlocks::IPAddress<IPv4>{a};
      a = {130, 140, 150, 160};
      auto root_range_1_max = IPAddressBlocks::IPAddress<IPv4>{a};

      auto root_range_1 = IPAddressBlocks::IPAddressOrRange<IPv4>(root_range_1_min, root_range_1_max);
      auto root_ranges = {root_range_1};
      auto root_choice =
         IPAddressBlocks::IPAddressChoice<IPv4>(all_inherit ? std::nullopt : std::optional(root_ranges));
      auto root_family = IPAddressBlocks::IPAddressFamily(root_choice, 42);
      auto root_addr_blocks = {root_family};
      std::unique_ptr<IPAddressBlocks> root_blocks = std::make_unique<IPAddressBlocks>(root_addr_blocks);

      auto root_params = ca_params();
      if(!nullptr_extensions) {
         root_params.add_extension(std::move(root_blocks));
      }
      auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(*rng, root_params);

      // Issuer Cert
      a = {122, 0, 0, 255};
      auto iss_range_1_min = IPAddressBlocks::IPAddress<IPv4>(a);
      a = {128, 255, 255, 255};
      auto iss_range_1_max = IPAddressBlocks::IPAddress<IPv4>(a);
      auto iss_range_1 = IPAddressBlocks::IPAddressOrRange<IPv4>(iss_range_1_min, iss_range_1_max);

      std::vector<IPAddressBlocks::IPAddressOrRange<IPv4>> iss_ranges;

      if(!empty_issuer_ranges) {
         iss_ranges.push_back(iss_range_1);
      }

      auto iss_choice = IPAddressBlocks::IPAddressChoice<IPv4>(all_inherit ? std::nullopt : std::optional(iss_ranges));
      auto iss_family = IPAddressBlocks::IPAddressFamily(iss_choice, 42);
      auto iss_addr_blocks = {iss_family};
      std::unique_ptr<IPAddressBlocks> iss_blocks = std::make_unique<IPAddressBlocks>(iss_addr_blocks);
      auto [iss_cert, iss_ca] = make_and_sign_ca(std::move(iss_blocks), root_ca, *rng);

      // Subject cert
      if(too_small_subrange) {
         a = {118, 0, 255, 0};
      } else if(no_more_issuer_ranges) {
         a = {140, 0, 0, 1};
      } else {
         a = {124, 0, 255, 0};
      }

      auto sub_range_1_min = IPAddressBlocks::IPAddress<IPv4>(a);
      if(too_large_subrange) {
         a = {134, 0, 0, 1};
      } else if(no_more_issuer_ranges) {
         a = {150, 0, 0, 1};
      } else {
         a = {126, 0, 0, 1};
      }
      auto sub_range_1_max = IPAddressBlocks::IPAddress<IPv4>(a);

      auto sub_range_1 = IPAddressBlocks::IPAddressOrRange<IPv4>(sub_range_1_min, sub_range_1_max);
      auto sub_ranges = {sub_range_1};
      auto sub_choice = IPAddressBlocks::IPAddressChoice<IPv4>(all_inherit ? std::nullopt : std::optional(sub_ranges));
      auto sub_family = IPAddressBlocks::IPAddressFamily(sub_choice, different_safi ? 41 : 42);

      auto sub_addr_blocks = {sub_family};
      std::unique_ptr<IPAddressBlocks> sub_blocks = std::make_unique<IPAddressBlocks>(sub_addr_blocks);

      auto sub_req = user_params().add_extension(std::move(sub_blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
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

   auto cert = make_self_signed(*rng, ca_params().add_extension(std::move(blocks)));
   auto bits = cert.v3_extensions().get_extension_bits(ASBlocks::static_oid());

   result.test_eq(
      "extension is encoded as specified", bits, "301AA014301202020087300802020BB802020F9F02021389A1020500");

   auto as_idents = cert.v3_extensions().get_extension_object_as<ASBlocks>()->as_identifiers();
   auto as_ids = as_idents.asnum().value().ranges().value();

   result.confirm("extension has correct data", as_ids[0].min() == 135);

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_encode_builder() {
   Test::Result result("X509 IP Address Blocks encode (builder)");
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

   auto cert = make_self_signed(*rng, ca_params().add_extension(std::move(blocks)));
   auto bits = cert.v3_extensions().get_extension_bits(ASBlocks::static_oid());

   result.test_eq("extension is encoded as specified", bits, "3011A0023000A10B300930070201090202012D");

   result.end_timer();
   return result;
}

Test::Result test_x509_as_blocks_extension_encode_ctor() {
   Test::Result result("X509 AS Blocks encode (ctor)");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;

   auto rng = Test::new_rng(__func__);

   auto [ca_cert, ca, sub_key, sig_algo, hash_fn] = make_ca(*rng);

   for(size_t i = 0; i < 16; i++) {
      bool push_asnum = bit_set<0>(i);
      bool push_rdi = bit_set<1>(i);
      bool include_asnum = bit_set<2>(i);
      bool include_rdi = bit_set<3>(i);
      if(!include_asnum && !include_rdi) {
         continue;
      }

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

      auto req = user_params().add_extension(std::move(blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
      Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));

      {
         const auto* as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();
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

Test::Result test_x509_as_blocks_range_merge() {
   Test::Result result("X509 AS Block range merge");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;

   auto rng = Test::new_rng(__func__);

   auto [ca_cert, ca, sub_key, sig_algo, hash_fn] = make_ca(*rng);

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

   const auto req = user_params().add_extension(std::move(blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
   Botan::X509_Certificate cert = ca.sign_request(req, *rng, from_date(-1, 01, 01), from_date(2, 01, 01));
   {
      const auto* as_blocks = cert.v3_extensions().get_extension_object_as<ASBlocks>();
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

Test::Result test_x509_as_blocks_path_validation_success_builder() {
   Test::Result result("X509 AS Block path validation success (builder)");
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

   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] =
      make_ca(*rng, ca_params().add_extension(std::move(root_blocks)));
   auto [inherit_cert, inherit_ca] = make_and_sign_ca(std::move(inherit_blocks), root_ca, *rng);

   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root_cert);

   for(size_t i = 0; i < 4; i++) {
      bool include_asnum = bit_set<0>(i);
      bool include_rdi = bit_set<1>(i);

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

      auto [dyn_cert, dyn_ca] = make_and_sign_ca(std::move(dyn_blocks), inherit_ca, *rng);

      const auto sub_req = user_params().add_extension(sub_blocks->copy()).into_pkcs10_request(*sub_key, *rng, hash_fn);
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

Test::Result test_x509_as_blocks_path_validation_success_ctor() {
   Test::Result result("X509 AS Block path validation success (ctor)");
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
   ASBlocks::ASIdOrRange root_asnum_id_or_range0 = ASBlocks::ASIdOrRange(0, 999);
   ASBlocks::ASIdOrRange root_asnum_id_or_range1 = ASBlocks::ASIdOrRange(5042);
   ASBlocks::ASIdOrRange root_asnum_id_or_range2 = ASBlocks::ASIdOrRange(5043, 4294967295);

   ASBlocks::ASIdOrRange root_rdi_id_or_range0 = ASBlocks::ASIdOrRange(1234, 5678);
   ASBlocks::ASIdOrRange root_rdi_id_or_range1 = ASBlocks::ASIdOrRange(32768);
   ASBlocks::ASIdOrRange root_rdi_id_or_range2 = ASBlocks::ASIdOrRange(32769, 4294967295);

   std::vector<ASBlocks::ASIdOrRange> root_as_ranges;
   root_as_ranges.push_back(root_asnum_id_or_range0);
   root_as_ranges.push_back(root_asnum_id_or_range1);
   root_as_ranges.push_back(root_asnum_id_or_range2);

   std::vector<ASBlocks::ASIdOrRange> root_rdi_ranges;
   root_rdi_ranges.push_back(root_rdi_id_or_range0);
   root_rdi_ranges.push_back(root_rdi_id_or_range1);
   root_rdi_ranges.push_back(root_rdi_id_or_range2);

   ASBlocks::ASIdentifierChoice root_asnum = ASBlocks::ASIdentifierChoice(root_as_ranges);
   ASBlocks::ASIdentifierChoice root_rdi = ASBlocks::ASIdentifierChoice(root_rdi_ranges);
   ASBlocks::ASIdentifiers root_ident = ASBlocks::ASIdentifiers(root_asnum, root_rdi);
   std::unique_ptr<ASBlocks> root_blocks = std::make_unique<ASBlocks>(root_ident);

   // Inherit cert, both as 'inherit'
   ASBlocks::ASIdentifierChoice inherit_asnum = ASBlocks::ASIdentifierChoice();
   ASBlocks::ASIdentifierChoice inherit_rdi = ASBlocks::ASIdentifierChoice();
   ASBlocks::ASIdentifiers inherit_ident = ASBlocks::ASIdentifiers(inherit_asnum, inherit_rdi);
   std::unique_ptr<ASBlocks> inherit_blocks = std::make_unique<ASBlocks>(inherit_ident);

   // Dynamic cert
   ASBlocks::ASIdOrRange dyn_asnum_id_or_range0 = ASBlocks::ASIdOrRange(100, 600);
   ASBlocks::ASIdOrRange dyn_asnum_id_or_range1 = ASBlocks::ASIdOrRange(678);
   ASBlocks::ASIdOrRange dyn_asnum_id_or_range2 = ASBlocks::ASIdOrRange(5042, 5101);

   ASBlocks::ASIdOrRange dyn_rdi_id_or_range0 = ASBlocks::ASIdOrRange(1500, 5000);
   ASBlocks::ASIdOrRange dyn_rdi_id_or_range1 = ASBlocks::ASIdOrRange(33000, 60000);

   std::vector<ASBlocks::ASIdOrRange> dyn_as_ranges;
   dyn_as_ranges.push_back(dyn_asnum_id_or_range0);
   dyn_as_ranges.push_back(dyn_asnum_id_or_range1);
   dyn_as_ranges.push_back(dyn_asnum_id_or_range2);

   std::vector<ASBlocks::ASIdOrRange> dyn_rdi_ranges;
   dyn_rdi_ranges.push_back(dyn_rdi_id_or_range0);
   dyn_rdi_ranges.push_back(dyn_rdi_id_or_range1);

   // Subject cert
   ASBlocks::ASIdOrRange sub_asnum_id_or_range0 = ASBlocks::ASIdOrRange(120, 180);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range1 = ASBlocks::ASIdOrRange(220, 240);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range2 = ASBlocks::ASIdOrRange(260, 511);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range3 = ASBlocks::ASIdOrRange(678);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range4 = ASBlocks::ASIdOrRange(5043, 5100);

   ASBlocks::ASIdOrRange sub_rdi_id_or_range0 = ASBlocks::ASIdOrRange(1500, 2300);
   ASBlocks::ASIdOrRange sub_rdi_id_or_range1 = ASBlocks::ASIdOrRange(2500, 4000);
   ASBlocks::ASIdOrRange sub_rdi_id_or_range2 = ASBlocks::ASIdOrRange(1567);
   ASBlocks::ASIdOrRange sub_rdi_id_or_range3 = ASBlocks::ASIdOrRange(33100, 40000);

   std::vector<ASBlocks::ASIdOrRange> sub_as_ranges;
   sub_as_ranges.push_back(sub_asnum_id_or_range0);
   sub_as_ranges.push_back(sub_asnum_id_or_range1);
   sub_as_ranges.push_back(sub_asnum_id_or_range2);
   sub_as_ranges.push_back(sub_asnum_id_or_range3);
   sub_as_ranges.push_back(sub_asnum_id_or_range4);

   std::vector<ASBlocks::ASIdOrRange> sub_rdi_ranges;
   sub_rdi_ranges.push_back(sub_rdi_id_or_range0);
   sub_rdi_ranges.push_back(sub_rdi_id_or_range1);
   sub_rdi_ranges.push_back(sub_rdi_id_or_range2);
   sub_rdi_ranges.push_back(sub_rdi_id_or_range3);

   ASBlocks::ASIdentifierChoice sub_asnum = ASBlocks::ASIdentifierChoice(sub_as_ranges);
   ASBlocks::ASIdentifierChoice sub_rdi = ASBlocks::ASIdentifierChoice(sub_rdi_ranges);
   ASBlocks::ASIdentifiers sub_ident = ASBlocks::ASIdentifiers(sub_asnum, sub_rdi);
   std::unique_ptr<ASBlocks> sub_blocks = std::make_unique<ASBlocks>(sub_ident);

   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] =
      make_ca(*rng, ca_params().add_extension(std::move(root_blocks)));
   auto [inherit_cert, inherit_ca] = make_and_sign_ca(std::move(inherit_blocks), root_ca, *rng);

   Botan::Certificate_Store_In_Memory trusted;
   trusted.add_certificate(root_cert);

   for(size_t i = 0; i < 4; i++) {
      bool include_asnum = bit_set<0>(i);
      bool include_rdi = bit_set<1>(i);

      ASBlocks::ASIdentifierChoice dyn_asnum =
         ASBlocks::ASIdentifierChoice(include_asnum ? std::optional(dyn_as_ranges) : std::nullopt);
      ASBlocks::ASIdentifierChoice dyn_rdi =
         ASBlocks::ASIdentifierChoice(include_rdi ? std::optional(dyn_rdi_ranges) : std::nullopt);
      ASBlocks::ASIdentifiers dyn_ident = ASBlocks::ASIdentifiers(dyn_asnum, dyn_rdi);
      std::unique_ptr<ASBlocks> dyn_blocks = std::make_unique<ASBlocks>(dyn_ident);

      auto [dyn_cert, dyn_ca] = make_and_sign_ca(std::move(dyn_blocks), inherit_ca, *rng);

      const auto sub_req = user_params().add_extension(sub_blocks->copy()).into_pkcs10_request(*sub_key, *rng, hash_fn);
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

Test::Result test_x509_as_blocks_path_validation_extension_not_present_builder() {
   Test::Result result("X509 AS Block path validation extension not present (builder)");
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
   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(*rng, ca_params());
   auto sub_req = user_params().add_extension(std::move(sub_blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
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

Test::Result test_x509_as_blocks_path_validation_extension_not_present_ctor() {
   Test::Result result("X509 AS Block path validation extension not present (ctor)");
   result.start_timer();

   using Botan::Cert_Extension::ASBlocks;
   auto rng = Test::new_rng(__func__);

   // Subject cert
   ASBlocks::ASIdOrRange sub_asnum_id_or_range0 = ASBlocks::ASIdOrRange(120, 180);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range1 = ASBlocks::ASIdOrRange(220, 240);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range2 = ASBlocks::ASIdOrRange(260, 511);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range3 = ASBlocks::ASIdOrRange(678);
   ASBlocks::ASIdOrRange sub_asnum_id_or_range4 = ASBlocks::ASIdOrRange(5043, 5100);

   ASBlocks::ASIdOrRange sub_rdi_id_or_range0 = ASBlocks::ASIdOrRange(1500, 2300);
   ASBlocks::ASIdOrRange sub_rdi_id_or_range1 = ASBlocks::ASIdOrRange(2500, 4000);
   ASBlocks::ASIdOrRange sub_rdi_id_or_range2 = ASBlocks::ASIdOrRange(1567);
   ASBlocks::ASIdOrRange sub_rdi_id_or_range3 = ASBlocks::ASIdOrRange(33100, 40000);

   std::vector<ASBlocks::ASIdOrRange> sub_as_ranges;
   sub_as_ranges.push_back(sub_asnum_id_or_range0);
   sub_as_ranges.push_back(sub_asnum_id_or_range1);
   sub_as_ranges.push_back(sub_asnum_id_or_range2);
   sub_as_ranges.push_back(sub_asnum_id_or_range3);
   sub_as_ranges.push_back(sub_asnum_id_or_range4);

   std::vector<ASBlocks::ASIdOrRange> sub_rdi_ranges;
   sub_rdi_ranges.push_back(sub_rdi_id_or_range0);
   sub_rdi_ranges.push_back(sub_rdi_id_or_range1);
   sub_rdi_ranges.push_back(sub_rdi_id_or_range2);
   sub_rdi_ranges.push_back(sub_rdi_id_or_range3);

   ASBlocks::ASIdentifierChoice sub_asnum = ASBlocks::ASIdentifierChoice(sub_as_ranges);
   ASBlocks::ASIdentifierChoice sub_rdi = ASBlocks::ASIdentifierChoice(sub_rdi_ranges);
   ASBlocks::ASIdentifiers sub_ident = ASBlocks::ASIdentifiers(sub_asnum, sub_rdi);
   std::unique_ptr<ASBlocks> sub_blocks = std::make_unique<ASBlocks>(sub_ident);

   // create a root ca that does not have any extension
   auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] = make_ca(*rng, ca_params());
   const auto sub_req = user_params().add_extension(std::move(sub_blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
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

Test::Result test_x509_as_blocks_path_validation_failure_builder() {
   Test::Result result("X509 AS Block path validation failure (builder)");
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

      auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] =
         make_ca(*rng, ca_params().add_extension(std::move(root_blocks)));
      auto [issu_cert, issu_ca] = make_and_sign_ca(std::move(issu_blocks), root_ca, *rng);

      const auto sub_req =
         user_params().add_extension(std::move(sub_blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
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

Test::Result test_x509_as_blocks_path_validation_failure_ctor() {
   Test::Result result("X509 AS Block path validation failure (ctor)");
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
      std::vector<ASBlocks::ASIdOrRange> root_as_ranges;
      std::vector<ASBlocks::ASIdOrRange> root_rdi_ranges;

      // assign the root ranges
      if(push_asnum_min_edge_ranges || push_asnum_max_edge_ranges) {
         // 100-200 for 02,03,04
         root_as_ranges.push_back(ASBlocks::ASIdOrRange(100, 200));
      } else if(push_asnum_max_middle_ranges || push_asnum_min_middle_ranges) {
         // 10-20,30-40,50-60 for 08,09,10
         root_as_ranges.push_back(ASBlocks::ASIdOrRange(10, 20));
         root_as_ranges.push_back(ASBlocks::ASIdOrRange(30, 40));
         root_as_ranges.push_back(ASBlocks::ASIdOrRange(50, 60));
      } else if(push_asnum_max_split_ranges || push_asnum_min_split_ranges) {
         // 10-20,30-50,60-70 for 11,12,13
         root_as_ranges.push_back(ASBlocks::ASIdOrRange(10, 20));
         root_as_ranges.push_back(ASBlocks::ASIdOrRange(30, 50));
         root_as_ranges.push_back(ASBlocks::ASIdOrRange(60, 70));
      }

      // same values but for rdis
      if(push_rdi_min_edge_ranges || push_rdi_max_edge_ranges) {
         root_rdi_ranges.push_back(ASBlocks::ASIdOrRange(100, 200));
      } else if(push_rdi_max_middle_ranges || push_rdi_min_middle_ranges) {
         root_rdi_ranges.push_back(ASBlocks::ASIdOrRange(10, 20));
         root_rdi_ranges.push_back(ASBlocks::ASIdOrRange(30, 40));
         root_rdi_ranges.push_back(ASBlocks::ASIdOrRange(50, 60));
      } else if(push_rdi_max_split_ranges || push_rdi_min_split_ranges) {
         root_rdi_ranges.push_back(ASBlocks::ASIdOrRange(10, 20));
         root_rdi_ranges.push_back(ASBlocks::ASIdOrRange(30, 50));
         root_rdi_ranges.push_back(ASBlocks::ASIdOrRange(60, 70));
      }

      // Issuer cert
      // the issuer cert has the same ranges as the root cert
      // it is used to check that the 'inherit' check is bubbled up until the root cert is hit
      std::vector<ASBlocks::ASIdOrRange> issu_as_ranges;
      std::vector<ASBlocks::ASIdOrRange> issu_rdi_ranges;

      // Subject cert
      std::vector<ASBlocks::ASIdOrRange> sub_as_ranges;
      std::vector<ASBlocks::ASIdOrRange> sub_rdi_ranges;

      // assign the subject asnum ranges
      if(push_asnum_min_edge_ranges) {
         // 99-200 for 02 (so overlapping to the left)
         sub_as_ranges.push_back(ASBlocks::ASIdOrRange(99, 200));
      } else if(push_asnum_max_edge_ranges) {
         // 100-201 for 03 (so overlapping to the right)
         sub_as_ranges.push_back(ASBlocks::ASIdOrRange(100, 201));
      } else if(push_asnum_max_middle_ranges) {
         // just change the range in the middle to overlap to the right for 08
         sub_as_ranges = root_as_ranges;
         sub_as_ranges[1] = ASBlocks::ASIdOrRange(30, 41);
      } else if(push_asnum_max_split_ranges) {
         // change the range in the middle to be cut at 45 for case 11
         // the left range is 30-44
         // the right range is 46-51 (overlapping the issuer range to the right)
         sub_as_ranges = root_as_ranges;
         sub_as_ranges[1] = ASBlocks::ASIdOrRange(30, 44);
         // pushing the new range created by splitting to the back since they will be sorted anyway
         sub_as_ranges.push_back(ASBlocks::ASIdOrRange(46, 51));
      } else if(push_asnum_min_middle_ranges) {
         // just change the test in the middle to overlap to the left for case 14
         sub_as_ranges = root_as_ranges;
         sub_as_ranges[1] = ASBlocks::ASIdOrRange(29, 40);
      } else if(push_asnum_min_split_ranges) {
         // again split the range in the middle at 45 for case 17
         // creating two ranges 29-44 and 46-50 (so overlapping to the left)
         sub_as_ranges = root_as_ranges;
         sub_as_ranges[1] = ASBlocks::ASIdOrRange(29, 44);
         sub_as_ranges.push_back(ASBlocks::ASIdOrRange(46, 50));
      } else if(empty_issuer_non_empty_subject) {
         sub_as_ranges.push_back(ASBlocks::ASIdOrRange(50));
      }

      // same values but for rdis
      if(push_rdi_min_edge_ranges) {
         sub_rdi_ranges.push_back(ASBlocks::ASIdOrRange(99, 200));
      } else if(push_rdi_max_edge_ranges) {
         sub_rdi_ranges.push_back(ASBlocks::ASIdOrRange(100, 201));
      } else if(push_rdi_max_middle_ranges) {
         sub_rdi_ranges = root_rdi_ranges;
         sub_rdi_ranges[1] = ASBlocks::ASIdOrRange(30, 41);
      } else if(push_rdi_max_split_ranges) {
         sub_rdi_ranges = root_rdi_ranges;
         sub_rdi_ranges[1] = ASBlocks::ASIdOrRange(30, 44);
         sub_rdi_ranges.push_back(ASBlocks::ASIdOrRange(46, 51));
      } else if(push_rdi_min_middle_ranges) {
         sub_rdi_ranges = root_rdi_ranges;
         sub_rdi_ranges[1] = ASBlocks::ASIdOrRange(29, 40);
      } else if(push_rdi_min_split_ranges) {
         sub_rdi_ranges = root_rdi_ranges;
         sub_rdi_ranges[1] = ASBlocks::ASIdOrRange(29, 44);
         sub_rdi_ranges.push_back(ASBlocks::ASIdOrRange(46, 50));
      }

      // for cases 00 and 01, set all certs to inherit (so std::nullopt)
      // in all other cases use the ranges created beforehand
      ASBlocks::ASIdentifierChoice root_asnum =
         ASBlocks::ASIdentifierChoice(inherit_all_asnums ? std::nullopt : std::optional(root_as_ranges));
      ASBlocks::ASIdentifierChoice root_rdi =
         ASBlocks::ASIdentifierChoice(inherit_all_rdis ? std::nullopt : std::optional(root_rdi_ranges));
      ASBlocks::ASIdentifiers root_ident = ASBlocks::ASIdentifiers(root_asnum, root_rdi);
      std::unique_ptr<ASBlocks> root_blocks = std::make_unique<ASBlocks>(root_ident);

      ASBlocks::ASIdentifiers issu_ident = root_ident;
      std::unique_ptr<ASBlocks> issu_blocks = std::make_unique<ASBlocks>(issu_ident);

      ASBlocks::ASIdentifierChoice sub_asnum =
         ASBlocks::ASIdentifierChoice(inherit_all_asnums ? std::nullopt : std::optional(sub_as_ranges));
      ASBlocks::ASIdentifierChoice sub_rdi =
         ASBlocks::ASIdentifierChoice(inherit_all_rdis ? std::nullopt : std::optional(sub_rdi_ranges));
      ASBlocks::ASIdentifiers sub_ident = ASBlocks::ASIdentifiers(sub_asnum, sub_rdi);
      std::unique_ptr<ASBlocks> sub_blocks = std::make_unique<ASBlocks>(sub_ident);

      auto [root_cert, root_ca, sub_key, sig_algo, hash_fn] =
         make_ca(*rng, ca_params().add_extension(std::move(root_blocks)));
      auto [issu_cert, issu_ca] = make_and_sign_ca(std::move(issu_blocks), root_ca, *rng);

      const auto sub_req =
         user_params().add_extension(std::move(sub_blocks)).into_pkcs10_request(*sub_key, *rng, hash_fn);
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
         results.push_back(test_x509_ip_addr_blocks_encode_builder());
         results.push_back(test_x509_ip_addr_blocks_extension_encode_ctor());
         results.push_back(test_x509_ip_addr_blocks_extension_encode_edge_cases_ctor());
         results.push_back(test_x509_ip_addr_blocks_range_merge());
         results.push_back(test_x509_ip_addr_blocks_family_merge());
         results.push_back(test_x509_ip_addr_blocks_path_validation_success_builder());
         results.push_back(test_x509_ip_addr_blocks_path_validation_success_ctor());
         results.push_back(test_x509_ip_addr_blocks_path_validation_failure_builder());
         results.push_back(test_x509_ip_addr_blocks_path_validation_failure_ctor());
         results.push_back(test_x509_as_blocks_rfc3779_example());
         results.push_back(test_x509_as_blocks_encode_builder());
         results.push_back(test_x509_as_blocks_extension_encode_ctor());
         results.push_back(test_x509_as_blocks_range_merge());
         results.push_back(test_x509_as_blocks_path_validation_success_builder());
         results.push_back(test_x509_as_blocks_path_validation_success_ctor());
         results.push_back(test_x509_as_blocks_path_validation_extension_not_present_builder());
         results.push_back(test_x509_as_blocks_path_validation_extension_not_present_ctor());
         results.push_back(test_x509_as_blocks_path_validation_failure_builder());
         results.push_back(test_x509_as_blocks_path_validation_failure_ctor());
         return results;
      }
};

BOTAN_REGISTER_TEST("x509", "x509_rpki", X509_RPKI_Tests);

#endif

}  // namespace

}  // namespace Botan_Tests
