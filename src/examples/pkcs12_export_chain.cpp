#include <botan/asn1_time.h>
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pkcs10.h>
#include <botan/pkcs12.h>
#include <botan/x509_builder.h>
#include <botan/x509_ca.h>

#include <iostream>
#include <memory>

int main() {
   Botan::AutoSeeded_RNG rng;
   const auto group = Botan::EC_Group::from_name("secp256r1");

   // Issuing CA.
   const Botan::ECDSA_PrivateKey ca_key(rng, group);

   constexpr uint64_t seconds_in_a_year = 31556926;
   auto not_before = Botan::ASN1_Time::current_time();
   auto not_after = Botan::ASN1_Time::from_seconds_since_epoch(not_before.time_since_epoch() + seconds_in_a_year);

   auto ca_metadata = Botan::CertificateParametersBuilder();
   ca_metadata.add_common_name("Example CA").set_as_ca_certificate();
   const auto ca_cert = ca_metadata.into_self_signed_cert(not_before, not_after, ca_key, rng);

   // End-entity, signed by the CA.
   auto ee_key = std::make_shared<Botan::ECDSA_PrivateKey>(rng, group);

   auto ee_metadata = Botan::CertificateParametersBuilder();
   ee_metadata.add_dns("example.com");
   const auto csr = ee_metadata.into_pkcs10_request(*ee_key, rng);

   const Botan::X509_CA ca(ca_cert, ca_key, "SHA-256", rng);
   const auto ee_cert = ca.sign_request(csr, rng, Botan::X509_Time("200101000000Z"), Botan::X509_Time("300101000000Z"));

   // Bundle: end-entity key + cert + issuing CA in the chain.
   Botan::PKCS12 bundle;
   bundle.add_key(ee_key);
   bundle.add_certificate(ee_cert);
   bundle.add_certificate(ca_cert);

   const auto pfx = bundle.export_to(Botan::PKCS12_Export_Options::modern("secret", "Server Key"), rng);

   std::cout << Botan::hex_encode(pfx) << '\n';
   return 0;
}
