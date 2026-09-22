#include <botan/asn1_time.h>
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pkcs12.h>
#include <botan/x509_builder.h>

#include <iostream>
#include <memory>

int main() {
   Botan::AutoSeeded_RNG rng;

   // Generate an ECDSA private key + self-signed certificate to bundle.
   auto key = std::make_shared<Botan::ECDSA_PrivateKey>(rng, Botan::EC_Group::from_name("secp256r1"));

   constexpr uint64_t seconds_in_a_year = 31556926;
   auto not_before = Botan::ASN1_Time::current_time();
   auto not_after = Botan::ASN1_Time::from_seconds_since_epoch(not_before.time_since_epoch() + seconds_in_a_year);

   auto metadata = Botan::CertificateParametersBuilder();
   metadata.add_uri("https://example.com");
   const auto cert = metadata.into_self_signed_cert(not_before, not_after, *key, rng);

   // Populate the PKCS#12 bundle.
   Botan::PKCS12 bundle;
   bundle.add_key(key);
   bundle.add_certificate(cert);
   bundle.set_friendly_name("My Key");

   // Export with modern defaults (PBES2-SHA256-AES256, SHA-256 MAC,
   // 100 000 iterations). For maximum interoperability with legacy software
   // use Botan::PKCS12_Export_Options::legacy_compat("secret") instead.
   const auto pfx = bundle.export_to(Botan::PKCS12_Export_Options::modern("secret"), rng);

   std::cout << Botan::hex_encode(pfx) << '\n';
   return 0;
}
