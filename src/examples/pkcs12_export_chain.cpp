#include <botan/asn1_time.h>
#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/pkcs10.h>
#include <botan/pkcs12.h>
#include <botan/x509_ca.h>
#include <botan/x509self.h>

#include <iostream>
#include <memory>
#include <vector>

int main() {
   Botan::AutoSeeded_RNG rng;
   const auto group = Botan::EC_Group::from_name("secp256r1");

   // Issuing CA.
   const Botan::ECDSA_PrivateKey ca_key(rng, group);
   Botan::X509_Cert_Options ca_opts("CN=Example CA");
   ca_opts.CA_key();
   const auto ca_cert = Botan::X509::create_self_signed_cert(ca_opts, ca_key, "SHA-256", rng);

   // End-entity, signed by the CA.
   auto ee_key = std::make_shared<Botan::ECDSA_PrivateKey>(rng, group);
   Botan::X509_Cert_Options ee_opts("CN=example.com");
   ee_opts.dns = "example.com";
   const auto csr = Botan::X509::create_cert_req(ee_opts, *ee_key, "SHA-256", rng);
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
