#include <botan/bigint.h>
#include <botan/ecdh.h>
#include <botan/hex.h>
#include <botan/pkcs8.h>
#include <botan/rng.h>
#include <botan/x509_key.h>

#include <iostream>
#include <string>

int main() {
   const std::string curve_name = "secp256r1";
   const auto private_scalar_bytes =
      Botan::hex_decode("D2AC61C35CAEE918E47B0BD5E61DA9B3A5C2964AB317647DEF6DFC042A06C829");

   Botan::Null_RNG null_rng;
   const auto domain = Botan::EC_Group::from_name(curve_name);
   const auto private_scalar = Botan::BigInt(private_scalar_bytes);

   // This loads the private scalar into an ECDH_PrivateKey. Creating an
   // ECDSA_PrivateKey would work the same way.
   const auto private_key = Botan::ECDH_PrivateKey(null_rng, domain, private_scalar);
   const auto public_key = private_key.public_key();

   std::cout << "Private Key (PEM):\n\n" << Botan::PKCS8::PEM_encode(private_key) << '\n';
   std::cout << "Public Key (PEM):\n\n" << Botan::X509::PEM_encode(*public_key) << '\n';
}
