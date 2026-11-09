#include <botan/bigint.h>
#include <botan/ec_apoint.h>
#include <botan/ec_group.h>
#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/x509_key.h>

#include <iostream>
#include <string>

int main() {
   const std::string curve_name = "secp256r1";
   const auto public_x_bytes = Botan::hex_decode("278309D4A88ADF89CA0E5328D3B655CF8949F2D9F9B2308AA22FE28202A315EC");
   const auto public_y_bytes = Botan::hex_decode("AC457F18D1F3675D46E98ED2E509EE47AC2CB9A012F73263B30CD7248AEA6020");

   const auto domain = Botan::EC_Group::from_name(curve_name);

   // This function will return nullopt if either coordinate is not in the
   // valid range for the group, or if (x,y) is not a point on the curve.
   const auto public_point = Botan::EC_AffinePoint::from_bigint_xy(
      domain, Botan::BigInt::from_bytes(public_x_bytes), Botan::BigInt::from_bytes(public_y_bytes));

   if(!public_point) {
      std::cerr << "Public key is invalid\n";
      return 1;
   }

   // This loads the public point into an ECDSA_PublicKey. Creating an
   // ECDH_PublicKey would work the same way.
   const auto public_key = Botan::ECDSA_PublicKey(domain, public_point.value());

   std::cout << "Public Key (PEM):\n\n" << Botan::X509::PEM_encode(public_key) << '\n';
   return 0;
}
