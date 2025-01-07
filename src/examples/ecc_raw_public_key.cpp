#include <botan/ecdsa.h>
#include <botan/hex.h>
#include <botan/x509_key.h>

#include <iostream>
#include <span>
#include <string>
#include <vector>

namespace {

std::vector<uint8_t> to_uncompress_point_encoding(std::span<const uint8_t> x, std::span<const uint8_t> y) {
   std::vector<uint8_t> public_key_bytes;
   public_key_bytes.reserve(x.size() + y.size() + 1);
   public_key_bytes.push_back(0x04);  // means: uncompressed point encoding
   public_key_bytes.insert(public_key_bytes.end(), x.begin(), x.end());
   public_key_bytes.insert(public_key_bytes.end(), y.begin(), y.end());
   return public_key_bytes;
}

}  // namespace

int main() {
   const std::string curve_name = "secp256r1";
   const auto public_x_bytes = Botan::hex_decode("278309D4A88ADF89CA0E5328D3B655CF8949F2D9F9B2308AA22FE28202A315EC");
   const auto public_y_bytes = Botan::hex_decode("AC457F18D1F3675D46E98ED2E509EE47AC2CB9A012F73263B30CD7248AEA6020");

   const auto domain = Botan::EC_Group::from_name(curve_name);
   const auto encoded_public_point = to_uncompress_point_encoding(public_x_bytes, public_y_bytes);

   // This loads the public point into an ECDSA_PublicKey. Creating an
   // ECDH_PublicKey would work the same way.

   const auto public_key = Botan::ECDSA_PublicKey(domain, Botan::EC_AffinePoint(domain, encoded_public_point));

   std::cout << "Public Key (PEM):\n\n" << Botan::X509::PEM_encode(public_key) << '\n';
}
