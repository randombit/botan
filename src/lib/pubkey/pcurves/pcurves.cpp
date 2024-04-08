/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves.h>

#include <botan/internal/pcurves_impl.h>

namespace Botan::PCurve {

// clang-format off
typedef EllipticCurve<
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
   "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
   "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
   "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
   "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
   "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
   -10>
   P256;

typedef EllipticCurve<
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
   "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
   "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
   "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
   "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
   -12>
   P384;

typedef EllipticCurve<
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
   "51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
   "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
   "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
   "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
   -4>
   P521;

// clang-format on

std::vector<uint8_t> hash_to_curve(PrimeOrderCurveId curve,
                                   std::string_view hash,
                                   bool random_oracle,
                                   std::span<const uint8_t> input,
                                   std::span<const uint8_t> domain_sep) {
   switch(curve.code()) {
      case PrimeOrderCurveId::secp256r1:
         return hash_to_curve_sswu<P256>(hash, random_oracle, input, domain_sep);
      case PrimeOrderCurveId::secp384r1:
         return hash_to_curve_sswu<P384>(hash, random_oracle, input, domain_sep);
      case PrimeOrderCurveId::secp521r1:
         return hash_to_curve_sswu<P521>(hash, random_oracle, input, domain_sep);

      default:
         throw Not_Implemented("Hash to curve not implemented for this curve");
   }
}

std::vector<uint8_t> mul_by_g(PrimeOrderCurveId curve, std::span<const uint8_t> scalar_bytes) {
   switch(curve.code()) {
      case PrimeOrderCurveId::secp256r1:
         if(auto scalar = P256::Scalar::deserialize(scalar_bytes)) {
            return P256::MulByG(*scalar).to_affine().serialize_to_vec();
         } else {
            throw Invalid_Argument("Invalid scalar");
         }
      case PrimeOrderCurveId::secp384r1:
         if(auto scalar = P384::Scalar::deserialize(scalar_bytes)) {
            return P384::MulByG(*scalar).to_affine().serialize_to_vec();
         } else {
            throw Invalid_Argument("Invalid scalar");
         }
      case PrimeOrderCurveId::secp521r1:
         if(auto scalar = P521::Scalar::deserialize(scalar_bytes)) {
            return P521::MulByG(*scalar).to_affine().serialize_to_vec();
         } else {
            throw Invalid_Argument("Invalid scalar");
         }
      default:
         throw Not_Implemented("Point mul not implemented for this curve");
   }
}

}  // namespace Botan::PCurve
