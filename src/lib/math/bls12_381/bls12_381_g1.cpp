/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bls12_381.h>

#include <botan/internal/ct_utils.h>
#include <botan/internal/mp_core.h>

namespace Botan::BLS12_381 {

namespace {

// Standard generator coordinates, pre-converted into Montgomery form
const auto G1_X = FieldElement::_unchecked_from_words(hex_to_words<word>(
                                                         "120177419e0bfb75edce6ecc21dbf440f0ae6acdf3d0e747154f95c7143ba1c17817fc679976fff55cb38790fd530c16"));

const auto G1_Y = FieldElement::_unchecked_from_words(hex_to_words<word>(
                                                         "0bbc3efc5008a26a0e1c8c3fad0059c051ac582950405194dd595f13570725ce8c22631a7918fd8ebaac93d50ce72271"));

inline FieldElement mul_by_3b(const FieldElement& fe) {
   // b == 4 so 3*b == 12
   const auto fe2 = fe + fe;
   const auto fe3 = fe2 + fe;
   return (fe3 + fe3);
}

}  // namespace

//static
G1Affine G1Affine::generator() {
   return G1Affine(G1_X, G1_Y, 0);
}

bool G1Affine::is_identity() const {
   return m_infinity != 0;
}

//static
std::optional<G1Affine> G1Affine::deserialize(std::span<const uint8_t> bytes) {
   throw Not_Implemented(__func__);
}

std::array<uint8_t, G1Affine::BYTES> G1Affine::serialize() const {
   auto bytes = m_x.serialize();

   // Set the compressed point indicator bit
   bytes[0] |= 0x80;

   const bool identity = this->is_identity();

   // If the identity element, set the identity bit
   bytes[0] |= (identity ? 0x40 : 0x00);

   // If y is the larger choice *and* not the point at identity, set the large-y bit
   const bool large_y = m_y._is_lexicographically_largest();
   bytes[0] |= (!identity && large_y) ? 0x20 : 0x00;

   return bytes;
}

//static
G1Projective G1Projective::generator() {
   return G1Projective(G1_X, G1_Y, FieldElement::one());
}

G1Affine G1Projective::to_affine() const {
   const auto zinv = m_z.invert();
   const auto inf = m_z.is_zero();
   return G1Affine(m_x * zinv, m_y * zinv, inf);
}

G1Projective G1Projective::negate() const {
   return G1Projective(m_x, m_y.negate(), m_z);
}

bool G1Projective::is_identity() const {
   return m_z.is_zero();
}

G1Projective G1Projective::dbl() const {
   // Algorithm 9, https://eprint.iacr.org/2015/1060.pdf

   auto t0 = m_y.square();
   auto z3 = t0 + t0;
   z3 = z3 + z3;
   z3 = z3 + z3;
   auto t1 = m_y * m_z;
   auto t2 = m_z.square();
   t2 = mul_by_3b(t2);
   auto x3 = t2 * z3;
   auto y3 = t0 + t2;
   z3 = t1 * z3;
   t1 = t2 + t2;
   t2 = t1 + t2;
   t0 = t0 - t2;
   y3 = t0 * y3;
   y3 = x3 + y3;
   t1 = m_x * m_y;
   x3 = t0 * t1;
   x3 = x3 + x3;

   return G1Projective(x3, y3, z3);
}

G1Projective G1Projective::add(const G1Projective& other) const {
   // Algorithm 7, https://eprint.iacr.org/2015/1060.pdf

   auto t0 = m_x * other.m_x;
   auto t1 = m_y * other.m_y;
   auto t2 = m_z * other.m_z;
   auto t3 = m_x + m_y;
   auto t4 = other.m_x + other.m_y;
   t3 = t3 * t4;
   t4 = t0 + t1;
   t3 = t3 - t4;
   t4 = m_y + m_z;
   auto x3 = other.m_y + other.m_z;
   t4 = t4 * x3;
   x3 = t1 + t2;
   t4 = t4 - x3;
   x3 = m_x + m_z;
   auto y3 = other.m_x + other.m_z;
   x3 = x3 * y3;
   y3 = t0 + t2;
   y3 = x3 - y3;
   x3 = t0 + t0;
   t0 = x3 + t0;
   t2 = mul_by_3b(t2);
   auto z3 = t1 + t2;
   t1 = t1 - t2;
   y3 = mul_by_3b(y3);
   x3 = t4 * y3;
   t2 = t3 * t1;
   x3 = t2 - x3;
   y3 = y3 * t0;
   t1 = t1 * z3;
   y3 = t1 + y3;
   t0 = t0 * t3;
   z3 = z3 * t4;
   z3 = z3 + t0;

   return G1Projective(x3, y3, z3);
}

G1Projective G1Projective::add_mixed(const G1Affine& other) const {
   // Algorithm 8, https://eprint.iacr.org/2015/1060.pdf

   auto t0 = m_x * other.m_x;
   auto t1 = m_y * other.m_y;
   auto t3 = other.m_x + other.m_y;
   auto t4 = m_x + m_y;
   t3 = t3 * t4;
   t4 = t0 + t1;
   t3 = t3 - t4;
   t4 = other.m_y * m_z;
   t4 = t4 + m_y;
   auto y3 = other.m_x * m_z;
   y3 = y3 + m_x;
   auto x3 = t0 + t0;
   t0 = x3 + t0;
   auto t2 = mul_by_3b(m_z);
   auto z3 = t1 + t2;
   t1 = t1 - t2;
   y3 = mul_by_3b(y3);
   x3 = t4 * y3;
   t2 = t3 * t1;
   x3 = t2 - x3;
   y3 = y3 * t0;
   t1 = t1 * z3;
   y3 = t1 + y3;
   t0 = t0 * t3;
   z3 = z3 * t4;
   z3 = z3 + t0;

   return G1Projective(x3, y3, z3);
}

G1Projective G1Projective::mul(const Scalar& scalar) const {
   //const auto sbytes = scalar.serialize();

   auto accum = G1Projective::identity();

   return accum;
}

/*
std::vector<G1Affine> G1Projective::batch_to_affine(std::span<const G1Projective> points) {

}
*/

}  // namespace Botan::BLS12_381
