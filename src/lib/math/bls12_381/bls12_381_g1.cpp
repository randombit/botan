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
   throw Not_Implemented(__func__);
}

//static
G1Projective G1Projective::generator() {
   return G1Projective(G1_X, G1_Y, FieldElement::one(), 0);
}

G1Affine G1Projective::to_affine() const {
   throw Not_Implemented(__func__);
}

G1Projective G1Projective::negate() const {
   return G1Projective(m_x, m_y.negate(), m_z, m_infinity);
}

G1Projective G1Projective::dbl() const {
   throw Not_Implemented(__func__);
}

G1Projective G1Projective::add(const G1Projective& other) const {
   throw Not_Implemented(__func__);
}

G1Projective G1Projective::add_mixed(const G1Affine& other) const {
   // FIXME
   return this->add(G1Projective::from_affine(other));
}

G1Projective G1Projective::mul(const Scalar& scalar) const {
   throw Not_Implemented(__func__);
}

}  // namespace Botan::BLS12_381
