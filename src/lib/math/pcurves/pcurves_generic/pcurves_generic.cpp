/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pcurves_generic.h>

#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/internal/pcurves_instance.h>
#include <botan/internal/primality.h>

namespace Botan::PCurve {

GenericPrimeOrderCurve::GenericPrimeOrderCurve(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) {
   throw Not_Implemented(__func__);
}

size_t GenericPrimeOrderCurve::order_bits() const {
   throw Not_Implemented(__func__);
}

size_t GenericPrimeOrderCurve::scalar_bytes() const {
   throw Not_Implemented(__func__);
}

size_t GenericPrimeOrderCurve::field_element_bytes() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul_by_g(const Scalar& scalar,
                                                                  RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(scalar, rng);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::mul(const AffinePoint& pt,
                                                             const Scalar& scalar,
                                                             RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(pt, scalar, rng);
   throw Not_Implemented(__func__);
}

std::unique_ptr<const PrimeOrderCurve::PrecomputedMul2Table> GenericPrimeOrderCurve::mul2_setup(
   const AffinePoint& x, const AffinePoint& y) const {
   BOTAN_UNUSED(x, y);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul2_vartime(const PrecomputedMul2Table& tableb,
                                                                                     const Scalar& s1,
                                                                                     const Scalar& s2) const {
   BOTAN_UNUSED(tableb, s1, s2);
   throw Not_Implemented(__func__);
};

std::optional<PrimeOrderCurve::ProjectivePoint> GenericPrimeOrderCurve::mul_px_qy(
   const AffinePoint& p, const Scalar& x, const AffinePoint& q, const Scalar& y, RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(p, x, q, y, rng);
   throw Not_Implemented(__func__);
};

bool GenericPrimeOrderCurve::mul2_vartime_x_mod_order_eq(const PrecomputedMul2Table& tableb,
                                                         const Scalar& v,
                                                         const Scalar& s1,
                                                         const Scalar& s2) const {
   BOTAN_UNUSED(tableb, v, s1, s2);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::base_point_mul_x_mod_order(const Scalar& scalar,
                                                                           RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(scalar, rng);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::generator() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_to_affine(const ProjectivePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_to_projective(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_double(const ProjectivePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_add(const ProjectivePoint& a,
                                                                   const ProjectivePoint& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::point_add_mixed(const ProjectivePoint& a,
                                                                         const AffinePoint& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::point_negate(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

bool GenericPrimeOrderCurve::affine_point_is_identity(const AffinePoint& pt) const {
   BOTAN_UNUSED(pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point_compressed(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_point_x(std::span<uint8_t> bytes, const AffinePoint& pt) const {
   BOTAN_UNUSED(bytes, pt);
   throw Not_Implemented(__func__);
}

void GenericPrimeOrderCurve::serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const {
   BOTAN_UNUSED(bytes, scalar);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::deserialize_scalar(
   std::span<const uint8_t> bytes) const {
   BOTAN_UNUSED(bytes);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::Scalar> GenericPrimeOrderCurve::scalar_from_wide_bytes(
   std::span<const uint8_t> bytes) const {
   BOTAN_UNUSED(bytes);
   throw Not_Implemented(__func__);
}

std::optional<PrimeOrderCurve::AffinePoint> GenericPrimeOrderCurve::deserialize_point(
   std::span<const uint8_t> bytes) const {
   BOTAN_UNUSED(bytes);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::AffinePoint GenericPrimeOrderCurve::hash_to_curve_nu(std::string_view hash,
                                                                      std::span<const uint8_t> input,
                                                                      std::span<const uint8_t> domain_sep) const {
   BOTAN_UNUSED(hash, input, domain_sep);
   throw Not_Implemented("Hash to curve is not implemented for this curve");
}

PrimeOrderCurve::ProjectivePoint GenericPrimeOrderCurve::hash_to_curve_ro(std::string_view hash,
                                                                          std::span<const uint8_t> input,
                                                                          std::span<const uint8_t> domain_sep) const {
   BOTAN_UNUSED(hash, input, domain_sep);
   throw Not_Implemented("Hash to curve is not implemented for this curve");
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_add(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_sub(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_mul(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_square(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_invert(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_negate(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

bool GenericPrimeOrderCurve::scalar_is_zero(const Scalar& s) const {
   BOTAN_UNUSED(s);
   throw Not_Implemented(__func__);
}

bool GenericPrimeOrderCurve::scalar_equal(const Scalar& a, const Scalar& b) const {
   BOTAN_UNUSED(a, b);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_zero() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_one() const {
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::scalar_from_u32(uint32_t x) const {
   BOTAN_UNUSED(x);
   throw Not_Implemented(__func__);
}

PrimeOrderCurve::Scalar GenericPrimeOrderCurve::random_scalar(RandomNumberGenerator& rng) const {
   BOTAN_UNUSED(rng);
   throw Not_Implemented(__func__);
}

std::shared_ptr<const PrimeOrderCurve> PCurveInstance::from_params(
   const BigInt& p, const BigInt& a, const BigInt& b, const BigInt& base_x, const BigInt& base_y, const BigInt& order) {
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(p), "p is not prime");
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(order), "order is not prime");
   BOTAN_ARG_CHECK(a >= 0 && a < p, "a is invalid");
   BOTAN_ARG_CHECK(b > 0 && b < p, "b is invalid");
   BOTAN_ARG_CHECK(base_x >= 0 && base_x < p, "base_x is invalid");
   BOTAN_ARG_CHECK(base_y >= 0 && base_y < p, "base_y is invalid");

   const size_t p_bits = p.bits();

   // Same size restriction as EC_Group:
   // Must be either exactly P-512 or else in 128..512 bits multiple of 32
   if(p_bits == 512) {
      if(p != BigInt::power_of_2(521) - 1) {
         return {};
      }
   } else if(p_bits < 128 || p_bits > 512 || p_bits % 32 != 0) {
      return {};
   }

   // We don't want to deal with Shanks-Tonelli in the generic case
   if(p % 4 != 3) {
      return {};
   }

   // The bit length of the field and order being the same simplifies things
   if(p_bits != order.bits()) {
      return {};
   }

   return std::make_shared<GenericPrimeOrderCurve>(p, a, b, base_x, base_y, order);
}

}  // namespace Botan::PCurve
