/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_WRAP_H_
#define BOTAN_PCURVES_WRAP_H_

#include <botan/exceptn.h>
#include <botan/internal/pcurves.h>
#include <botan/internal/pcurves_impl.h>

namespace Botan::PCurve {

template <typename C>
concept curve_supports_scalar_invert = requires(const typename C::Scalar& s) {
   { C::scalar_invert(s) } -> std::same_as<typename C::Scalar>;
};

/**
* This class provides a bridge between the "public" (actually still
* internal) PrimeOrderCurve type, and the inner templates which are
* subclasses of EllipticCurve from pcurves_impl.h
*/
template <typename C>
class PrimeOrderCurveImpl final : public PrimeOrderCurve {
   public:
      static_assert(C::OrderBits <= PrimeOrderCurve::MaximumBitLength);
      static_assert(C::PrimeFieldBits <= PrimeOrderCurve::MaximumBitLength);

      size_t order_bits() const override { return C::OrderBits; }

      size_t scalar_bytes() const override { return C::Scalar::BYTES; }

      size_t field_element_bytes() const override { return C::FieldElement::BYTES; }

      ProjectivePoint mul_by_g(const Scalar& scalar, RandomNumberGenerator& rng) const override {
         return stash(m_mul_by_g.mul(from_stash(scalar), rng));
      }

      ProjectivePoint mul(const AffinePoint& pt, const Scalar& scalar, RandomNumberGenerator& rng) const override {
         auto tbl = WindowedBoothMulTable<C, VarPointWindowBits>(from_stash(pt));
         return stash(tbl.mul(from_stash(scalar), rng));
      }

      secure_vector<uint8_t> mul_x_only(const AffinePoint& pt,
                                        const Scalar& scalar,
                                        RandomNumberGenerator& rng) const override {
         auto tbl = WindowedBoothMulTable<C, VarPointWindowBits>(from_stash(pt));
         auto pt_x = to_affine_x<C>(tbl.mul(from_stash(scalar), rng));
         secure_vector<uint8_t> x_bytes(C::FieldElement::BYTES);
         pt_x.serialize_to(std::span<uint8_t, C::FieldElement::BYTES>{x_bytes});
         return x_bytes;
      }

      class PrecomputedMul2TableC final : public PrimeOrderCurve::PrecomputedMul2Table {
         public:
            const auto& table() const { return m_table; }

            explicit PrecomputedMul2TableC(const typename C::AffinePoint& x, const typename C::AffinePoint& y) :
                  m_table(x, y) {}

         private:
            WindowedMul2Table<C, Mul2PrecompWindowBits> m_table;
      };

      std::unique_ptr<const PrecomputedMul2Table> mul2_setup_g(const AffinePoint& q) const override {
         return std::make_unique<PrecomputedMul2TableC>(C::G, from_stash(q));
      }

      std::optional<ProjectivePoint> mul2_vartime(const PrecomputedMul2Table& tableb,
                                                  const Scalar& x,
                                                  const Scalar& y) const override {
         try {
            const auto& table = dynamic_cast<const PrecomputedMul2TableC&>(tableb);
            auto pt = table.table().mul2_vartime(from_stash(x), from_stash(y));
            if(pt.is_identity().as_bool()) {
               return {};
            } else {
               return stash(pt);
            }
         } catch(std::bad_cast&) {
            throw Invalid_Argument("Curve mismatch");
         }
      }

      std::optional<ProjectivePoint> mul_px_qy(const AffinePoint& p,
                                               const Scalar& x,
                                               const AffinePoint& q,
                                               const Scalar& y,
                                               RandomNumberGenerator& rng) const override {
         WindowedMul2Table<C, Mul2WindowBits> tbl(from_stash(p), from_stash(q));
         auto pt = tbl.mul2(from_stash(x), from_stash(y), rng);
         if(pt.is_identity().as_bool()) {
            return {};
         } else {
            return stash(pt);
         }
      }

      bool mul2_vartime_x_mod_order_eq(const PrecomputedMul2Table& tableb,
                                       const Scalar& v,
                                       const Scalar& x,
                                       const Scalar& y) const override {
         try {
            const auto& table = dynamic_cast<const PrecomputedMul2TableC&>(tableb);
            const auto pt = table.table().mul2_vartime(from_stash(x), from_stash(y));
            // Variable time here, so the early return is fine
            if(pt.is_identity().as_bool()) {
               return false;
            }

            /*
            * Avoid the inversion by instead projecting v.
            *
            * Given (x*z2) and v we want to know if x % n == v
            *
            * Inverting z2 to extract x is expensive. Instead compute (v*z2) and
            * compare it with (x*z2).
            *
            * With overwhelming probability, this conversion is correct. The
            * only time it is not is in the extremely unlikely case where the
            * signer actually reduced the x coordinate modulo the group order.
            * That is handled seperately in a second step.
            */
            const auto z2 = pt.z().square();

            std::array<uint8_t, C::Scalar::BYTES> v_bytes;
            from_stash(v).serialize_to(v_bytes);

            if(const auto fe_v = C::FieldElement::deserialize(v_bytes)) {
               if((*fe_v * z2 == pt.x()).as_bool()) {
                  return true;
               }

               /*
               * Possibly (if cryptographically unlikely) the signer
               * reduced the value modulo the group order.
               *
               * If so we must check v + n similarly as before. However here
               * we must be careful to not overflow since otherwise that
               * would lead to us accepting an incorrect signature.
               *
               * If the order is > p then the reduction modulo p would not have
               * had any effect and we don't need to consider the possibility
               */
               if constexpr(C::OrderIsLessThanField) {
                  /*
                  * We have to be careful to avoid overflow since this would
                  * lead to a forgery
                  *
                  * v < (p)-n => v + n < p
                  *
                  * The values n and neg_n could be precomputed but they are
                  * fast to compute and this codepath will ~never be taken
                  * unless when verifying an invalid signature. In any case
                  * it is many times cheaper than performing the modular inversion
                  * which this approach avoids.
                  */

                  // Create the group order as a field element, safe because n < p
                  const auto n = C::FieldElement::from_words(C::NW);
                  const auto neg_n = n.negate().to_words();

                  const auto vw = fe_v->to_words();
                  if(bigint_ct_is_lt(vw.data(), vw.size(), neg_n.data(), neg_n.size()).as_bool()) {
                     return (((*fe_v + n) * z2) == pt.x()).as_bool();
                  }
               }
            }

            return false;
         } catch(std::bad_cast&) {
            throw Invalid_Argument("Curve mismatch");
         }
      }

      Scalar base_point_mul_x_mod_order(const Scalar& scalar, RandomNumberGenerator& rng) const override {
         auto pt = m_mul_by_g.mul(from_stash(scalar), rng);
         std::array<uint8_t, C::FieldElement::BYTES> x_bytes;
         to_affine_x<C>(pt).serialize_to(std::span{x_bytes});
         // Reduction might be required (if unlikely)
         return stash(C::Scalar::from_wide_bytes(std::span<const uint8_t, C::FieldElement::BYTES>{x_bytes}));
      }

      AffinePoint generator() const override { return stash(C::G); }

      AffinePoint point_to_affine(const ProjectivePoint& pt) const override {
         return stash(to_affine<C>(from_stash(pt)));
      }

      ProjectivePoint point_add(const AffinePoint& a, const AffinePoint& b) const override {
         return stash(C::ProjectivePoint::from_affine(from_stash(a)) + from_stash(b));
      }

      AffinePoint point_negate(const AffinePoint& pt) const override { return stash(from_stash(pt).negate()); }

      bool affine_point_is_identity(const AffinePoint& pt) const override {
         return from_stash(pt).is_identity().as_bool();
      }

      void serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const override {
         BOTAN_ARG_CHECK(bytes.size() == C::AffinePoint::BYTES, "Invalid length for serialize_point");
         from_stash(pt).serialize_to(bytes.subspan<0, C::AffinePoint::BYTES>());
      }

      void serialize_scalar(std::span<uint8_t> bytes, const Scalar& scalar) const override {
         BOTAN_ARG_CHECK(bytes.size() == C::Scalar::BYTES, "Invalid length to serialize_scalar");
         return from_stash(scalar).serialize_to(bytes.subspan<0, C::Scalar::BYTES>());
      }

      std::optional<Scalar> deserialize_scalar(std::span<const uint8_t> bytes) const override {
         if(auto scalar = C::Scalar::deserialize(bytes)) {
            if(!scalar->is_zero().as_bool()) {
               return stash(*scalar);
            }
         }

         return {};
      }

      std::optional<Scalar> scalar_from_wide_bytes(std::span<const uint8_t> bytes) const override {
         if(auto s = C::Scalar::from_wide_bytes_varlen(bytes)) {
            return stash(*s);
         } else {
            return {};
         }
      }

      std::optional<AffinePoint> deserialize_point(std::span<const uint8_t> bytes) const override {
         if(auto pt = C::AffinePoint::deserialize(bytes)) {
            return stash(*pt);
         } else {
            return {};
         }
      }

      bool hash_to_curve_supported() const override { return C::ValidForSswuHash; }

      AffinePoint hash_to_curve_nu(std::function<void(std::span<uint8_t>)> expand_message) const override {
         if constexpr(C::ValidForSswuHash) {
            return stash(hash_to_curve_sswu<C, false>(expand_message));
         } else {
            throw Not_Implemented("Hash to curve is not implemented for this curve");
         }
      }

      ProjectivePoint hash_to_curve_ro(std::function<void(std::span<uint8_t>)> expand_message) const override {
         if constexpr(C::ValidForSswuHash) {
            return stash(hash_to_curve_sswu<C, true>(expand_message));
         } else {
            throw Not_Implemented("Hash to curve is not implemented for this curve");
         }
      }

      Scalar scalar_add(const Scalar& a, const Scalar& b) const override {
         return stash(from_stash(a) + from_stash(b));
      }

      Scalar scalar_sub(const Scalar& a, const Scalar& b) const override {
         return stash(from_stash(a) - from_stash(b));
      }

      Scalar scalar_mul(const Scalar& a, const Scalar& b) const override {
         return stash(from_stash(a) * from_stash(b));
      }

      Scalar scalar_square(const Scalar& s) const override { return stash(from_stash(s).square()); }

      Scalar scalar_invert(const Scalar& ss) const override {
         auto s = from_stash(ss);
         if constexpr(curve_supports_scalar_invert<C>) {
            return stash(C::scalar_invert(s));
         } else {
            return stash(s.invert());
         }
      }

      Scalar scalar_invert_vartime(const Scalar& ss) const override {
         auto s = from_stash(ss);
         return stash(s.invert_vartime());
      }

      Scalar scalar_negate(const Scalar& s) const override { return stash(from_stash(s).negate()); }

      bool scalar_is_zero(const Scalar& s) const override { return from_stash(s).is_zero().as_bool(); }

      bool scalar_equal(const Scalar& a, const Scalar& b) const override {
         return (from_stash(a) == from_stash(b)).as_bool();
      }

      Scalar scalar_one() const override { return stash(C::Scalar::one()); }

      Scalar random_scalar(RandomNumberGenerator& rng) const override { return stash(C::Scalar::random(rng)); }

      PrimeOrderCurveImpl() : m_mul_by_g(C::G) {}

      static std::shared_ptr<const PrimeOrderCurve> instance() {
         static auto g_curve = std::make_shared<const PrimeOrderCurveImpl<C>>();
         return g_curve;
      }

   private:
      static Scalar stash(const typename C::Scalar& s) {
         return Scalar::_create(instance(), s.template stash_value<StorageWords>());
      }

      static typename C::Scalar from_stash(const Scalar& s) {
         if(s._curve() != instance()) {
            throw Invalid_Argument("Curve mismatch");
         }
         return C::Scalar::from_stash(s._value());
      }

      static AffinePoint stash(const typename C::AffinePoint& pt) {
         auto x_w = pt.x().template stash_value<StorageWords>();
         auto y_w = pt.y().template stash_value<StorageWords>();
         return AffinePoint::_create(instance(), x_w, y_w);
      }

      static typename C::AffinePoint from_stash(const AffinePoint& pt) {
         if(pt._curve() != instance()) {
            throw Invalid_Argument("Curve mismatch");
         }
         auto x = C::FieldElement::from_stash(pt._x());
         auto y = C::FieldElement::from_stash(pt._y());
         return typename C::AffinePoint(x, y);
      }

      static ProjectivePoint stash(const typename C::ProjectivePoint& pt) {
         auto x_w = pt.x().template stash_value<StorageWords>();
         auto y_w = pt.y().template stash_value<StorageWords>();
         auto z_w = pt.z().template stash_value<StorageWords>();
         return ProjectivePoint::_create(instance(), x_w, y_w, z_w);
      }

      static typename C::ProjectivePoint from_stash(const ProjectivePoint& pt) {
         if(pt._curve() != instance()) {
            throw Invalid_Argument("Curve mismatch");
         }
         auto x = C::FieldElement::from_stash(pt._x());
         auto y = C::FieldElement::from_stash(pt._y());
         auto z = C::FieldElement::from_stash(pt._z());
         return typename C::ProjectivePoint(x, y, z);
      }

   private:
      const PrecomputedBaseMulTable<C, BasePointWindowBits> m_mul_by_g;
};

}  // namespace Botan::PCurve

#endif
