/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_PCURVES_WRAP_H_
#define BOTAN_PCURVES_WRAP_H_

#include <botan/internal/pcurves.h>
#include <botan/internal/pcurves_impl.h>

namespace Botan::PCurve {

template <typename C>
class PrimeOrderCurveImpl final : public PrimeOrderCurve {
   public:
      class PrecomputedMul2TableC final : public PrimeOrderCurve::PrecomputedMul2Table {
         public:
            static constexpr size_t WindowBits = 4;

            const WindowedMul2Table<C, WindowBits>& table() const { return m_table; }

            explicit PrecomputedMul2TableC(const typename C::AffinePoint& x, const typename C::AffinePoint& y) :
                  m_table(x, y) {}

         private:
            WindowedMul2Table<C, WindowBits> m_table;
      };

      static_assert(C::OrderBits <= PrimeOrderCurve::MaximumBitLength);
      static_assert(C::PrimeFieldBits <= PrimeOrderCurve::MaximumBitLength);

      size_t order_bits() const override { return C::OrderBits; }

      size_t scalar_bytes() const override { return C::Scalar::BYTES; }

      size_t field_element_bytes() const override { return C::FieldElement::BYTES; }

      ProjectivePoint mul_by_g(const Scalar& scalar, RandomNumberGenerator& rng) const override {
         return stash(m_mul_by_g.mul(from_stash(scalar), rng));
      }

      ProjectivePoint mul(const AffinePoint& pt, const Scalar& scalar, RandomNumberGenerator& rng) const override {
         auto tbl = WindowedMulTable<C, 4>(from_stash(pt));
         return stash(tbl.mul(from_stash(scalar), rng));
      }

      std::unique_ptr<const PrecomputedMul2Table> mul2_setup(const AffinePoint& x,
                                                             const AffinePoint& y) const override {
         return std::make_unique<PrecomputedMul2TableC>(from_stash(x), from_stash(y));
      }

      std::optional<ProjectivePoint> mul2_vartime(const PrecomputedMul2Table& tableb,
                                                  const Scalar& s1,
                                                  const Scalar& s2) const override {
         try {
            const auto& table = dynamic_cast<const PrecomputedMul2TableC&>(tableb);
            auto pt = table.table().mul2_vartime(from_stash(s1), from_stash(s2));
            if(pt.is_identity().as_bool()) {
               return {};
            } else {
               return stash(pt);
            }
         } catch(std::bad_cast&) {
            throw Invalid_Argument("Curve mismatch");
         }
      }

      std::optional<Scalar> mul2_vartime_x_mod_order(const PrecomputedMul2Table& tableb,
                                                     const Scalar& s1,
                                                     const Scalar& s2) const override {
         try {
            const auto& table = dynamic_cast<const PrecomputedMul2TableC&>(tableb);
            const auto pt = table.table().mul2_vartime(from_stash(s1), from_stash(s2));
            // Variable time here, so the early return is fine
            if(pt.is_identity().as_bool()) {
               return {};
            }
            std::array<uint8_t, C::FieldElement::BYTES> x_bytes;
            pt.to_affine().x().serialize_to(std::span{x_bytes});
            return stash(C::Scalar::from_wide_bytes(std::span<const uint8_t, C::FieldElement::BYTES>{x_bytes}));
         } catch(std::bad_cast&) {
            throw Invalid_Argument("Curve mismatch");
         }
      }

      Scalar base_point_mul_x_mod_order(const Scalar& scalar, RandomNumberGenerator& rng) const override {
         auto pt = m_mul_by_g.mul(from_stash(scalar), rng);
         std::array<uint8_t, C::FieldElement::BYTES> x_bytes;
         pt.to_affine().x().serialize_to(std::span{x_bytes});
         return stash(C::Scalar::from_wide_bytes(std::span<const uint8_t, C::FieldElement::BYTES>{x_bytes}));
      }

      AffinePoint generator() const override { return stash(C::G); }

      AffinePoint point_to_affine(const ProjectivePoint& pt) const override {
         return stash(from_stash(pt).to_affine());
      }

      ProjectivePoint point_to_projective(const AffinePoint& pt) const override {
         return stash(C::ProjectivePoint::from_affine(from_stash(pt)));
      }

      ProjectivePoint point_double(const ProjectivePoint& pt) const override { return stash(from_stash(pt).dbl()); }

      ProjectivePoint point_add(const ProjectivePoint& a, const ProjectivePoint& b) const override {
         return stash(from_stash(a) + from_stash(b));
      }

      ProjectivePoint point_add_mixed(const ProjectivePoint& a, const AffinePoint& b) const override {
         return stash(from_stash(a) + from_stash(b));
      }

      ProjectivePoint point_negate(const ProjectivePoint& pt) const override { return stash(from_stash(pt).negate()); }

      bool affine_point_is_identity(const AffinePoint& pt) const override {
         return from_stash(pt).is_identity().as_bool();
      }

      void serialize_point(std::span<uint8_t> bytes, const AffinePoint& pt) const override {
         BOTAN_ARG_CHECK(bytes.size() == C::AffinePoint::BYTES, "Invalid length for serialize_point");
         from_stash(pt).serialize_to(bytes.subspan<0, C::AffinePoint::BYTES>());
      }

      void serialize_point_compressed(std::span<uint8_t> bytes, const AffinePoint& pt) const override {
         BOTAN_ARG_CHECK(bytes.size() == C::AffinePoint::COMPRESSED_BYTES,
                         "Invalid length for serialize_point_compressed");
         from_stash(pt).serialize_compressed_to(bytes.subspan<0, C::AffinePoint::COMPRESSED_BYTES>());
      }

      void serialize_point_x(std::span<uint8_t> bytes, const AffinePoint& pt) const override {
         BOTAN_ARG_CHECK(bytes.size() == C::FieldElement::BYTES, "Invalid length for serialize_point_x");
         from_stash(pt).x().serialize_to(bytes.subspan<0, C::FieldElement::BYTES>());
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

      Scalar scalar_from_bits_with_trunc(std::span<const uint8_t> bytes) const override {
         return stash(C::Scalar::from_bits_with_trunc(bytes));
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

      ProjectivePoint hash_to_curve(std::string_view hash,
                                    std::span<const uint8_t> input,
                                    std::span<const uint8_t> domain_sep,
                                    bool random_oracle) const override {
         if constexpr(C::ValidForSswuHash) {
            return stash(hash_to_curve_sswu<C>(hash, random_oracle, input, domain_sep));
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

      Scalar scalar_invert(const Scalar& s) const override { return stash(from_stash(s).invert()); }

      Scalar scalar_negate(const Scalar& s) const override { return stash(from_stash(s).negate()); }

      bool scalar_is_zero(const Scalar& s) const override { return from_stash(s).is_zero().as_bool(); }

      bool scalar_equal(const Scalar& a, const Scalar& b) const override {
         return (from_stash(a) == from_stash(b)).as_bool();
      }

      Scalar scalar_zero() const override { return stash(C::Scalar::zero()); }

      Scalar scalar_one() const override { return stash(C::Scalar::one()); }

      Scalar scalar_from_u32(uint32_t x) const override { return stash(C::Scalar::from_word(x)); }

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
      const PrecomputedBaseMulTable<C, 5> m_mul_by_g;
};

}  // namespace Botan::PCurve

#endif
