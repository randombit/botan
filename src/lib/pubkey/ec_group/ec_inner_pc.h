/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_INNER_DATA_PC_H_
#define BOTAN_EC_INNER_DATA_PC_H_

#include <botan/internal/ec_inner_data.h>

#include <botan/internal/pcurves.h>

namespace Botan {

class EC_Scalar_Data_PC final : public EC_Scalar_Data {
   public:
      EC_Scalar_Data_PC(std::shared_ptr<const EC_Group_Data> group, PCurve::PrimeOrderCurve::Scalar v) :
            m_group(std::move(group)), m_v(std::move(v)) {}

      static const EC_Scalar_Data_PC& checked_ref(const EC_Scalar_Data& data);

      const std::shared_ptr<const EC_Group_Data>& group() const override;

      std::unique_ptr<EC_Scalar_Data> clone() const override;

      size_t bytes() const override;

      bool is_zero() const override;

      bool is_eq(const EC_Scalar_Data& y) const override;

      void assign(const EC_Scalar_Data& y) override;

      void square_self() override;

      std::unique_ptr<EC_Scalar_Data> negate() const override;

      std::unique_ptr<EC_Scalar_Data> invert() const override;

      std::unique_ptr<EC_Scalar_Data> invert_vartime() const override;

      std::unique_ptr<EC_Scalar_Data> add(const EC_Scalar_Data& other) const override;

      std::unique_ptr<EC_Scalar_Data> sub(const EC_Scalar_Data& other) const override;

      std::unique_ptr<EC_Scalar_Data> mul(const EC_Scalar_Data& other) const override;

      void serialize_to(std::span<uint8_t> bytes) const override;

      const auto& value() const { return m_v; }

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      PCurve::PrimeOrderCurve::Scalar m_v;
};

class EC_AffinePoint_Data_PC final : public EC_AffinePoint_Data {
   public:
      EC_AffinePoint_Data_PC(std::shared_ptr<const EC_Group_Data> group, PCurve::PrimeOrderCurve::AffinePoint pt);

      EC_AffinePoint_Data_PC(std::shared_ptr<const EC_Group_Data> group, std::span<const uint8_t> pt);

      static const EC_AffinePoint_Data_PC& checked_ref(const EC_AffinePoint_Data& data);

      const std::shared_ptr<const EC_Group_Data>& group() const override;

      std::unique_ptr<EC_AffinePoint_Data> clone() const override;

      size_t field_element_bytes() const override;

      bool is_identity() const override;

      void serialize_x_to(std::span<uint8_t> bytes) const override;

      void serialize_y_to(std::span<uint8_t> bytes) const override;

      void serialize_xy_to(std::span<uint8_t> bytes) const override;

      void serialize_compressed_to(std::span<uint8_t> bytes) const override;

      void serialize_uncompressed_to(std::span<uint8_t> bytes) const override;

      std::unique_ptr<EC_AffinePoint_Data> mul(const EC_Scalar_Data& scalar,
                                               RandomNumberGenerator& rng,
                                               std::vector<BigInt>& ws) const override;

      secure_vector<uint8_t> mul_x_only(const EC_Scalar_Data& scalar,
                                        RandomNumberGenerator& rng,
                                        std::vector<BigInt>& ws) const override;

      const PCurve::PrimeOrderCurve::AffinePoint& value() const { return m_pt; }

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      EC_Point to_legacy_point() const override;
#endif

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      PCurve::PrimeOrderCurve::AffinePoint m_pt;
      secure_vector<uint8_t> m_xy;  // empty if point is identity
};

class EC_Mul2Table_Data_PC final : public EC_Mul2Table_Data {
   public:
      EC_Mul2Table_Data_PC(const EC_AffinePoint_Data& q);

      std::unique_ptr<EC_AffinePoint_Data> mul2_vartime(const EC_Scalar_Data& x,
                                                        const EC_Scalar_Data& y) const override;

      bool mul2_vartime_x_mod_order_eq(const EC_Scalar_Data& v,
                                       const EC_Scalar_Data& x,
                                       const EC_Scalar_Data& y) const override;

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      std::unique_ptr<const PCurve::PrimeOrderCurve::PrecomputedMul2Table> m_tbl;
};

}  // namespace Botan

#endif
