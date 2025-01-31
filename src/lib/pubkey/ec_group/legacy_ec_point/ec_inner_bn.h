/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_INNER_DATA_BN_H_
#define BOTAN_EC_INNER_DATA_BN_H_

#include <botan/internal/ec_inner_data.h>
#include <botan/internal/point_mul.h>

namespace Botan {

class EC_Scalar_Data_BN final : public EC_Scalar_Data {
   public:
      EC_Scalar_Data_BN(std::shared_ptr<const EC_Group_Data> group, BigInt v) :
            m_group(std::move(group)), m_v(std::move(v)) {}

      static const EC_Scalar_Data_BN& checked_ref(const EC_Scalar_Data& data);

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

      const BigInt& value() const { return m_v; }

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      BigInt m_v;
};

class EC_AffinePoint_Data_BN final : public EC_AffinePoint_Data {
   public:
      EC_AffinePoint_Data_BN(std::shared_ptr<const EC_Group_Data> group, EC_Point pt);

      EC_AffinePoint_Data_BN(std::shared_ptr<const EC_Group_Data> group, std::span<const uint8_t> pt);

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

      EC_Point to_legacy_point() const override { return m_pt; }

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      EC_Point m_pt;
      secure_vector<uint8_t> m_xy;  // empty if point is identity element
};

class EC_Mul2Table_Data_BN final : public EC_Mul2Table_Data {
   public:
      EC_Mul2Table_Data_BN(const EC_AffinePoint_Data& g, const EC_AffinePoint_Data& h);

      std::unique_ptr<EC_AffinePoint_Data> mul2_vartime(const EC_Scalar_Data& x,
                                                        const EC_Scalar_Data& y) const override;

      bool mul2_vartime_x_mod_order_eq(const EC_Scalar_Data& v,
                                       const EC_Scalar_Data& x,
                                       const EC_Scalar_Data& y) const override;

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      EC_Point_Multi_Point_Precompute m_tbl;
};

}  // namespace Botan

#endif
