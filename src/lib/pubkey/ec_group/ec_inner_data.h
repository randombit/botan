/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EC_INNER_DATA_H_
#define BOTAN_EC_INNER_DATA_H_

#include <botan/ec_group.h>

#include <botan/asn1_obj.h>
#include <botan/bigint.h>
#include <botan/reducer.h>
#include <botan/internal/point_mul.h>
#include <botan/internal/stl_util.h>
#include <memory>
#include <span>

namespace Botan {

class EC_Group_Data;

class EC_Scalar_Data {
   public:
      virtual ~EC_Scalar_Data() = default;

      virtual const std::shared_ptr<const EC_Group_Data>& group() const = 0;

      virtual size_t bytes() const = 0;

      virtual std::unique_ptr<EC_Scalar_Data> clone() const = 0;

      virtual bool is_zero() const = 0;

      virtual bool is_eq(const EC_Scalar_Data& y) const = 0;

      virtual void assign(const EC_Scalar_Data& y) = 0;

      virtual void square_self() = 0;

      virtual std::unique_ptr<EC_Scalar_Data> negate() const = 0;

      virtual std::unique_ptr<EC_Scalar_Data> invert() const = 0;

      virtual std::unique_ptr<EC_Scalar_Data> add(const EC_Scalar_Data& other) const = 0;

      virtual std::unique_ptr<EC_Scalar_Data> sub(const EC_Scalar_Data& other) const = 0;

      virtual std::unique_ptr<EC_Scalar_Data> mul(const EC_Scalar_Data& other) const = 0;

      virtual void serialize_to(std::span<uint8_t> bytes) const = 0;
};

class EC_AffinePoint_Data {
   public:
      virtual ~EC_AffinePoint_Data() = default;

      virtual const std::shared_ptr<const EC_Group_Data>& group() const = 0;

      virtual std::unique_ptr<EC_AffinePoint_Data> clone() const = 0;

      // Return size of a field element
      virtual size_t field_element_bytes() const = 0;

      // Writes 1 field element worth of data to bytes
      virtual void serialize_x_to(std::span<uint8_t> bytes) const = 0;

      // Writes 1 field element worth of data to bytes
      virtual void serialize_y_to(std::span<uint8_t> bytes) const = 0;

      // Writes 2 field elements worth of data to bytes
      virtual void serialize_xy_to(std::span<uint8_t> bytes) const = 0;

      // Writes 1 byte + 1 field element worth of data to bytes
      virtual void serialize_compressed_to(std::span<uint8_t> bytes) const = 0;

      // Writes 1 byte + 2 field elements worth of data to bytes
      virtual void serialize_uncompressed_to(std::span<uint8_t> bytes) const = 0;

      virtual std::unique_ptr<EC_AffinePoint_Data> mul(const EC_Scalar_Data& scalar,
                                                       RandomNumberGenerator& rng,
                                                       std::vector<BigInt>& ws) const = 0;

      virtual EC_Point to_legacy_point() const = 0;
};

class EC_Mul2Table_Data {
   public:
      virtual ~EC_Mul2Table_Data() = default;

      // Returns nullptr if g*x + h*y was point at infinity
      virtual std::unique_ptr<EC_AffinePoint_Data> mul2_vartime(const EC_Scalar_Data& x,
                                                                const EC_Scalar_Data& y) const = 0;

      // Returns nullptr if g*x + h*y was point at infinity
      virtual std::unique_ptr<EC_Scalar_Data> mul2_vartime_x_mod_order(const EC_Scalar_Data& x,
                                                                       const EC_Scalar_Data& y) const = 0;
};

class EC_Group_Data final : public std::enable_shared_from_this<EC_Group_Data> {
   public:
      EC_Group_Data(const BigInt& p,
                    const BigInt& a,
                    const BigInt& b,
                    const BigInt& g_x,
                    const BigInt& g_y,
                    const BigInt& order,
                    const BigInt& cofactor,
                    const OID& oid,
                    EC_Group_Source source);

      bool params_match(const BigInt& p,
                        const BigInt& a,
                        const BigInt& b,
                        const BigInt& g_x,
                        const BigInt& g_y,
                        const BigInt& order,
                        const BigInt& cofactor) const;

      bool params_match(const EC_Group_Data& other) const;

      void set_oid(const OID& oid) {
         BOTAN_STATE_CHECK(m_oid.empty());
         m_oid = oid;
      }

      const OID& oid() const { return m_oid; }

      const BigInt& p() const { return m_curve.get_p(); }

      const BigInt& a() const { return m_curve.get_a(); }

      const BigInt& b() const { return m_curve.get_b(); }

      const BigInt& order() const { return m_order; }

      const BigInt& cofactor() const { return m_cofactor; }

      const BigInt& g_x() const { return m_g_x; }

      const BigInt& g_y() const { return m_g_y; }

      size_t p_bits() const { return m_p_bits; }

      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      size_t order_bits() const { return m_order_bits; }

      size_t order_bytes() const { return m_order_bytes; }

      const CurveGFp& curve() const { return m_curve; }

      const EC_Point& base_point() const { return m_base_point; }

      bool a_is_minus_3() const { return m_a_is_minus_3; }

      bool a_is_zero() const { return m_a_is_zero; }

      BigInt mod_order(const BigInt& x) const { return m_mod_order.reduce(x); }

      BigInt square_mod_order(const BigInt& x) const { return m_mod_order.square(x); }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const { return m_mod_order.multiply(x, y); }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const {
         return m_mod_order.multiply(m_mod_order.multiply(x, y), z);
      }

      BigInt inverse_mod_order(const BigInt& x) const { return inverse_mod(x, m_order); }

      EC_Point blinded_base_point_multiply(const BigInt& k, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const {
         return m_base_mult.mul(k, rng, m_order, ws);
      }

      EC_Group_Source source() const { return m_source; }

      std::unique_ptr<EC_Scalar_Data> scalar_from_bytes_with_trunc(std::span<const uint8_t> bytes) const;

      std::unique_ptr<EC_Scalar_Data> scalar_from_bytes_mod_order(std::span<const uint8_t> bytes) const;

      std::unique_ptr<EC_Scalar_Data> scalar_from_bigint(const BigInt& bn) const;

      std::unique_ptr<EC_Scalar_Data> scalar_random(RandomNumberGenerator& rng) const;

      std::unique_ptr<EC_Scalar_Data> scalar_zero() const;

      std::unique_ptr<EC_Scalar_Data> scalar_one() const;

      std::unique_ptr<EC_Scalar_Data> gk_x_mod_order(const EC_Scalar_Data& scalar,
                                                     RandomNumberGenerator& rng,
                                                     std::vector<BigInt>& ws) const;

      std::unique_ptr<EC_Scalar_Data> scalar_deserialize(std::span<const uint8_t> bytes);

      std::unique_ptr<EC_AffinePoint_Data> point_deserialize(std::span<const uint8_t> bytes) const;

      std::unique_ptr<EC_AffinePoint_Data> point_hash_to_curve_ro(std::string_view hash_fn,
                                                                  std::span<const uint8_t> input,
                                                                  std::span<const uint8_t> domain_sep) const;

      std::unique_ptr<EC_AffinePoint_Data> point_hash_to_curve_nu(std::string_view hash_fn,
                                                                  std::span<const uint8_t> input,
                                                                  std::span<const uint8_t> domain_sep) const;

      std::unique_ptr<EC_AffinePoint_Data> point_g_mul(const EC_Scalar_Data& scalar,
                                                       RandomNumberGenerator& rng,
                                                       std::vector<BigInt>& ws) const;

      std::unique_ptr<EC_Mul2Table_Data> make_mul2_table(const EC_AffinePoint_Data& pt) const;

   private:
      CurveGFp m_curve;
      EC_Point m_base_point;

      BigInt m_g_x;
      BigInt m_g_y;
      BigInt m_order;
      BigInt m_cofactor;
      Modular_Reducer m_mod_order;
      EC_Point_Base_Point_Precompute m_base_mult;
      OID m_oid;
      size_t m_p_bits;
      size_t m_order_bits;
      size_t m_order_bytes;
      bool m_a_is_minus_3;
      bool m_a_is_zero;
      EC_Group_Source m_source;
};

}  // namespace Botan

#endif
