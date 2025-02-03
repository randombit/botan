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
#include <botan/internal/monty.h>
#include <botan/internal/stl_util.h>
#include <memory>
#include <span>

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
   #include <botan/reducer.h>
#endif

namespace Botan {

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
class EC_Point_Base_Point_Precompute;
#endif

namespace PCurve {

class PrimeOrderCurve;

}

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

      virtual std::unique_ptr<EC_Scalar_Data> invert_vartime() const = 0;

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

      // Return if this is the identity element
      virtual bool is_identity() const = 0;

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

      virtual secure_vector<uint8_t> mul_x_only(const EC_Scalar_Data& scalar,
                                                RandomNumberGenerator& rng,
                                                std::vector<BigInt>& ws) const = 0;

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      virtual EC_Point to_legacy_point() const = 0;
#endif
};

class EC_Mul2Table_Data {
   public:
      virtual ~EC_Mul2Table_Data() = default;

      // Returns nullptr if g*x + h*y was point at infinity
      virtual std::unique_ptr<EC_AffinePoint_Data> mul2_vartime(const EC_Scalar_Data& x,
                                                                const EC_Scalar_Data& y) const = 0;

      // Check if v == (g*x + h*y).x % n
      //
      // Returns false if g*x + h*y was point at infinity
      virtual bool mul2_vartime_x_mod_order_eq(const EC_Scalar_Data& v,
                                               const EC_Scalar_Data& x,
                                               const EC_Scalar_Data& y) const = 0;
};

class EC_Group_Data final : public std::enable_shared_from_this<EC_Group_Data> {
   public:
      static std::shared_ptr<EC_Group_Data> create(const BigInt& p,
                                                   const BigInt& a,
                                                   const BigInt& b,
                                                   const BigInt& g_x,
                                                   const BigInt& g_y,
                                                   const BigInt& order,
                                                   const BigInt& cofactor,
                                                   const OID& oid,
                                                   EC_Group_Source source);

      ~EC_Group_Data();

      bool params_match(const BigInt& p,
                        const BigInt& a,
                        const BigInt& b,
                        const BigInt& g_x,
                        const BigInt& g_y,
                        const BigInt& order,
                        const BigInt& cofactor) const;

      bool params_match(const EC_Group_Data& other) const;

      void set_oid(const OID& oid);

      const OID& oid() const { return m_oid; }

      const std::vector<uint8_t>& der_named_curve() const { return m_der_named_curve; }

      const BigInt& p() const { return m_p; }

      const BigInt& a() const { return m_a; }

      const BigInt& b() const { return m_b; }

      const BigInt& order() const { return m_order; }

      const BigInt& cofactor() const { return m_cofactor; }

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      const CurveGFp& curve() const { return m_curve; }

      const EC_Point& base_point() const { return m_base_point; }

      const Montgomery_Params& monty() const { return m_monty; }

      const BigInt& monty_a() const { return m_a_r; }

      const BigInt& monty_b() const { return m_b_r; }

      const Modular_Reducer& mod_order() const { return m_mod_order; }
#endif

      bool order_is_less_than_p() const { return m_order_is_less_than_p; }

      bool has_cofactor() const { return m_has_cofactor; }

      const BigInt& g_x() const { return m_g_x; }

      const BigInt& g_y() const { return m_g_y; }

      size_t p_words() const { return m_p_words; }

      size_t p_bits() const { return m_p_bits; }

      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      size_t order_bits() const { return m_order_bits; }

      size_t order_bytes() const { return m_order_bytes; }

      bool a_is_minus_3() const { return m_a_is_minus_3; }

      bool a_is_zero() const { return m_a_is_zero; }

      EC_Group_Source source() const { return m_source; }

      EC_Group_Engine engine() const { return m_engine; }

      /// Scalar from bytes
      ///
      /// This returns a value only if the bytes represent (in big-endian encoding) an integer
      /// that is less than n, where n is the group order. It requires that the fixed length
      /// encoding (with zero prefix) be used. It also rejects inputs that encode zero.
      /// Thus the accepted range is [1,n)
      ///
      /// If the input is rejected then nullptr is returned
      std::unique_ptr<EC_Scalar_Data> scalar_deserialize(std::span<const uint8_t> bytes) const;

      /// Scalar from bytes with ECDSA style trunction
      ///
      /// This should always succeed
      std::unique_ptr<EC_Scalar_Data> scalar_from_bytes_with_trunc(std::span<const uint8_t> bytes) const;

      /// Scalar from bytes with modular reduction
      ///
      /// This returns a value only if bytes represents (in big-endian encoding) an integer
      /// that is at most the square of the scalar group size. Otherwise it returns nullptr.
      std::unique_ptr<EC_Scalar_Data> scalar_from_bytes_mod_order(std::span<const uint8_t> bytes) const;

      /// Scalar from BigInt
      ///
      /// This returns a value only if bn is in [1,n) where n is the group order.
      /// Otherwise it returns nullptr
      std::unique_ptr<EC_Scalar_Data> scalar_from_bigint(const BigInt& bn) const;

      /// Return a random scalar
      ///
      /// This will be in the range [1,n) where n is the group order
      std::unique_ptr<EC_Scalar_Data> scalar_random(RandomNumberGenerator& rng) const;

      std::unique_ptr<EC_Scalar_Data> scalar_zero() const;

      std::unique_ptr<EC_Scalar_Data> scalar_one() const;

      std::unique_ptr<EC_Scalar_Data> gk_x_mod_order(const EC_Scalar_Data& scalar,
                                                     RandomNumberGenerator& rng,
                                                     std::vector<BigInt>& ws) const;

      /// Deserialize a point
      ///
      /// Returns nullptr if the point encoding was invalid or not on the curve
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

      std::unique_ptr<EC_AffinePoint_Data> mul_px_qy(const EC_AffinePoint_Data& p,
                                                     const EC_Scalar_Data& x,
                                                     const EC_AffinePoint_Data& q,
                                                     const EC_Scalar_Data& y,
                                                     RandomNumberGenerator& rng) const;

      std::unique_ptr<EC_AffinePoint_Data> affine_add(const EC_AffinePoint_Data& p, const EC_AffinePoint_Data& q) const;

      std::unique_ptr<EC_AffinePoint_Data> affine_neg(const EC_AffinePoint_Data& p) const;

      std::unique_ptr<EC_Mul2Table_Data> make_mul2_table(const EC_AffinePoint_Data& pt) const;

      const PCurve::PrimeOrderCurve& pcurve() const {
         BOTAN_ASSERT_NONNULL(m_pcurve);
         return *m_pcurve;
      }

      /**
      * Note this constructor should *only* be called by EC_Group_Data::create.
      *
      * It is only public to allow use of std::make_shared
      */
      EC_Group_Data(const BigInt& p,
                    const BigInt& a,
                    const BigInt& b,
                    const BigInt& g_x,
                    const BigInt& g_y,
                    const BigInt& order,
                    const BigInt& cofactor,
                    const OID& oid,
                    EC_Group_Source source);

   private:
      // Possibly nullptr (if pcurves not available or not a standard curve)
      std::shared_ptr<const PCurve::PrimeOrderCurve> m_pcurve;

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      // Set only if m_pcurve is nullptr
      std::unique_ptr<EC_Point_Base_Point_Precompute> m_base_mult;
#endif

      BigInt m_p;
      BigInt m_a;
      BigInt m_b;
      BigInt m_g_x;
      BigInt m_g_y;
      BigInt m_order;
      BigInt m_cofactor;

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      CurveGFp m_curve;
      EC_Point m_base_point;

      Modular_Reducer m_mod_field;
      Modular_Reducer m_mod_order;

      // Montgomery parameters (only used for legacy EC_Point)
      Montgomery_Params m_monty;

      BigInt m_a_r;  // (a*r) % p
      BigInt m_b_r;  // (b*r) % p
#endif

      OID m_oid;
      std::vector<uint8_t> m_der_named_curve;
      size_t m_p_words;
      size_t m_p_bits;
      size_t m_order_bits;
      size_t m_order_bytes;
      bool m_a_is_minus_3;
      bool m_a_is_zero;
      bool m_has_cofactor;
      bool m_order_is_less_than_p;
      EC_Group_Source m_source;
      EC_Group_Engine m_engine;
};

}  // namespace Botan

#endif
