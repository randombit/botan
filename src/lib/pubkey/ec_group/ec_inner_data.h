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
#include <botan/internal/ct_utils.h>
#include <botan/internal/pcurves.h>
#include <functional>
#include <memory>
#include <span>

namespace Botan {

class EC_Group_Data;

/**
* The internal representation of an EC_Scalar
*/
class EC_Scalar_Data final {
   public:
      EC_Scalar_Data(std::shared_ptr<const EC_Group_Data> group, PCurve::PrimeOrderCurve::Scalar v) :
            m_group(std::move(group)), m_v(std::move(v)) {}

      const std::shared_ptr<const EC_Group_Data>& group() const { return m_group; }

      const PCurve::PrimeOrderCurve::Scalar& value() const { return m_v; }

      void set_value(const PCurve::PrimeOrderCurve::Scalar& v) { m_v = v; }

      void zeroize() { m_v._zeroize(); }

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      PCurve::PrimeOrderCurve::Scalar m_v;
};

/**
* The internal representation of an EC_AffinePoint
*/
class EC_AffinePoint_Data final {
   public:
      EC_AffinePoint_Data(std::shared_ptr<const EC_Group_Data> group, PCurve::PrimeOrderCurve::AffinePoint pt);

      const std::shared_ptr<const EC_Group_Data>& group() const { return m_group; }

      const PCurve::PrimeOrderCurve::AffinePoint& value() const { return m_pt; }

      bool is_identity() const { return m_xy.empty(); }

      /// The SEC1 uncompressed encoding; empty if the point is the identity
      std::span<const uint8_t> uncompressed() const { return m_xy; }

      void _const_time_poison() const { CT::poison_all(m_pt, m_xy); }

      void _const_time_unpoison() const { CT::unpoison_all(m_pt, m_xy); }

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      PCurve::PrimeOrderCurve::AffinePoint m_pt;
      secure_vector<uint8_t> m_xy;
};

/**
* The internal representation of an EC_Group::Mul2Table
*/
class EC_Mul2Table_Data final {
   public:
      EC_Mul2Table_Data(std::shared_ptr<const EC_Group_Data> group,
                        std::unique_ptr<const PCurve::PrimeOrderCurve::PrecomputedMul2Table> tbl) :
            m_group(std::move(group)), m_tbl(std::move(tbl)) {}

      const std::shared_ptr<const EC_Group_Data>& group() const { return m_group; }

      const PCurve::PrimeOrderCurve::PrecomputedMul2Table& table() const { return *m_tbl; }

   private:
      std::shared_ptr<const EC_Group_Data> m_group;
      std::unique_ptr<const PCurve::PrimeOrderCurve::PrecomputedMul2Table> m_tbl;
};

class EC_Group_Data final {
   public:
      static std::shared_ptr<EC_Group_Data> create(const BigInt& p,
                                                   const BigInt& a,
                                                   const BigInt& b,
                                                   const BigInt& g_x,
                                                   const BigInt& g_y,
                                                   const BigInt& order,
                                                   const OID& oid,
                                                   EC_Group_Source source);

      ~EC_Group_Data();

      EC_Group_Data(const EC_Group_Data& other) = delete;
      EC_Group_Data(EC_Group_Data&& other) = delete;
      EC_Group_Data& operator=(const EC_Group_Data& other) = delete;
      EC_Group_Data& operator=(EC_Group_Data&& other) = delete;

      bool params_match(const BigInt& p,
                        const BigInt& a,
                        const BigInt& b,
                        const BigInt& g_x,
                        const BigInt& g_y,
                        const BigInt& order) const;

      // Like the other params_match but accepting the base point in encoded form
      bool params_match(const BigInt& p,
                        const BigInt& a,
                        const BigInt& b,
                        std::span<const uint8_t> base_pt,
                        const BigInt& order) const;

      bool params_match(const EC_Group_Data& other) const;

      const OID& oid() const { return m_oid; }

      const std::vector<uint8_t>& der_named_curve() const { return m_der_named_curve; }

      const BigInt& p() const { return m_p; }

      const BigInt& a() const { return m_a; }

      const BigInt& b() const { return m_b; }

      const BigInt& order() const { return m_order; }

      const BigInt& g_x() const { return m_g_x; }

      const BigInt& g_y() const { return m_g_y; }

      size_t p_bits() const { return m_p_bits; }

      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      size_t order_bits() const { return m_order_bits; }

      size_t order_bytes() const { return m_order_bytes; }

      EC_Group_Source source() const { return m_source; }

      EC_Group_Engine engine() const { return m_engine; }

      /// Return true if EC_AffinePoint::hash_to_curve_ro/hash_to_curve_nu will
      /// work for this group when using the specified hash function
      bool hash_to_curve_supported(std::string_view hash_fn) const;

      const PCurve::PrimeOrderCurve& pcurve() const { return *m_pcurve; }

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
                    const OID& oid,
                    EC_Group_Source source);

   private:
      // Never null; the constructor throws if no implementation is available
      std::shared_ptr<const PCurve::PrimeOrderCurve> m_pcurve;

      BigInt m_p;
      BigInt m_a;
      BigInt m_b;
      BigInt m_g_x;
      BigInt m_g_y;
      BigInt m_order;

      OID m_oid;
      std::vector<uint8_t> m_der_named_curve;
      size_t m_p_bits;
      size_t m_order_bits;
      size_t m_order_bytes;
      EC_Group_Source m_source;
      EC_Group_Engine m_engine;
};

/**
* Look up the parameters of a builtin group by OID
*
* @param oid the OID of the group to look up
* @return the group data, or nullptr if the OID is not a known group
*/
std::shared_ptr<EC_Group_Data> EC_group_info(const OID& oid);

/**
* Identify a builtin group by its order
*
* @param order the group order to look up
* @return the OID of the matching group, or an empty OID if none matches
*/
OID BOTAN_TEST_API EC_group_identity_from_order(const BigInt& order);

/**
* Instantiate the named hash and return a closure implementing the
* expand_message function of RFC 9380
*
* Throws if the hash is unknown, or too weak for use with a group
* of order_bits, per the RFC 9380 requirements
*/
std::function<void(std::span<uint8_t>)> h2c_expand_message(std::string_view hash_fn,
                                                           size_t order_bits,
                                                           std::span<const uint8_t> input,
                                                           std::span<const uint8_t> domain_sep);

}  // namespace Botan

#endif
