/*
* (C) 2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/ec_inner_pc.h>

namespace Botan {

namespace {

PCurve::PrimeOrderCurve::AffinePoint deserialize_pcurve_pt(const PCurve::PrimeOrderCurve& curve,
                                                           std::span<const uint8_t> bytes) {
   if(auto pt = curve.deserialize_point(bytes)) {
      return *pt;
   } else {
      throw Decoding_Error("Invalid elliptic curve point encoding");
   }
}

}  // namespace

const EC_Scalar_Data_PC& EC_Scalar_Data_PC::checked_ref(const EC_Scalar_Data& data) {
   const auto* p = dynamic_cast<const EC_Scalar_Data_PC*>(&data);
   if(!p) {
      throw Invalid_State("Failed conversion to EC_Scalar_Data_PC");
   }
   return *p;
}

const std::shared_ptr<const EC_Group_Data>& EC_Scalar_Data_PC::group() const {
   return m_group;
}

size_t EC_Scalar_Data_PC::bytes() const {
   return this->group()->order_bytes();
}

std::unique_ptr<EC_Scalar_Data> EC_Scalar_Data_PC::clone() const {
   return std::make_unique<EC_Scalar_Data_PC>(this->group(), this->value());
}

bool EC_Scalar_Data_PC::is_zero() const {
   return this->value().is_zero();
}

bool EC_Scalar_Data_PC::is_eq(const EC_Scalar_Data& other) const {
   return (value() == checked_ref(other).value());
}

void EC_Scalar_Data_PC::assign(const EC_Scalar_Data& other) {
   m_v = checked_ref(other).value();
}

void EC_Scalar_Data_PC::square_self() {
   // TODO square in place
   m_v = m_v.square();
}

std::unique_ptr<EC_Scalar_Data> EC_Scalar_Data_PC::negate() const {
   return std::make_unique<EC_Scalar_Data_PC>(m_group, m_v.negate());
}

std::unique_ptr<EC_Scalar_Data> EC_Scalar_Data_PC::invert() const {
   return std::make_unique<EC_Scalar_Data_PC>(m_group, m_v.invert());
}

std::unique_ptr<EC_Scalar_Data> EC_Scalar_Data_PC::invert_vartime() const {
   return std::make_unique<EC_Scalar_Data_PC>(m_group, m_v.invert_vartime());
}

std::unique_ptr<EC_Scalar_Data> EC_Scalar_Data_PC::add(const EC_Scalar_Data& other) const {
   return std::make_unique<EC_Scalar_Data_PC>(m_group, m_v + checked_ref(other).value());
}

std::unique_ptr<EC_Scalar_Data> EC_Scalar_Data_PC::sub(const EC_Scalar_Data& other) const {
   return std::make_unique<EC_Scalar_Data_PC>(m_group, m_v - checked_ref(other).value());
}

std::unique_ptr<EC_Scalar_Data> EC_Scalar_Data_PC::mul(const EC_Scalar_Data& other) const {
   return std::make_unique<EC_Scalar_Data_PC>(m_group, m_v * checked_ref(other).value());
}

void EC_Scalar_Data_PC::serialize_to(std::span<uint8_t> bytes) const {
   BOTAN_ARG_CHECK(bytes.size() == m_group->order_bytes(), "Invalid output length");
   m_group->pcurve().serialize_scalar(bytes, m_v);
}

EC_AffinePoint_Data_PC::EC_AffinePoint_Data_PC(std::shared_ptr<const EC_Group_Data> group,
                                               PCurve::PrimeOrderCurve::AffinePoint pt) :
      m_group(std::move(group)), m_pt(std::move(pt)) {
   if(!m_pt.is_identity()) {
      m_xy = m_pt.serialize<secure_vector<uint8_t>>();
      BOTAN_ASSERT_NOMSG(m_xy.size() == 1 + 2 * field_element_bytes());
   }
}

EC_AffinePoint_Data_PC::EC_AffinePoint_Data_PC(std::shared_ptr<const EC_Group_Data> group,
                                               std::span<const uint8_t> bytes) :
      m_group(std::move(group)), m_pt(deserialize_pcurve_pt(m_group->pcurve(), bytes)) {
   if(!m_pt.is_identity()) {
      m_xy = m_pt.serialize<secure_vector<uint8_t>>();
      BOTAN_ASSERT_NOMSG(m_xy.size() == 1 + 2 * field_element_bytes());
   }
}

const EC_AffinePoint_Data_PC& EC_AffinePoint_Data_PC::checked_ref(const EC_AffinePoint_Data& data) {
   const auto* p = dynamic_cast<const EC_AffinePoint_Data_PC*>(&data);
   if(!p) {
      throw Invalid_State("Failed conversion to EC_AffinePoint_Data_PC");
   }
   return *p;
}

std::unique_ptr<EC_AffinePoint_Data> EC_AffinePoint_Data_PC::clone() const {
   return std::make_unique<EC_AffinePoint_Data_PC>(m_group, m_pt);
}

const std::shared_ptr<const EC_Group_Data>& EC_AffinePoint_Data_PC::group() const {
   return m_group;
}

std::unique_ptr<EC_AffinePoint_Data> EC_AffinePoint_Data_PC::mul(const EC_Scalar_Data& scalar,
                                                                 RandomNumberGenerator& rng,
                                                                 std::vector<BigInt>& ws) const {
   BOTAN_UNUSED(ws);

   BOTAN_ARG_CHECK(scalar.group() == m_group, "Curve mismatch");
   const auto& k = EC_Scalar_Data_PC::checked_ref(scalar).value();
   auto pt = m_group->pcurve().mul(m_pt, k, rng).to_affine();
   return std::make_unique<EC_AffinePoint_Data_PC>(m_group, std::move(pt));
}

secure_vector<uint8_t> EC_AffinePoint_Data_PC::mul_x_only(const EC_Scalar_Data& scalar,
                                                          RandomNumberGenerator& rng,
                                                          std::vector<BigInt>& ws) const {
   BOTAN_UNUSED(ws);

   BOTAN_ARG_CHECK(scalar.group() == m_group, "Curve mismatch");
   const auto& k = EC_Scalar_Data_PC::checked_ref(scalar).value();
   return m_group->pcurve().mul_x_only(m_pt, k, rng);
}

size_t EC_AffinePoint_Data_PC::field_element_bytes() const {
   return m_group->pcurve().field_element_bytes();
}

bool EC_AffinePoint_Data_PC::is_identity() const {
   return m_xy.empty();
}

void EC_AffinePoint_Data_PC::serialize_x_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == fe_bytes, "Invalid output size");
   copy_mem(bytes, std::span{m_xy}.subspan(1, fe_bytes));
}

void EC_AffinePoint_Data_PC::serialize_y_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == fe_bytes, "Invalid output size");
   copy_mem(bytes, std::span{m_xy}.subspan(1 + fe_bytes, fe_bytes));
}

void EC_AffinePoint_Data_PC::serialize_xy_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == 2 * fe_bytes, "Invalid output size");
   copy_mem(bytes, std::span{m_xy}.last(2 * fe_bytes));
}

void EC_AffinePoint_Data_PC::serialize_compressed_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == 1 + fe_bytes, "Invalid output size");
   const bool y_is_odd = (m_xy.back() & 0x01) == 0x01;

   BufferStuffer stuffer(bytes);
   stuffer.append(y_is_odd ? 0x03 : 0x02);
   this->serialize_x_to(stuffer.next(fe_bytes));
}

void EC_AffinePoint_Data_PC::serialize_uncompressed_to(std::span<uint8_t> bytes) const {
   BOTAN_STATE_CHECK(!this->is_identity());
   const size_t fe_bytes = this->field_element_bytes();
   BOTAN_ARG_CHECK(bytes.size() == 1 + 2 * fe_bytes, "Invalid output size");
   copy_mem(bytes, m_xy);
}

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
EC_Point EC_AffinePoint_Data_PC::to_legacy_point() const {
   if(this->is_identity()) {
      return EC_Point(m_group->curve());
   } else {
      const size_t fe_bytes = this->field_element_bytes();
      return EC_Point(m_group->curve(),
                      BigInt::from_bytes(std::span{m_xy}.subspan(1, fe_bytes)),
                      BigInt::from_bytes(std::span{m_xy}.last(fe_bytes)));
   }
}
#endif

EC_Mul2Table_Data_PC::EC_Mul2Table_Data_PC(const EC_AffinePoint_Data& q) : m_group(q.group()) {
   BOTAN_ARG_CHECK(q.group() == m_group, "Curve mismatch");

   const auto& pt_q = EC_AffinePoint_Data_PC::checked_ref(q);

   m_tbl = m_group->pcurve().mul2_setup_g(pt_q.value());
}

std::unique_ptr<EC_AffinePoint_Data> EC_Mul2Table_Data_PC::mul2_vartime(const EC_Scalar_Data& xd,
                                                                        const EC_Scalar_Data& yd) const {
   BOTAN_ARG_CHECK(xd.group() == m_group && yd.group() == m_group, "Curve mismatch");

   const auto& x = EC_Scalar_Data_PC::checked_ref(xd);
   const auto& y = EC_Scalar_Data_PC::checked_ref(yd);

   if(auto pt = m_group->pcurve().mul2_vartime(*m_tbl, x.value(), y.value())) {
      return std::make_unique<EC_AffinePoint_Data_PC>(m_group, pt->to_affine());
   } else {
      return nullptr;
   }
}

bool EC_Mul2Table_Data_PC::mul2_vartime_x_mod_order_eq(const EC_Scalar_Data& vd,
                                                       const EC_Scalar_Data& xd,
                                                       const EC_Scalar_Data& yd) const {
   BOTAN_ARG_CHECK(xd.group() == m_group && yd.group() == m_group, "Curve mismatch");

   const auto& v = EC_Scalar_Data_PC::checked_ref(vd);
   const auto& x = EC_Scalar_Data_PC::checked_ref(xd);
   const auto& y = EC_Scalar_Data_PC::checked_ref(yd);

   return m_group->pcurve().mul2_vartime_x_mod_order_eq(*m_tbl, v.value(), x.value(), y.value());
}

}  // namespace Botan
