/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008,2018,2024 Jack Lloyd
* (C) 2018 Tobias Niemann
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_group.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/mutex.h>
#include <botan/pem.h>
#include <botan/rng.h>
#include <botan/internal/barrett.h>
#include <botan/internal/ec_inner_data.h>
#include <botan/internal/fmt.h>
#include <botan/internal/primality.h>
#include <map>
#include <vector>

namespace Botan {

class EC_Group_Data_Map final {
   public:
      EC_Group_Data_Map() = default;

      size_t clear() {
         const lock_guard_type<mutex_type> lock(m_mutex);
         const size_t count = m_registered_curves.size();
         m_registered_curves.clear();
         return count;
      }

      bool unregister(const OID& oid) {
         if(oid.empty()) {
            throw Invalid_Argument("OID must not be empty");
         }

         const lock_guard_type<mutex_type> lock(m_mutex);
         return m_registered_curves.erase(oid) > 0;
      }

      std::shared_ptr<const EC_Group_Data> lookup(const OID& oid) {
         const lock_guard_type<mutex_type> lock(m_mutex);

         if(const auto i = m_registered_curves.find(oid); i != m_registered_curves.end()) {
            return i->second;
         }

         // Not found, check hardcoded data
         if(const auto data = EC_Group::EC_group_info(oid)) {
            // The requested OID may be an alias for a curve whose canonical OID differs,
            // in which case the canonical curve may already be registered
            // TODO(Botan4) remove this once we require exactly one canonical OID per curve
            return add(data);
         }

         // Nope, unknown curve
         return {};
      }

      std::shared_ptr<const EC_Group_Data> lookup_or_create(const OID& oid,
                                                            const BigInt& p,
                                                            const BigInt& a,
                                                            const BigInt& b,
                                                            const BigInt& g_x,
                                                            const BigInt& g_y,
                                                            const BigInt& order) {
         BOTAN_ASSERT_NOMSG(oid.has_value());

         const lock_guard_type<mutex_type> lock(m_mutex);

         if(const auto i = m_registered_curves.find(oid); i != m_registered_curves.end()) {
            /*
            * If both OID and params are the same then we are done, just return
            * the already registered curve obj.
            *
            * First verify that the params match, to catch an application
            * that is attempting to register a EC_Group under the same OID as
            * another group currently in use
            */
            if(!i->second->params_match(p, a, b, g_x, g_y, order)) {
               throw Invalid_Argument("Attempting to register a curve using OID " + oid.to_string() +
                                      " but a distinct curve is already registered using that OID");
            }

            return i->second;
         }

         /*
         * Not found in current list, so we need to create a new entry
         */
         const auto new_group = [&] {
            if(auto g = EC_Group::EC_group_info(oid); g != nullptr) {
               /*
               * This turned out to be the OID of one of the builtin groups. Verify
               * that all of the provided parameters match that builtin group.
               */
               BOTAN_ARG_CHECK(g->params_match(p, a, b, g_x, g_y, order),
                               "Attempting to register an EC group under OID of hardcoded group");

               return g;
            } else {
               /*
               * This path is taken for an application registering a new EC_Group with an OID specified
               */
               return EC_Group_Data::create(p, a, b, g_x, g_y, order, oid, EC_Group_Source::ExternalSource);
            }
         }();

         if(new_group->source() != EC_Group_Source::Builtin) {
            BOTAN_ARG_CHECK(EC_Group::verify_generator_order(new_group),
                            "EC_Group generator does not have the claimed order");
         }

         return add(new_group);
      }

      std::shared_ptr<const EC_Group_Data> lookup_from_params(
         const BigInt& p, const BigInt& a, const BigInt& b, std::span<const uint8_t> base_pt, const BigInt& order) {
         const lock_guard_type<mutex_type> lock(m_mutex);

         for(const auto& i : m_registered_curves) {
            if(i.second->params_match(p, a, b, base_pt, order)) {
               return i.second;
            }
         }

         // Try to use the order as a hint to look up the group id
         const OID oid_from_order = EC_Group::EC_group_identity_from_order(order);
         if(oid_from_order.has_value()) {
            const auto new_group = EC_Group::EC_group_info(oid_from_order);

            // Have to check all params in the (unlikely/malicious) event of an order collision
            if(new_group && new_group->params_match(p, a, b, base_pt, order)) {
               return add(new_group);
            }
         }

         return {};
      }

   private:
      // Returns the group already registered under the same OID, if there is one
      // Caller must hold m_mutex
      std::shared_ptr<const EC_Group_Data> add(const std::shared_ptr<const EC_Group_Data>& data) {
         return m_registered_curves.try_emplace(data->oid(), data).first->second;
      }

      mutex_type m_mutex;
      std::map<OID, std::shared_ptr<const EC_Group_Data>> m_registered_curves;
};

//static
EC_Group_Data_Map& EC_Group::ec_group_data() {
   /*
   * This exists purely to ensure the allocator is constructed before g_ec_data,
   * which ensures that its destructor runs after ~g_ec_data is complete.
   */

   static const Allocator_Initializer g_init_allocator;
   static EC_Group_Data_Map g_ec_data;
   return g_ec_data;
}

//static
size_t EC_Group::clear_registered_curve_data() {
   return ec_group_data().clear();
}

//static
std::shared_ptr<EC_Group_Data> EC_Group::load_EC_group_info(const char* p_str,
                                                            const char* a_str,
                                                            const char* b_str,
                                                            const char* g_x_str,
                                                            const char* g_y_str,
                                                            const char* order_str,
                                                            const OID& oid) {
   BOTAN_ARG_CHECK(oid.has_value(), "EC_Group::load_EC_group_info OID must be set");

   const BigInt p(p_str);
   const BigInt a(a_str);
   const BigInt b(b_str);
   const BigInt g_x(g_x_str);
   const BigInt g_y(g_y_str);
   const BigInt order(order_str);

   return EC_Group_Data::create(p, a, b, g_x, g_y, order, oid, EC_Group_Source::Builtin);
}

//static
std::pair<std::shared_ptr<const EC_Group_Data>, bool> EC_Group::DER_decode_EC_group(std::span<const uint8_t> der) {
   BER_Decoder dec(der, BER_Decoder::Limits::DER());

   const auto next_obj_type = dec.peek_next_object().type_tag();

   if(next_obj_type == ASN1_Type::ObjectId) {
      OID oid;
      dec.decode(oid).verify_end();

      const auto data = ec_group_data().lookup(oid);
      if(!data) {
         throw Decoding_Error(fmt("Unknown namedCurve OID '{}'", oid.to_string()));
      }

      return std::make_pair(data, false);
   } else if(next_obj_type == ASN1_Type::Sequence) {
      BigInt p;
      BigInt a;
      BigInt b;
      BigInt order;
      BigInt cofactor;
      std::vector<uint8_t> base_pt;
      std::vector<uint8_t> seed;

      dec.start_sequence()
         .decode_and_check<size_t>(1, "Unknown ECC param version code")
         .start_sequence()
         .decode_and_check(OID({1, 2, 840, 10045, 1, 1}), "Only prime ECC fields supported")
         .decode(p)
         .end_cons()
         .start_sequence()
         .decode_octet_string_bigint(a)
         .decode_octet_string_bigint(b)
         .decode_optional_string(seed, ASN1_Type::BitString, ASN1_Type::BitString, ASN1_Class::Universal)
         .end_cons()
         .decode(base_pt, ASN1_Type::OctetString)
         .decode(order)
         .decode(cofactor)
         .end_cons()
         .verify_end();

      // Only prime order groups are supported
      if(cofactor != 1) {
         throw Decoding_Error("Invalid ECC cofactor parameter");
      }

      if(p.bits() < 112 || p.bits() > 521 || p.signum() < 0) {
         throw Decoding_Error("ECC p parameter is invalid size");
      }

      // A can be zero
      if(a.signum() < 0 || a >= p) {
         throw Decoding_Error("Invalid ECC a parameter");
      }

      // B must be > 0
      //
      // Technically this is not true but we have historically rejected this and
      // nobody has noted it as an issue, so it is retained.
      if(b.signum() <= 0 || b >= p) {
         throw Decoding_Error("Invalid ECC b parameter");
      }

      if(order.signum() <= 0 || order >= 2 * p) {
         throw Decoding_Error("Invalid ECC group order");
      }

      if(p == order) {
         throw Decoding_Error("Anomalous elliptic curves are not supported");
      }

      if(const auto data = ec_group_data().lookup_from_params(p, a, b, base_pt, order)) {
         return std::make_pair(data, true);
      }

      throw Decoding_Error("Explicit ECC parameters do not match any builtin or registered group");
   } else if(next_obj_type == ASN1_Type::Null) {
      throw Decoding_Error("Decoding ImplicitCA ECC parameters is not supported");
   } else {
      throw Decoding_Error(
         fmt("Unexpected tag {} while decoding ECC domain params", asn1_tag_to_string(next_obj_type)));
   }
}

EC_Group::EC_Group() = default;

EC_Group::~EC_Group() = default;

EC_Group::EC_Group(const EC_Group&) = default;

EC_Group& EC_Group::operator=(const EC_Group&) = default;

// Internal constructor
EC_Group::EC_Group(std::shared_ptr<const EC_Group_Data> data) : m_data(std::move(data)) {}

//static
bool EC_Group::verify_generator_order(std::shared_ptr<const EC_Group_Data> data) {
   const EC_Group group(std::move(data));

   auto g_pt = EC_AffinePoint::from_bigint_xy(group, group.get_g_x(), group.get_g_y());
   if(!g_pt) {
      return false;
   }

   Null_RNG null_rng;
   const auto neg_one = EC_Scalar::one(group).negate();
   const auto n_minus_one_g = EC_AffinePoint::g_mul(neg_one, null_rng);
   return n_minus_one_g == g_pt->negate();
}

//static
bool EC_Group::supports_named_group(std::string_view name) {
   if(name.empty()) {
      return false;
   }

   // Is it one of the groups compiled into the library?
   if(EC_Group::known_named_groups().contains(std::string(name))) {
      return true;
   }

   // Is it a custom group registered by the application?
   if(auto oid = OID::from_name(name)) {
      try {
         if(ec_group_data().lookup(oid.value()) != nullptr) {
            return true;
         }
      } catch(Not_Implemented&) {
         // This would be thrown for example if the group is a known curve
         // but the relevant module that enables it is not compiled in
      }
   }

   // Not known
   return false;
}

//static
bool EC_Group::supports_application_specific_group() {
#if defined(BOTAN_HAS_PCURVES_GENERIC)
   return true;
#else
   return false;
#endif
}

//static
EC_Group EC_Group::from_OID(const OID& oid) {
   auto data = ec_group_data().lookup(oid);

   if(!data) {
      throw Invalid_Argument(fmt("No EC_Group associated with OID '{}'", oid.to_string()));
   }

   return EC_Group(std::move(data));
}

//static
EC_Group EC_Group::from_name(std::string_view name) {
   std::shared_ptr<const EC_Group_Data> data;

   if(auto oid = OID::from_name(name)) {
      data = ec_group_data().lookup(oid.value());
   }

   if(!data) {
      throw Invalid_Argument(fmt("Unknown EC_Group '{}'", name));
   }

   return EC_Group(std::move(data));
}

EC_Group::EC_Group(std::string_view str) {
   if(str.empty()) {
      return;  // no initialization / uninitialized
   }

   try {
      const OID oid = OID::from_string(str);
      if(oid.has_value()) {
         m_data = ec_group_data().lookup(oid);
      }
   } catch(...) {}

   if(m_data == nullptr) {
      if(str.size() > 30 && str.starts_with("-----BEGIN EC PARAMETERS-----")) {
         // OK try it as PEM ...
         const auto der = PEM_Code::decode_check_label(str, "EC PARAMETERS");

         const auto data = DER_decode_EC_group(der);
         this->m_data = data.first;
         this->m_explicit_encoding = data.second;
      }
   }

   if(m_data == nullptr) {
      throw Invalid_Argument(fmt("Unknown ECC group '{}'", str));
   }
}

//static
EC_Group EC_Group::from_PEM(std::string_view pem) {
   const auto der = PEM_Code::decode_check_label(pem, "EC PARAMETERS");
   return EC_Group(der);
}

EC_Group::EC_Group(const OID& oid,
                   const BigInt& p,
                   const BigInt& a,
                   const BigInt& b,
                   const BigInt& base_x,
                   const BigInt& base_y,
                   const BigInt& order) :
      EC_Group(std::move(EC_Group::register_custom_group(oid, p, a, b, base_x, base_y, order).m_data)) {}

//static
EC_Group EC_Group::register_custom_group(const OID& oid,
                                         const BigInt& p,
                                         const BigInt& a,
                                         const BigInt& b,
                                         const BigInt& base_x,
                                         const BigInt& base_y,
                                         const BigInt& order) {
   BOTAN_ARG_CHECK(oid.has_value(), "An OID is required for creating an EC_Group");

   // TODO(Botan4) remove this and require 192 bits minimum
#if defined(BOTAN_DISABLE_DEPRECATED_FEATURES)
   constexpr size_t p_bits_lower_bound = 192;
#else
   constexpr size_t p_bits_lower_bound = 128;
#endif

   BOTAN_ARG_CHECK(p.bits() >= p_bits_lower_bound, "EC_Group p too small");
   BOTAN_ARG_CHECK(p.bits() <= 521, "EC_Group p too large");

   if(p.bits() == 521) {
      const auto p521 = BigInt::power_of_2(521) - 1;
      BOTAN_ARG_CHECK(p == p521, "EC_Group with p of 521 bits must be 2**521-1");
   } else if(p.bits() == 239) {
      const auto x962_p239 = []() {
         BigInt p239;
         for(size_t i = 0; i != 239; ++i) {
            if(i < 47 || ((i >= 94) && (i != 143))) {
               p239.set_bit(i);
            }
         }
         return p239;
      }();

      BOTAN_ARG_CHECK(p == x962_p239, "EC_Group with p of 239 bits must be the X9.62 prime");
   } else {
      BOTAN_ARG_CHECK(p.bits() % 32 == 0, "EC_Group p must be a multiple of 32 bits");
   }

   BOTAN_ARG_CHECK(p % 4 == 3, "EC_Group p must be congruent to 3 modulo 4");

   BOTAN_ARG_CHECK(a >= 0 && a < p, "EC_Group a is invalid");
   BOTAN_ARG_CHECK(b > 0 && b < p, "EC_Group b is invalid");
   BOTAN_ARG_CHECK(base_x >= 0 && base_x < p, "EC_Group base_x is invalid");
   BOTAN_ARG_CHECK(base_y >= 0 && base_y < p, "EC_Group base_y is invalid");
   BOTAN_ARG_CHECK(p.bits() == order.bits(), "EC_Group p and order must have the same number of bits");

   const auto mod_p = Barrett_Reduction::for_public_modulus(p);
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime_vartime(p), "EC_Group p is not prime");

   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime_vartime(order), "EC_Group order is not prime");

   BOTAN_ARG_CHECK(p != order, "Anomalous elliptic curves are not supported");

   // This catches someone "ignoring" a cofactor and just trying to
   // provide the subgroup order
   BOTAN_ARG_CHECK((p - order).abs().bits() <= (p.bits() / 2) + 1, "Hasse bound invalid");

   // Check that 4*a^3 + 27*b^2 != 0
   const auto discriminant = mod_p.reduce(mod_p.multiply(BigInt::from_s32(4), mod_p.cube(a)) +
                                          mod_p.multiply(BigInt::from_s32(27), mod_p.square(b)));
   BOTAN_ARG_CHECK(discriminant != 0, "EC_Group discriminant is invalid");

   // Check that the generator (base_x,base_y) is on the curve; y^2 = x^3 + a*x + b
   const auto y2 = mod_p.square(base_y);
   const auto x3_ax_b = mod_p.reduce(mod_p.cube(base_x) + mod_p.multiply(a, base_x) + b);
   BOTAN_ARG_CHECK(y2 == x3_ax_b, "EC_Group generator is not on the curve");

   return EC_Group(ec_group_data().lookup_or_create(oid, p, a, b, base_x, base_y, order));
}

EC_Group::EC_Group(std::span<const uint8_t> der) {
   const auto data = DER_decode_EC_group(der);
   m_data = data.first;
   m_explicit_encoding = data.second;
}

// static
bool EC_Group::unregister(const OID& oid) {
   return ec_group_data().unregister(oid);
}

const EC_Group_Data& EC_Group::data() const {
   if(m_data == nullptr) {
      throw Invalid_State("EC_Group uninitialized");
   }
   return *m_data;
}

size_t EC_Group::get_p_bits() const {
   return data().p_bits();
}

size_t EC_Group::get_p_bytes() const {
   return data().p_bytes();
}

size_t EC_Group::get_order_bits() const {
   return data().order_bits();
}

size_t EC_Group::get_order_bytes() const {
   return data().order_bytes();
}

const BigInt& EC_Group::get_p() const {
   return data().p();
}

const BigInt& EC_Group::get_a() const {
   return data().a();
}

const BigInt& EC_Group::get_b() const {
   return data().b();
}

const BigInt& EC_Group::get_order() const {
   return data().order();
}

const BigInt& EC_Group::get_g_x() const {
   return data().g_x();
}

const BigInt& EC_Group::get_g_y() const {
   return data().g_y();
}

const OID& EC_Group::get_curve_oid() const {
   return data().oid();
}

EC_Group_Source EC_Group::source() const {
   return data().source();
}

EC_Group_Engine EC_Group::engine() const {
   return data().engine();
}

bool EC_Group::hash_to_curve_supported(std::string_view hash_fn) const {
   return data().hash_to_curve_supported(hash_fn);
}

std::vector<uint8_t> EC_Group::DER_encode() const {
   return data().der_named_curve();
}

std::vector<uint8_t> EC_Group::DER_encode(EC_Group_Encoding form) const {
   if(form == EC_Group_Encoding::Explicit) {
      std::vector<uint8_t> output;
      DER_Encoder der(output);
      const size_t ecpVers1 = 1;
      const OID curve_type("1.2.840.10045.1.1");  // prime field

      const size_t p_bytes = get_p_bytes();

      const auto generator = EC_AffinePoint::generator(*this).serialize_uncompressed();

      der.start_sequence()
         .encode(ecpVers1)
         .start_sequence()
         .encode(curve_type)
         .encode(get_p())
         .end_cons()
         .start_sequence()
         .encode(get_a().serialize(p_bytes), ASN1_Type::OctetString)
         .encode(get_b().serialize(p_bytes), ASN1_Type::OctetString)
         .end_cons()
         .encode(generator, ASN1_Type::OctetString)
         .encode(get_order())
         .encode(static_cast<size_t>(1))  // cofactor
         .end_cons();
      return output;
   } else if(form == EC_Group_Encoding::NamedCurve) {
      return this->DER_encode();
   } else if(form == EC_Group_Encoding::ImplicitCA) {
      return {0x00, 0x05};
   } else {
      throw Internal_Error("EC_Group::DER_encode: Unknown encoding");
   }
}

std::string EC_Group::PEM_encode(EC_Group_Encoding form) const {
   const std::vector<uint8_t> der = DER_encode(form);
   return PEM_Code::encode(der, "EC PARAMETERS");
}

bool EC_Group::operator==(const EC_Group& other) const {
   if(m_data == other.m_data) {
      return true;  // same shared rep
   }

   return (get_p() == other.get_p() && get_a() == other.get_a() && get_b() == other.get_b() &&
           get_g_x() == other.get_g_x() && get_g_y() == other.get_g_y() && get_order() == other.get_order());
}

bool EC_Group::verify_group(RandomNumberGenerator& /*rng*/, bool /*strong*/) const {
   // Builtin groups are trusted, and register_custom_group fully validates
   // the parameters of any other group before it can be used
   BOTAN_STATE_CHECK(initialized());
   return true;
}

EC_Group::Mul2Table::Mul2Table(EC_Group::Mul2Table&& other) noexcept = default;

EC_Group::Mul2Table& EC_Group::Mul2Table::operator=(EC_Group::Mul2Table&& other) noexcept = default;

EC_Group::Mul2Table::Mul2Table(const EC_AffinePoint& h) {
   const auto& group = h._group();
   m_tbl = std::make_unique<EC_Mul2Table_Data>(group, group->pcurve().mul2_setup_g(h._inner().value()));
}

EC_Group::Mul2Table::~Mul2Table() = default;

std::optional<EC_AffinePoint> EC_Group::Mul2Table::mul2_vartime(const EC_Scalar& x, const EC_Scalar& y) const {
   const auto& group = m_tbl->group();
   BOTAN_ARG_CHECK(x._inner().group() == group && y._inner().group() == group, "Curve mismatch");

   const auto& pcurve = group->pcurve();

   if(auto pt = pcurve.mul2_vartime(m_tbl->table(), x._inner().value(), y._inner().value())) {
      return EC_AffinePoint::_from_inner(std::make_unique<EC_AffinePoint_Data>(group, pcurve.point_to_affine(*pt)));
   } else {
      return {};
   }
}

bool EC_Group::Mul2Table::mul2_vartime_x_mod_order_eq(const EC_Scalar& v,
                                                      const EC_Scalar& x,
                                                      const EC_Scalar& y) const {
   const auto& group = m_tbl->group();
   BOTAN_ARG_CHECK(x._inner().group() == group && y._inner().group() == group, "Curve mismatch");

   return group->pcurve().mul2_vartime_x_mod_order_eq(
      m_tbl->table(), v._inner().value(), x._inner().value(), y._inner().value());
}

bool EC_Group::Mul2Table::mul2_vartime_x_mod_order_eq(const EC_Scalar& v,
                                                      const EC_Scalar& c,
                                                      const EC_Scalar& x,
                                                      const EC_Scalar& y) const {
   return this->mul2_vartime_x_mod_order_eq(v, c * x, c * y);
}

}  // namespace Botan
