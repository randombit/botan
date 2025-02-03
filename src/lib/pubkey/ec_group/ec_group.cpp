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
#include <botan/numthry.h>
#include <botan/pem.h>
#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/internal/ec_inner_data.h>
#include <botan/internal/fmt.h>
#include <botan/internal/primality.h>
#include <vector>

namespace Botan {

class EC_Group_Data_Map final {
   public:
      EC_Group_Data_Map() = default;

      size_t clear() {
         lock_guard_type<mutex_type> lock(m_mutex);
         size_t count = m_registered_curves.size();
         m_registered_curves.clear();
         return count;
      }

      std::shared_ptr<EC_Group_Data> lookup(const OID& oid) {
         lock_guard_type<mutex_type> lock(m_mutex);

         for(auto i : m_registered_curves) {
            if(i->oid() == oid) {
               return i;
            }
         }

         // Not found, check hardcoded data
         std::shared_ptr<EC_Group_Data> data = EC_Group::EC_group_info(oid);

         if(data) {
            for(auto curve : m_registered_curves) {
               if(curve->oid().empty() == true && curve->params_match(*data)) {
                  curve->set_oid(oid);
                  return curve;
               }
            }

            m_registered_curves.push_back(data);
            return data;
         }

         // Nope, unknown curve
         return std::shared_ptr<EC_Group_Data>();
      }

      std::shared_ptr<EC_Group_Data> lookup_or_create(const BigInt& p,
                                                      const BigInt& a,
                                                      const BigInt& b,
                                                      const BigInt& g_x,
                                                      const BigInt& g_y,
                                                      const BigInt& order,
                                                      const BigInt& cofactor,
                                                      const OID& oid,
                                                      EC_Group_Source source) {
         lock_guard_type<mutex_type> lock(m_mutex);

         for(auto i : m_registered_curves) {
            /*
            * The params may be the same but you are trying to register under a
            * different OID than the one we are using, so using a different
            * group, since EC_Group's model assumes a single OID per group.
            */
            if(!oid.empty() && !i->oid().empty() && i->oid() != oid) {
               continue;
            }

            const bool same_oid = !oid.empty() && i->oid() == oid;
            const bool same_params = i->params_match(p, a, b, g_x, g_y, order, cofactor);

            /*
            * If the params and OID are the same then we are done, just return
            * the already registered curve obj.
            */
            if(same_params && same_oid) {
               return i;
            }

            /*
            * If same params and the new OID is empty, then that's ok too
            */
            if(same_params && oid.empty()) {
               return i;
            }

            /*
            * Check for someone trying to reuse an already in-use OID
            */
            if(same_oid && !same_params) {
               throw Invalid_Argument("Attempting to register a curve using OID " + oid.to_string() +
                                      " but a distinct curve is already registered using that OID");
            }

            /*
            * If the same curve was previously created without an OID but is now
            * being registered again using an OID, save that OID.
            */
            if(same_params && i->oid().empty() && !oid.empty()) {
               i->set_oid(oid);
               return i;
            }
         }

         /*
         Not found in current list, so we need to create a new entry

         If an OID is set, try to look up relative our static tables to detect a duplicate
         registration under an OID
         */

         auto new_group = EC_Group_Data::create(p, a, b, g_x, g_y, order, cofactor, oid, source);

         if(oid.has_value()) {
            std::shared_ptr<EC_Group_Data> data = EC_Group::EC_group_info(oid);
            if(data != nullptr && !new_group->params_match(*data)) {
               throw Invalid_Argument("Attempting to register an EC group under OID of hardcoded group");
            }
         } else {
            // Here try to use the order as a hint to look up the group id, to identify common groups
            const OID oid_from_store = EC_Group::EC_group_identity_from_order(order);
            if(oid_from_store.has_value()) {
               std::shared_ptr<EC_Group_Data> data = EC_Group::EC_group_info(oid_from_store);

               /*
               If EC_group_identity_from_order returned an OID then looking up that OID
               must always return a result.
               */
               BOTAN_ASSERT_NOMSG(data != nullptr);

               /*
               It is possible (if unlikely) that someone is registering another group
               that happens to have an order equal to that of a well known group -
               so verify all values before assigning the OID.
               */
               if(new_group->params_match(*data)) {
                  new_group->set_oid(oid_from_store);
               }
            }
         }

         m_registered_curves.push_back(new_group);
         return new_group;
      }

   private:
      mutex_type m_mutex;
      std::vector<std::shared_ptr<EC_Group_Data>> m_registered_curves;
};

//static
EC_Group_Data_Map& EC_Group::ec_group_data() {
   /*
   * This exists purely to ensure the allocator is constructed before g_ec_data,
   * which ensures that its destructor runs after ~g_ec_data is complete.
   */

   static Allocator_Initializer g_init_allocator;
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
   const BigInt p(p_str);
   const BigInt a(a_str);
   const BigInt b(b_str);
   const BigInt g_x(g_x_str);
   const BigInt g_y(g_y_str);
   const BigInt order(order_str);
   const BigInt cofactor(1);  // implicit

   return EC_Group_Data::create(p, a, b, g_x, g_y, order, cofactor, oid, EC_Group_Source::Builtin);
}

//static
std::pair<std::shared_ptr<EC_Group_Data>, bool> EC_Group::BER_decode_EC_group(std::span<const uint8_t> bits,
                                                                              EC_Group_Source source) {
   BER_Decoder ber(bits);

   auto next_obj_type = ber.peek_next_object().type_tag();

   if(next_obj_type == ASN1_Type::ObjectId) {
      OID oid;
      ber.decode(oid);

      auto data = ec_group_data().lookup(oid);
      if(!data) {
         throw Decoding_Error(fmt("Unknown namedCurve OID '{}'", oid.to_string()));
      }

      return std::make_pair(data, false);
   } else if(next_obj_type == ASN1_Type::Sequence) {
      BigInt p, a, b, order, cofactor;
      std::vector<uint8_t> base_pt;
      std::vector<uint8_t> seed;

      ber.start_sequence()
         .decode_and_check<size_t>(1, "Unknown ECC param version code")
         .start_sequence()
         .decode_and_check(OID("1.2.840.10045.1.1"), "Only prime ECC fields supported")
         .decode(p)
         .end_cons()
         .start_sequence()
         .decode_octet_string_bigint(a)
         .decode_octet_string_bigint(b)
         .decode_optional_string(seed, ASN1_Type::BitString, ASN1_Type::BitString)
         .end_cons()
         .decode(base_pt, ASN1_Type::OctetString)
         .decode(order)
         .decode(cofactor)
         .end_cons()
         .verify_end();

      if(p.bits() < 112 || p.bits() > 521 || p.is_negative()) {
         throw Decoding_Error("ECC p parameter is invalid size");
      }

      auto mod_p = Modular_Reducer::for_public_modulus(p);
      if(!is_bailie_psw_probable_prime(p, mod_p)) {
         throw Decoding_Error("ECC p parameter is not a prime");
      }

      if(a.is_negative() || a >= p) {
         throw Decoding_Error("Invalid ECC a parameter");
      }

      if(b <= 0 || b >= p) {
         throw Decoding_Error("Invalid ECC b parameter");
      }

      if(order.is_negative() || order.is_zero() || order >= 2 * p) {
         throw Decoding_Error("Invalid ECC group order");
      }

      auto mod_order = Modular_Reducer::for_public_modulus(order);
      if(!is_bailie_psw_probable_prime(order, mod_order)) {
         throw Decoding_Error("Invalid ECC order parameter");
      }

      if(cofactor <= 0 || cofactor >= 16) {
         throw Decoding_Error("Invalid ECC cofactor parameter");
      }

      const size_t p_bytes = p.bytes();
      if(base_pt.size() != 1 + p_bytes && base_pt.size() != 1 + 2 * p_bytes) {
         throw Decoding_Error("Invalid ECC base point encoding");
      }

      auto [g_x, g_y] = [&]() {
         const uint8_t hdr = base_pt[0];

         if(hdr == 0x04 && base_pt.size() == 1 + 2 * p_bytes) {
            BigInt x = BigInt::decode(&base_pt[1], p_bytes);
            BigInt y = BigInt::decode(&base_pt[p_bytes + 1], p_bytes);

            if(x < p && y < p) {
               return std::make_pair(x, y);
            }
         } else if((hdr == 0x02 || hdr == 0x03) && base_pt.size() == 1 + p_bytes) {
            BigInt x = BigInt::decode(&base_pt[1], p_bytes);
            BigInt y = sqrt_modulo_prime(((x * x + a) * x + b) % p, p);

            if(x < p && y >= 0) {
               const bool y_mod_2 = (hdr & 0x01) == 1;
               if(y.get_bit(0) != y_mod_2) {
                  y = p - y;
               }

               return std::make_pair(x, y);
            }
         }

         throw Decoding_Error("Invalid ECC base point encoding");
      }();

      auto y2 = mod_p.square(g_y);
      auto x3_ax_b = mod_p.reduce(mod_p.cube(g_x) + mod_p.multiply(a, g_x) + b);
      if(y2 != x3_ax_b) {
         throw Decoding_Error("Invalid ECC base point");
      }

      auto data = ec_group_data().lookup_or_create(p, a, b, g_x, g_y, order, cofactor, OID(), source);
      return std::make_pair(data, true);
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
EC_Group::EC_Group(std::shared_ptr<EC_Group_Data>&& data) : m_data(std::move(data)) {}

//static
bool EC_Group::supports_application_specific_group() {
#if defined(BOTAN_HAS_LEGACY_EC_POINT) || defined(BOTAN_HAS_PCURVES_GENERIC)
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
   std::shared_ptr<EC_Group_Data> data;

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
      if(str.size() > 30 && str.substr(0, 29) == "-----BEGIN EC PARAMETERS-----") {
         // OK try it as PEM ...
         const auto ber = PEM_Code::decode_check_label(str, "EC PARAMETERS");

         auto data = BER_decode_EC_group(ber, EC_Group_Source::ExternalSource);
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
   const auto ber = PEM_Code::decode_check_label(pem, "EC PARAMETERS");
   return EC_Group(ber);
}

EC_Group::EC_Group(const BigInt& p,
                   const BigInt& a,
                   const BigInt& b,
                   const BigInt& base_x,
                   const BigInt& base_y,
                   const BigInt& order,
                   const BigInt& cofactor,
                   const OID& oid) {
   m_data =
      ec_group_data().lookup_or_create(p, a, b, base_x, base_y, order, cofactor, oid, EC_Group_Source::ExternalSource);
}

EC_Group::EC_Group(const OID& oid,
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

   auto mod_p = Modular_Reducer::for_public_modulus(p);
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(p, mod_p), "EC_Group p is not prime");

   auto mod_order = Modular_Reducer::for_public_modulus(order);
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(order, mod_order), "EC_Group order is not prime");

   // This catches someone "ignoring" a cofactor and just trying to
   // provide the subgroup order
   BOTAN_ARG_CHECK((p - order).abs().bits() <= (p.bits() / 2) + 1, "Hasse bound invalid");

   // Check that 4*a^3 + 27*b^2 != 0
   const auto discriminant = mod_p.reduce(mod_p.multiply(4, mod_p.cube(a)) + mod_p.multiply(27, mod_p.square(b)));
   BOTAN_ARG_CHECK(discriminant != 0, "EC_Group discriminant is invalid");

   // Check that the generator (base_x,base_y) is on the curve; y^2 = x^3 + a*x + b
   auto y2 = mod_p.square(base_y);
   auto x3_ax_b = mod_p.reduce(mod_p.cube(base_x) + mod_p.multiply(a, base_x) + b);
   BOTAN_ARG_CHECK(y2 == x3_ax_b, "EC_Group generator is not on the curve");

   BigInt cofactor(1);

   m_data =
      ec_group_data().lookup_or_create(p, a, b, base_x, base_y, order, cofactor, oid, EC_Group_Source::ExternalSource);
}

EC_Group::EC_Group(std::span<const uint8_t> ber) {
   auto data = BER_decode_EC_group(ber, EC_Group_Source::ExternalSource);
   m_data = data.first;
   m_explicit_encoding = data.second;
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

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
const EC_Point& EC_Group::get_base_point() const {
   return data().base_point();
}

const EC_Point& EC_Group::generator() const {
   return data().base_point();
}

bool EC_Group::verify_public_element(const EC_Point& point) const {
   //check that public point is not at infinity
   if(point.is_zero()) {
      return false;
   }

   //check that public point is on the curve
   if(point.on_the_curve() == false) {
      return false;
   }

   //check that public point has order q
   if((point * get_order()).is_zero() == false) {
      return false;
   }

   if(has_cofactor()) {
      if((point * get_cofactor()).is_zero()) {
         return false;
      }
   }

   return true;
}

#endif

const BigInt& EC_Group::get_order() const {
   return data().order();
}

const BigInt& EC_Group::get_g_x() const {
   return data().g_x();
}

const BigInt& EC_Group::get_g_y() const {
   return data().g_y();
}

const BigInt& EC_Group::get_cofactor() const {
   return data().cofactor();
}

bool EC_Group::has_cofactor() const {
   return data().has_cofactor();
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

std::vector<uint8_t> EC_Group::DER_encode() const {
   const auto& der_named_curve = data().der_named_curve();
   // TODO(Botan4) this can be removed because an OID will always be defined
   if(der_named_curve.empty()) {
      throw Encoding_Error("Cannot encode EC_Group as OID because OID not set");
   }

   return der_named_curve;
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
         .encode(get_cofactor())
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

std::string EC_Group::PEM_encode() const {
   const std::vector<uint8_t> der = DER_encode(EC_Group_Encoding::Explicit);
   return PEM_Code::encode(der, "EC PARAMETERS");
}

bool EC_Group::operator==(const EC_Group& other) const {
   if(m_data == other.m_data) {
      return true;  // same shared rep
   }

   return (get_p() == other.get_p() && get_a() == other.get_a() && get_b() == other.get_b() &&
           get_g_x() == other.get_g_x() && get_g_y() == other.get_g_y() && get_order() == other.get_order() &&
           get_cofactor() == other.get_cofactor());
}

bool EC_Group::verify_group(RandomNumberGenerator& rng, bool strong) const {
   const bool is_builtin = source() == EC_Group_Source::Builtin;

   if(is_builtin && !strong) {
      return true;
   }

   // TODO(Botan4) this can probably all be removed once the deprecated EC_Group
   // constructor is removed, since at that point it no longer becomes possible
   // to create an EC_Group which fails to satisfy these conditions

   const BigInt& p = get_p();
   const BigInt& a = get_a();
   const BigInt& b = get_b();
   const BigInt& order = get_order();

   if(p <= 3 || order <= 0) {
      return false;
   }
   if(a < 0 || a >= p) {
      return false;
   }
   if(b <= 0 || b >= p) {
      return false;
   }

   const size_t test_prob = 128;
   const bool is_randomly_generated = is_builtin;

   //check if field modulus is prime
   if(!is_prime(p, rng, test_prob, is_randomly_generated)) {
      return false;
   }

   //check if order is prime
   if(!is_prime(order, rng, test_prob, is_randomly_generated)) {
      return false;
   }

   //compute the discriminant: 4*a^3 + 27*b^2 which must be nonzero
   auto mod_p = Modular_Reducer::for_public_modulus(p);

   const BigInt discriminant = mod_p.reduce(mod_p.multiply(4, mod_p.cube(a)) + mod_p.multiply(27, mod_p.square(b)));

   if(discriminant == 0) {
      return false;
   }

   //check for valid cofactor
   if(get_cofactor() < 1) {
      return false;
   }

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
   const EC_Point& base_point = get_base_point();
   //check if the base point is on the curve
   if(!base_point.on_the_curve()) {
      return false;
   }
   if((base_point * get_cofactor()).is_zero()) {
      return false;
   }
   //check if order of the base point is correct
   if(!(base_point * order).is_zero()) {
      return false;
   }
#endif

   // check the Hasse bound (roughly)
   if((p - get_cofactor() * order).abs().bits() > (p.bits() / 2) + 1) {
      return false;
   }

   return true;
}

EC_Group::Mul2Table::Mul2Table(const EC_AffinePoint& h) : m_tbl(h._group()->make_mul2_table(h._inner())) {}

EC_Group::Mul2Table::~Mul2Table() = default;

std::optional<EC_AffinePoint> EC_Group::Mul2Table::mul2_vartime(const EC_Scalar& x, const EC_Scalar& y) const {
   auto pt = m_tbl->mul2_vartime(x._inner(), y._inner());
   if(pt) {
      return EC_AffinePoint::_from_inner(std::move(pt));
   } else {
      return {};
   }
}

bool EC_Group::Mul2Table::mul2_vartime_x_mod_order_eq(const EC_Scalar& v,
                                                      const EC_Scalar& x,
                                                      const EC_Scalar& y) const {
   return m_tbl->mul2_vartime_x_mod_order_eq(v._inner(), x._inner(), y._inner());
}

bool EC_Group::Mul2Table::mul2_vartime_x_mod_order_eq(const EC_Scalar& v,
                                                      const EC_Scalar& c,
                                                      const EC_Scalar& x,
                                                      const EC_Scalar& y) const {
   return this->mul2_vartime_x_mod_order_eq(v, c * x, c * y);
}

}  // namespace Botan
