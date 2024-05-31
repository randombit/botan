/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008,2018 Jack Lloyd
* (C) 2018 Tobias Niemann
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_group.h>

#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/mutex.h>
#include <botan/pem.h>
#include <botan/reducer.h>
#include <botan/rng.h>
#include <botan/internal/fmt.h>
#include <botan/internal/point_mul.h>
#include <botan/internal/primality.h>
#include <vector>

#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)
   #include <botan/internal/ec_h2c.h>
#endif

namespace Botan {

class EC_Group_Data final {
   public:
      EC_Group_Data(const BigInt& p,
                    const BigInt& a,
                    const BigInt& b,
                    const BigInt& g_x,
                    const BigInt& g_y,
                    const BigInt& order,
                    const BigInt& cofactor,
                    const OID& oid,
                    EC_Group_Source source) :
            m_curve(p, a, b),
            m_base_point(m_curve, g_x, g_y),
            m_g_x(g_x),
            m_g_y(g_y),
            m_order(order),
            m_cofactor(cofactor),
            m_mod_order(order),
            m_base_mult(m_base_point, m_mod_order),
            m_oid(oid),
            m_p_bits(p.bits()),
            m_order_bits(order.bits()),
            m_a_is_minus_3(a == p - 3),
            m_a_is_zero(a.is_zero()),
            m_source(source) {}

      bool params_match(const BigInt& p,
                        const BigInt& a,
                        const BigInt& b,
                        const BigInt& g_x,
                        const BigInt& g_y,
                        const BigInt& order,
                        const BigInt& cofactor) const {
         return (this->p() == p && this->a() == a && this->b() == b && this->order() == order &&
                 this->cofactor() == cofactor && this->g_x() == g_x && this->g_y() == g_y);
      }

      bool params_match(const EC_Group_Data& other) const {
         return params_match(
            other.p(), other.a(), other.b(), other.g_x(), other.g_y(), other.order(), other.cofactor());
      }

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

      size_t order_bytes() const { return (m_order_bits + 7) / 8; }

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
      bool m_a_is_minus_3;
      bool m_a_is_zero;
      EC_Group_Source m_source;
};

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

         std::shared_ptr<EC_Group_Data> new_group =
            std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, cofactor, oid, source);

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

   return std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, cofactor, oid, EC_Group_Source::Builtin);
}

//static
std::pair<std::shared_ptr<EC_Group_Data>, bool> EC_Group::BER_decode_EC_group(std::span<const uint8_t> bits,
                                                                              EC_Group_Source source) {
   BER_Decoder ber(bits);
   BER_Object obj = ber.get_next_object();

   if(obj.type() == ASN1_Type::ObjectId) {
      OID dom_par_oid;
      BER_Decoder(bits).decode(dom_par_oid);
      return std::make_pair(ec_group_data().lookup(dom_par_oid), false);
   }

   if(obj.type() == ASN1_Type::Sequence) {
      BigInt p, a, b, order, cofactor;
      std::vector<uint8_t> base_pt;
      std::vector<uint8_t> seed;

      BER_Decoder(bits)
         .start_sequence()
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

      if(p.bits() < 112 || p.bits() > 521) {
         throw Decoding_Error("ECC p parameter is invalid size");
      }

      if(p.is_negative() || !is_bailie_psw_probable_prime(p)) {
         throw Decoding_Error("ECC p parameter is not a prime");
      }

      if(a.is_negative() || a >= p) {
         throw Decoding_Error("Invalid ECC a parameter");
      }

      if(b <= 0 || b >= p) {
         throw Decoding_Error("Invalid ECC b parameter");
      }

      if(order <= 0 || !is_bailie_psw_probable_prime(order)) {
         throw Decoding_Error("Invalid ECC order parameter");
      }

      if(cofactor <= 0 || cofactor >= 16) {
         throw Decoding_Error("Invalid ECC cofactor parameter");
      }

      std::pair<BigInt, BigInt> base_xy = Botan::OS2ECP(base_pt.data(), base_pt.size(), p, a, b);

      auto data =
         ec_group_data().lookup_or_create(p, a, b, base_xy.first, base_xy.second, order, cofactor, OID(), source);
      return std::make_pair(data, true);
   }

   if(obj.type() == ASN1_Type::Null) {
      throw Decoding_Error("Cannot handle ImplicitCA ECC parameters");
   } else {
      throw Decoding_Error(fmt("Unexpected tag {} while decoding ECC domain params", asn1_tag_to_string(obj.type())));
   }
}

EC_Group::EC_Group() = default;

EC_Group::~EC_Group() = default;

EC_Group::EC_Group(const EC_Group&) = default;

EC_Group& EC_Group::operator=(const EC_Group&) = default;

// Internal constructor
EC_Group::EC_Group(std::shared_ptr<EC_Group_Data>&& data) : m_data(std::move(data)) {}

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
   BOTAN_ARG_CHECK(p.bits() >= 128, "EC_Group p too small");
   BOTAN_ARG_CHECK(p.bits() <= 521, "EC_Group p too large");

   if(p.bits() == 521) {
      BOTAN_ARG_CHECK(p == BigInt::power_of_2(521) - 1, "EC_Group with p of 521 bits must be 2**521-1");
   } else {
      BOTAN_ARG_CHECK(p.bits() % 32 == 0, "EC_Group p must be a multiple of 32 bits");
   }

   BOTAN_ARG_CHECK(p % 4 == 3, "EC_Group p must be congruent to 3 modulo 4");

   BOTAN_ARG_CHECK(a >= 0 && a < p, "EC_Group a is invalid");
   BOTAN_ARG_CHECK(b > 0 && b < p, "EC_Group b is invalid");
   BOTAN_ARG_CHECK(base_x >= 0 && base_x < p, "EC_Group base_x is invalid");
   BOTAN_ARG_CHECK(base_y >= 0 && base_y < p, "EC_Group base_y is invalid");
   BOTAN_ARG_CHECK(p.bits() == order.bits(), "EC_Group p and order must have the same number of bits");

   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(p), "EC_Group p is not prime");
   BOTAN_ARG_CHECK(is_bailie_psw_probable_prime(order), "EC_Group order is not prime");

   // This catches someone "ignoring" a cofactor and just trying to
   // provide the subgroup order
   BOTAN_ARG_CHECK((p - order).abs().bits() <= (p.bits() / 2) + 1, "Hasse bound invalid");

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

bool EC_Group::a_is_minus_3() const {
   return data().a_is_minus_3();
}

bool EC_Group::a_is_zero() const {
   return data().a_is_zero();
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

const EC_Point& EC_Group::get_base_point() const {
   return data().base_point();
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

const BigInt& EC_Group::get_cofactor() const {
   return data().cofactor();
}

BigInt EC_Group::mod_order(const BigInt& k) const {
   return data().mod_order(k);
}

BigInt EC_Group::square_mod_order(const BigInt& x) const {
   return data().square_mod_order(x);
}

BigInt EC_Group::cube_mod_order(const BigInt& x) const {
   return multiply_mod_order(x, square_mod_order(x));
}

BigInt EC_Group::multiply_mod_order(const BigInt& x, const BigInt& y) const {
   return data().multiply_mod_order(x, y);
}

BigInt EC_Group::multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const {
   return data().multiply_mod_order(x, y, z);
}

BigInt EC_Group::inverse_mod_order(const BigInt& x) const {
   return data().inverse_mod_order(x);
}

const OID& EC_Group::get_curve_oid() const {
   return data().oid();
}

EC_Group_Source EC_Group::source() const {
   return data().source();
}

size_t EC_Group::point_size(EC_Point_Format format) const {
   // Hybrid and standard format are (x,y), compressed is y, +1 format byte
   if(format == EC_Point_Format::Compressed) {
      return (1 + get_p_bytes());
   } else {
      return (1 + 2 * get_p_bytes());
   }
}

EC_Point EC_Group::OS2ECP(const uint8_t bits[], size_t len) const {
   return Botan::OS2ECP(bits, len, data().curve());
}

EC_Point EC_Group::point(const BigInt& x, const BigInt& y) const {
   // TODO: randomize the representation?
   return EC_Point(data().curve(), x, y);
}

EC_Point EC_Group::point_multiply(const BigInt& x, const EC_Point& pt, const BigInt& y) const {
   EC_Point_Multi_Point_Precompute xy_mul(get_base_point(), pt);
   return xy_mul.multi_exp(x, y);
}

EC_Point EC_Group::blinded_base_point_multiply(const BigInt& k,
                                               RandomNumberGenerator& rng,
                                               std::vector<BigInt>& ws) const {
   return data().blinded_base_point_multiply(k, rng, ws);
}

BigInt EC_Group::blinded_base_point_multiply_x(const BigInt& k,
                                               RandomNumberGenerator& rng,
                                               std::vector<BigInt>& ws) const {
   const EC_Point pt = data().blinded_base_point_multiply(k, rng, ws);

   if(pt.is_zero()) {
      return BigInt::zero();
   }
   return pt.get_affine_x();
}

BigInt EC_Group::random_scalar(RandomNumberGenerator& rng) const {
   return BigInt::random_integer(rng, BigInt::one(), get_order());
}

EC_Point EC_Group::blinded_var_point_multiply(const EC_Point& point,
                                              const BigInt& k,
                                              RandomNumberGenerator& rng,
                                              std::vector<BigInt>& ws) const {
   EC_Point_Var_Point_Precompute mul(point, rng, ws);
   // We pass order*cofactor here to "correctly" handle the case where the
   // point is on the curve but not in the prime order subgroup. This only
   // matters for groups with cofactor > 1
   // See https://github.com/randombit/botan/issues/3800
   return mul.mul(k, rng, get_order() * get_cofactor(), ws);
}

EC_Point EC_Group::zero_point() const {
   return EC_Point(data().curve());
}

EC_Point EC_Group::hash_to_curve(std::string_view hash_fn,
                                 const uint8_t input[],
                                 size_t input_len,
                                 std::string_view domain,
                                 bool random_oracle) const {
   return this->hash_to_curve(
      hash_fn, input, input_len, reinterpret_cast<const uint8_t*>(domain.data()), domain.size(), random_oracle);
}

EC_Point EC_Group::hash_to_curve(std::string_view hash_fn,
                                 const uint8_t input[],
                                 size_t input_len,
                                 const uint8_t domain_sep[],
                                 size_t domain_sep_len,
                                 bool random_oracle) const {
#if defined(BOTAN_HAS_EC_HASH_TO_CURVE)

   // Only have SSWU currently
   if(get_a().is_zero() || get_b().is_zero() || get_p() % 4 == 1) {
      throw Not_Implemented("EC_Group::hash_to_curve not available for this curve type");
   }

   return hash_to_curve_sswu(*this, hash_fn, {input, input_len}, {domain_sep, domain_sep_len}, random_oracle);

#else
   BOTAN_UNUSED(hash_fn, random_oracle, input, input_len, domain_sep, domain_sep_len);
   throw Not_Implemented("EC_Group::hash_to_curve functionality not available in this configuration");
#endif
}

std::vector<uint8_t> EC_Group::DER_encode(EC_Group_Encoding form) const {
   std::vector<uint8_t> output;

   DER_Encoder der(output);

   if(form == EC_Group_Encoding::Explicit) {
      const size_t ecpVers1 = 1;
      const OID curve_type("1.2.840.10045.1.1");  // prime field

      const size_t p_bytes = get_p_bytes();

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
         .encode(get_base_point().encode(EC_Point_Format::Uncompressed), ASN1_Type::OctetString)
         .encode(get_order())
         .encode(get_cofactor())
         .end_cons();
   } else if(form == EC_Group_Encoding::NamedCurve) {
      const OID oid = get_curve_oid();
      if(oid.empty()) {
         throw Encoding_Error("Cannot encode EC_Group as OID because OID not set");
      }
      der.encode(oid);
   } else if(form == EC_Group_Encoding::ImplicitCA) {
      der.encode_null();
   } else {
      throw Internal_Error("EC_Group::DER_encode: Unknown encoding");
   }

   return output;
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

   if(get_cofactor() > 1) {
      if((point * get_cofactor()).is_zero()) {
         return false;
      }
   }

   return true;
}

bool EC_Group::verify_group(RandomNumberGenerator& rng, bool strong) const {
   const bool is_builtin = source() == EC_Group_Source::Builtin;

   if(is_builtin && !strong) {
      return true;
   }

   const BigInt& p = get_p();
   const BigInt& a = get_a();
   const BigInt& b = get_b();
   const BigInt& order = get_order();
   const EC_Point& base_point = get_base_point();

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
   const Modular_Reducer mod_p(p);

   const BigInt discriminant = mod_p.reduce(mod_p.multiply(4, mod_p.cube(a)) + mod_p.multiply(27, mod_p.square(b)));

   if(discriminant == 0) {
      return false;
   }

   //check for valid cofactor
   if(get_cofactor() < 1) {
      return false;
   }

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

   // check the Hasse bound (roughly)
   if((p - get_cofactor() * order).abs().bits() > (p.bits() / 2) + 1) {
      return false;
   }

   return true;
}

}  // namespace Botan
