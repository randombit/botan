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
#include <botan/internal/point_mul.h>
#include <botan/internal/primality.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/pem.h>
#include <botan/reducer.h>
#include <botan/mutex.h>
#include <botan/rng.h>
#include <vector>

namespace Botan {

class EC_Group_Data final
   {
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
         m_source(source)
         {
         }

      bool match(const BigInt& p, const BigInt& a, const BigInt& b,
                 const BigInt& g_x, const BigInt& g_y,
                 const BigInt& order, const BigInt& cofactor) const
         {
         return (this->p() == p &&
                 this->a() == a &&
                 this->b() == b &&
                 this->order() == order &&
                 this->cofactor() == cofactor &&
                 this->g_x() == g_x &&
                 this->g_y() == g_y);
         }

      void set_oid(const OID& oid)
         {
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
      const PointGFp& base_point() const { return m_base_point; }

      bool a_is_minus_3() const { return m_a_is_minus_3; }
      bool a_is_zero() const { return m_a_is_zero; }

      BigInt mod_order(const BigInt& x) const { return m_mod_order.reduce(x); }

      BigInt square_mod_order(const BigInt& x) const
         {
         return m_mod_order.square(x);
         }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const
         {
         return m_mod_order.multiply(x, y);
         }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const
         {
         return m_mod_order.multiply(m_mod_order.multiply(x, y), z);
         }

      BigInt inverse_mod_order(const BigInt& x) const
         {
         return inverse_mod(x, m_order);
         }

      PointGFp blinded_base_point_multiply(const BigInt& k,
                                           RandomNumberGenerator& rng,
                                           std::vector<BigInt>& ws) const
         {
         return m_base_mult.mul(k, rng, m_order, ws);
         }

      EC_Group_Source source() const { return m_source; }

   private:
      CurveGFp m_curve;
      PointGFp m_base_point;

      BigInt m_g_x;
      BigInt m_g_y;
      BigInt m_order;
      BigInt m_cofactor;
      Modular_Reducer m_mod_order;
      PointGFp_Base_Point_Precompute m_base_mult;
      OID m_oid;
      size_t m_p_bits;
      size_t m_order_bits;
      bool m_a_is_minus_3;
      bool m_a_is_zero;
      EC_Group_Source m_source;
   };

class EC_Group_Data_Map final
   {
   public:
      EC_Group_Data_Map() {}

      size_t clear()
         {
         lock_guard_type<mutex_type> lock(m_mutex);
         size_t count = m_registered_curves.size();
         m_registered_curves.clear();
         return count;
         }

      std::shared_ptr<EC_Group_Data> lookup(const OID& oid)
         {
         lock_guard_type<mutex_type> lock(m_mutex);

         for(auto i : m_registered_curves)
            {
            if(i->oid() == oid)
               return i;
            }

         // Not found, check hardcoded data
         std::shared_ptr<EC_Group_Data> data = EC_Group::EC_group_info(oid);

         if(data)
            {
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
                                                      EC_Group_Source source)
         {
         lock_guard_type<mutex_type> lock(m_mutex);

         for(auto i : m_registered_curves)
            {
            if(!oid.empty())
               {
               if(i->oid() == oid)
                  {
                  if(!i->match(p, a, b, g_x, g_y, order, cofactor))
                     throw Invalid_Argument("Attempting to register a curve using OID " + oid.to_string() +
                                            " but another curve is already registered using that OID");
                  return i;
                  }
               else if(i->oid().has_value())
                  continue; // distinct OIDs so not a match
               }

            if(i->match(p, a, b, g_x, g_y, order, cofactor))
               {
               /*
               * If the same curve was previously created without an OID
               * but has been registered again using an OID, save that OID.
               */
               if(oid.empty() == false)
                  {
                  if(i->oid().empty() == true)
                     {
                     i->set_oid(oid);
                     }
                  else
                     {
                     throw Invalid_Argument("Cannot register ECC group with OID " + oid.to_string() +
                                            " already registered using " + i->oid().to_string());
                     }
                  }
               return i;
               }
            }

         // Not found - if OID is set try looking up that way

         if(oid.has_value())
            {
            // Not located in existing store - try hardcoded data set
            std::shared_ptr<EC_Group_Data> data = EC_Group::EC_group_info(oid);

            if(data)
               {
               m_registered_curves.push_back(data);
               return data;
               }
            }

         // Not found or no OID, add data and return
         std::shared_ptr<EC_Group_Data> d =
            std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, cofactor, oid, source);

         m_registered_curves.push_back(d);
         return d;
         }

   private:
      mutex_type m_mutex;
      std::vector<std::shared_ptr<EC_Group_Data>> m_registered_curves;
   };

//static
EC_Group_Data_Map& EC_Group::ec_group_data()
   {
   /*
   * This exists purely to ensure the allocator is constructed before g_ec_data,
   * which ensures that its destructor runs after ~g_ec_data is complete.
   */

   static Allocator_Initializer g_init_allocator;
   static EC_Group_Data_Map g_ec_data;
   return g_ec_data;
   }

//static
size_t EC_Group::clear_registered_curve_data()
   {
   return ec_group_data().clear();
   }

//static
std::shared_ptr<EC_Group_Data>
EC_Group::load_EC_group_info(const char* p_str,
                             const char* a_str,
                             const char* b_str,
                             const char* g_x_str,
                             const char* g_y_str,
                             const char* order_str,
                             const OID& oid)
   {
   const BigInt p(p_str);
   const BigInt a(a_str);
   const BigInt b(b_str);
   const BigInt g_x(g_x_str);
   const BigInt g_y(g_y_str);
   const BigInt order(order_str);
   const BigInt cofactor(1); // implicit

   return std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, cofactor, oid, EC_Group_Source::Builtin);
   }

//static
std::shared_ptr<EC_Group_Data> EC_Group::BER_decode_EC_group(const uint8_t bits[], size_t len,
                                                             EC_Group_Source source)
   {
   BER_Decoder ber(bits, len);
   BER_Object obj = ber.get_next_object();

   if(obj.type() == NULL_TAG)
      {
      throw Decoding_Error("Cannot handle ImplicitCA ECC parameters");
      }
   else if(obj.type() == OBJECT_ID)
      {
      OID dom_par_oid;
      BER_Decoder(bits, len).decode(dom_par_oid);
      return ec_group_data().lookup(dom_par_oid);
      }
   else if(obj.type() == SEQUENCE)
      {
      BigInt p, a, b, order, cofactor;
      std::vector<uint8_t> base_pt;
      std::vector<uint8_t> seed;

      BER_Decoder(bits, len)
         .start_cons(SEQUENCE)
           .decode_and_check<size_t>(1, "Unknown ECC param version code")
           .start_cons(SEQUENCE)
            .decode_and_check(OID("1.2.840.10045.1.1"),
                              "Only prime ECC fields supported")
             .decode(p)
           .end_cons()
           .start_cons(SEQUENCE)
             .decode_octet_string_bigint(a)
             .decode_octet_string_bigint(b)
             .decode_optional_string(seed, BIT_STRING, BIT_STRING)
           .end_cons()
           .decode(base_pt, OCTET_STRING)
           .decode(order)
           .decode(cofactor)
         .end_cons()
         .verify_end();

      if(p.bits() < 64 || p.is_negative() || !is_bailie_psw_probable_prime(p))
         throw Decoding_Error("Invalid ECC p parameter");

      if(a.is_negative() || a >= p)
         throw Decoding_Error("Invalid ECC a parameter");

      if(b <= 0 || b >= p)
         throw Decoding_Error("Invalid ECC b parameter");

      if(order <= 0 || !is_bailie_psw_probable_prime(order))
         throw Decoding_Error("Invalid ECC order parameter");

      if(cofactor <= 0 || cofactor >= 16)
         throw Decoding_Error("Invalid ECC cofactor parameter");

      std::pair<BigInt, BigInt> base_xy = Botan::OS2ECP(base_pt.data(), base_pt.size(), p, a, b);

      return ec_group_data().lookup_or_create(p, a, b, base_xy.first, base_xy.second,
                                              order, cofactor, OID(), source);
      }
   else
      {
      throw Decoding_Error("Unexpected tag while decoding ECC domain params");
      }
   }

EC_Group::EC_Group()
   {
   }

EC_Group::~EC_Group()
   {
   // shared_ptr possibly freed here
   }

EC_Group::EC_Group(const OID& domain_oid)
   {
   this->m_data = ec_group_data().lookup(domain_oid);
   if(!this->m_data)
      throw Invalid_Argument("Unknown EC_Group " + domain_oid.to_string());
   }

EC_Group::EC_Group(const std::string& str)
   {
   if(str == "")
      return; // no initialization / uninitialized

   try
      {
      const OID oid = OID::from_string(str);
      if(oid.has_value())
         m_data = ec_group_data().lookup(oid);
      }
   catch(...)
      {
      }

   if(m_data == nullptr)
      {
      if(str.size() > 30 && str.substr(0, 29) == "-----BEGIN EC PARAMETERS-----")
         {
         // OK try it as PEM ...
         secure_vector<uint8_t> ber = PEM_Code::decode_check_label(str, "EC PARAMETERS");
         this->m_data = BER_decode_EC_group(ber.data(), ber.size(), EC_Group_Source::ExternalSource);
         }
      }

   if(m_data == nullptr)
      throw Invalid_Argument("Unknown ECC group '" + str + "'");
   }

//static
EC_Group EC_Group::EC_Group_from_PEM(const std::string& pem)
   {
   const auto ber = PEM_Code::decode_check_label(pem, "EC PARAMETERS");
   return EC_Group(ber.data(), ber.size());
   }

//static
std::string EC_Group::PEM_for_named_group(const std::string& name)
   {
   try
      {
      EC_Group group(name);
      return group.PEM_encode();
      }
   catch(...)
      {
      return "";
      }
   }

EC_Group::EC_Group(const BigInt& p,
                   const BigInt& a,
                   const BigInt& b,
                   const BigInt& base_x,
                   const BigInt& base_y,
                   const BigInt& order,
                   const BigInt& cofactor,
                   const OID& oid)
   {
   m_data = ec_group_data().lookup_or_create(p, a, b, base_x, base_y, order, cofactor, oid,
                                             EC_Group_Source::ExternalSource);
   }

EC_Group::EC_Group(const uint8_t ber[], size_t ber_len)
   {
   m_data = BER_decode_EC_group(ber, ber_len, EC_Group_Source::ExternalSource);
   }

const EC_Group_Data& EC_Group::data() const
   {
   if(m_data == nullptr)
      throw Invalid_State("EC_Group uninitialized");
   return *m_data;
   }

const CurveGFp& EC_Group::get_curve() const
   {
   return data().curve();
   }

bool EC_Group::a_is_minus_3() const
   {
   return data().a_is_minus_3();
   }

bool EC_Group::a_is_zero() const
   {
   return data().a_is_zero();
   }

size_t EC_Group::get_p_bits() const
   {
   return data().p_bits();
   }

size_t EC_Group::get_p_bytes() const
   {
   return data().p_bytes();
   }

size_t EC_Group::get_order_bits() const
   {
   return data().order_bits();
   }

size_t EC_Group::get_order_bytes() const
   {
   return data().order_bytes();
   }

const BigInt& EC_Group::get_p() const
   {
   return data().p();
   }

const BigInt& EC_Group::get_a() const
   {
   return data().a();
   }

const BigInt& EC_Group::get_b() const
   {
   return data().b();
   }

const PointGFp& EC_Group::get_base_point() const
   {
   return data().base_point();
   }

const BigInt& EC_Group::get_order() const
   {
   return data().order();
   }

const BigInt& EC_Group::get_g_x() const
   {
   return data().g_x();
   }

const BigInt& EC_Group::get_g_y() const
   {
   return data().g_y();
   }

const BigInt& EC_Group::get_cofactor() const
   {
   return data().cofactor();
   }

BigInt EC_Group::mod_order(const BigInt& k) const
   {
   return data().mod_order(k);
   }

BigInt EC_Group::square_mod_order(const BigInt& x) const
   {
   return data().square_mod_order(x);
   }

BigInt EC_Group::multiply_mod_order(const BigInt& x, const BigInt& y) const
   {
   return data().multiply_mod_order(x, y);
   }

BigInt EC_Group::multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const
   {
   return data().multiply_mod_order(x, y, z);
   }

BigInt EC_Group::inverse_mod_order(const BigInt& x) const
   {
   return data().inverse_mod_order(x);
   }

const OID& EC_Group::get_curve_oid() const
   {
   return data().oid();
   }

EC_Group_Source EC_Group::source() const
   {
   return data().source();
   }

size_t EC_Group::point_size(PointGFp::Compression_Type format) const
   {
   // Hybrid and standard format are (x,y), compressed is y, +1 format byte
   if(format == PointGFp::COMPRESSED)
      return (1 + get_p_bytes());
   else
      return (1 + 2*get_p_bytes());
   }

PointGFp EC_Group::OS2ECP(const uint8_t bits[], size_t len) const
   {
   return Botan::OS2ECP(bits, len, data().curve());
   }

PointGFp EC_Group::point(const BigInt& x, const BigInt& y) const
   {
   // TODO: randomize the representation?
   return PointGFp(data().curve(), x, y);
   }

PointGFp EC_Group::point_multiply(const BigInt& x, const PointGFp& pt, const BigInt& y) const
   {
   PointGFp_Multi_Point_Precompute xy_mul(get_base_point(), pt);
   return xy_mul.multi_exp(x, y);
   }

PointGFp EC_Group::blinded_base_point_multiply(const BigInt& k,
                                               RandomNumberGenerator& rng,
                                               std::vector<BigInt>& ws) const
   {
   return data().blinded_base_point_multiply(k, rng, ws);
   }

BigInt EC_Group::blinded_base_point_multiply_x(const BigInt& k,
                                               RandomNumberGenerator& rng,
                                               std::vector<BigInt>& ws) const
   {
   const PointGFp pt = data().blinded_base_point_multiply(k, rng, ws);

   if(pt.is_zero())
      return 0;
   return pt.get_affine_x();
   }

BigInt EC_Group::random_scalar(RandomNumberGenerator& rng) const
   {
   return BigInt::random_integer(rng, 1, get_order());
   }

PointGFp EC_Group::blinded_var_point_multiply(const PointGFp& point,
                                              const BigInt& k,
                                              RandomNumberGenerator& rng,
                                              std::vector<BigInt>& ws) const
   {
   PointGFp_Var_Point_Precompute mul(point, rng, ws);
   return mul.mul(k, rng, get_order(), ws);
   }

PointGFp EC_Group::zero_point() const
   {
   return PointGFp(data().curve());
   }

std::vector<uint8_t>
EC_Group::DER_encode(EC_Group_Encoding form) const
   {
   std::vector<uint8_t> output;

   DER_Encoder der(output);

   if(form == EC_DOMPAR_ENC_EXPLICIT)
      {
      const size_t ecpVers1 = 1;
      const OID curve_type("1.2.840.10045.1.1"); // prime field

      const size_t p_bytes = get_p_bytes();

      der.start_cons(SEQUENCE)
            .encode(ecpVers1)
            .start_cons(SEQUENCE)
               .encode(curve_type)
               .encode(get_p())
            .end_cons()
            .start_cons(SEQUENCE)
               .encode(BigInt::encode_1363(get_a(), p_bytes),
                       OCTET_STRING)
               .encode(BigInt::encode_1363(get_b(), p_bytes),
                       OCTET_STRING)
            .end_cons()
              .encode(get_base_point().encode(PointGFp::UNCOMPRESSED), OCTET_STRING)
            .encode(get_order())
            .encode(get_cofactor())
         .end_cons();
      }
   else if(form == EC_DOMPAR_ENC_OID)
      {
      const OID oid = get_curve_oid();
      if(oid.empty())
         {
         throw Encoding_Error("Cannot encode EC_Group as OID because OID not set");
         }
      der.encode(oid);
      }
   else if(form == EC_DOMPAR_ENC_IMPLICITCA)
      {
      der.encode_null();
      }
   else
      {
      throw Internal_Error("EC_Group::DER_encode: Unknown encoding");
      }

   return output;
   }

std::string EC_Group::PEM_encode() const
   {
   const std::vector<uint8_t> der = DER_encode(EC_DOMPAR_ENC_EXPLICIT);
   return PEM_Code::encode(der, "EC PARAMETERS");
   }

bool EC_Group::operator==(const EC_Group& other) const
   {
   if(m_data == other.m_data)
      return true; // same shared rep

   /*
   * No point comparing order/cofactor as they are uniquely determined
   * by the curve equation (p,a,b) and the base point.
   */
   return (get_p() == other.get_p() &&
           get_a() == other.get_a() &&
           get_b() == other.get_b() &&
           get_g_x() == other.get_g_x() &&
           get_g_y() == other.get_g_y());
   }

bool EC_Group::verify_public_element(const PointGFp& point) const
   {
   //check that public point is not at infinity
   if(point.is_zero())
      return false;

   //check that public point is on the curve
   if(point.on_the_curve() == false)
      return false;

   //check that public point has order q
   if((point * get_order()).is_zero() == false)
      return false;

   if(get_cofactor() > 1)
      {
      if((point * get_cofactor()).is_zero())
         return false;
      }

   return true;
   }

bool EC_Group::verify_group(RandomNumberGenerator& rng,
                            bool strong) const
   {
   const bool is_builtin = source() == EC_Group_Source::Builtin;

   if(is_builtin && !strong)
      return true;

   const BigInt& p = get_p();
   const BigInt& a = get_a();
   const BigInt& b = get_b();
   const BigInt& order = get_order();
   const PointGFp& base_point = get_base_point();

   if(p <= 3 || order <= 0)
      return false;
   if(a < 0 || a >= p)
      return false;
   if(b <= 0 || b >= p)
      return false;

   const size_t test_prob = 128;
   const bool is_randomly_generated = is_builtin;

   //check if field modulus is prime
   if(!is_prime(p, rng, test_prob, is_randomly_generated))
      {
      return false;
      }

   //check if order is prime
   if(!is_prime(order, rng, test_prob, is_randomly_generated))
      {
      return false;
      }

   //compute the discriminant: 4*a^3 + 27*b^2 which must be nonzero
   const Modular_Reducer mod_p(p);

   const BigInt discriminant = mod_p.reduce(
      mod_p.multiply(4, mod_p.cube(a)) +
      mod_p.multiply(27, mod_p.square(b)));

   if(discriminant == 0)
      {
      return false;
      }

   //check for valid cofactor
   if(get_cofactor() < 1)
      {
      return false;
      }

   //check if the base point is on the curve
   if(!base_point.on_the_curve())
      {
      return false;
      }
   if((base_point * get_cofactor()).is_zero())
      {
      return false;
      }
   //check if order of the base point is correct
   if(!(base_point * order).is_zero())
      {
      return false;
      }

   return true;
   }

}
