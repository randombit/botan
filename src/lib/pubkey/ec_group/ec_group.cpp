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
#include <botan/oids.h>
#include <botan/pem.h>
#include <botan/reducer.h>
#include <botan/mutex.h>
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
                    const OID& oid) :
         m_curve(p, a, b),
         m_base_point(m_curve, g_x, g_y),
         m_order(order),
         m_cofactor(cofactor),
         m_mod_order(order),
         m_oid(oid),
         m_p_bits(p.bits()),
         m_order_bits(order.bits())
         {
         }

      bool match(const BigInt& p, const BigInt& a, const BigInt& b,
                 const BigInt& g_x, const BigInt& g_y,
                 const BigInt& order, const BigInt& cofactor) const
         {
         return (this->p() == p && this->a() == a && this->b() == b &&
                 this->order() == order && this->cofactor() == cofactor &&
                 this->g_x() == g_x && this->g_y() == g_y);
         }

      const OID& oid() const { return m_oid; }
      const BigInt& p() const { return m_curve.get_p(); }
      const BigInt& a() const { return m_curve.get_a(); }
      const BigInt& b() const { return m_curve.get_b(); }
      const BigInt& order() const { return m_order; }
      const BigInt& cofactor() const { return m_cofactor; }
      BigInt g_x() const { return m_base_point.get_affine_x(); }
      BigInt g_y() const { return m_base_point.get_affine_y(); }

      size_t p_bits() const { return m_p_bits; }
      size_t p_bytes() const { return (m_p_bits + 7) / 8; }

      size_t order_bits() const { return m_order_bits; }
      size_t order_bytes() const { return (m_order_bits + 7) / 8; }

      const CurveGFp& curve() const { return m_curve; }
      const PointGFp& base_point() const { return m_base_point; }

      BigInt mod_order(const BigInt& x) const { return m_mod_order.reduce(x); }

      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const
         {
         return m_mod_order.multiply(x, y);
         }

   private:
      CurveGFp m_curve;
      PointGFp m_base_point;
      BigInt m_order;
      BigInt m_cofactor;
      Modular_Reducer m_mod_order;
      OID m_oid;
      size_t m_p_bits;
      size_t m_order_bits;
   };

class EC_Group_Data_Map final
   {
   public:
      EC_Group_Data_Map() {}

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
                                                      const OID& oid)
         {
         lock_guard_type<mutex_type> lock(m_mutex);

         for(auto i : m_registered_curves)
            {
            if(oid.has_value())
               {
               if(i->oid() == oid)
                  return i;
               else if(i->oid().has_value())
                  continue;
               }

            if(i->match(p, a, b, g_x, g_y, order, cofactor))
               return i;
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
         return add_curve(p, a, b, g_x, g_y, order, cofactor, oid);
         }

   private:

      std::shared_ptr<EC_Group_Data> add_curve(const BigInt& p,
                                               const BigInt& a,
                                               const BigInt& b,
                                               const BigInt& g_x,
                                               const BigInt& g_y,
                                               const BigInt& order,
                                               const BigInt& cofactor,
                                               const OID& oid)
         {
         std::shared_ptr<EC_Group_Data> d =
            std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, cofactor, oid);

         // This function is always called with the lock held
         m_registered_curves.push_back(d);
         return d;
         }

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

   return std::make_shared<EC_Group_Data>(p, a, b, g_x, g_y, order, cofactor, oid);
   }

//static
std::shared_ptr<EC_Group_Data> EC_Group::BER_decode_EC_group(const uint8_t bits[], size_t len)
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
           .end_cons()
           .decode(base_pt, OCTET_STRING)
           .decode(order)
           .decode(cofactor)
         .end_cons()
         .verify_end();

      if(p.bits() < 64 || p.is_negative() || a.is_negative() || b.is_negative() || order <= 0 || cofactor <= 0)
         throw Decoding_Error("Invalid ECC parameters");

      std::pair<BigInt, BigInt> base_xy = Botan::OS2ECP(base_pt.data(), base_pt.size(), p, a, b);

      return ec_group_data().lookup_or_create(p, a, b, base_xy.first, base_xy.second, order, cofactor, OID());
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
      throw Invalid_Argument("Unknown EC_Group " + domain_oid.as_string());
   }

EC_Group::EC_Group(const std::string& str)
   {
   if(str == "")
      return; // no initialization / uninitialized

   try
      {
      OID oid = OIDS::lookup(str);
      if(oid.empty() == false)
         m_data = ec_group_data().lookup(oid);
      }
   catch(Invalid_OID)
      {
      }

   if(m_data == nullptr)
      {
      // OK try it as PEM ...
      secure_vector<uint8_t> ber = PEM_Code::decode_check_label(str, "EC PARAMETERS");
      this->m_data = BER_decode_EC_group(ber.data(), ber.size());
      }
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
   m_data = ec_group_data().lookup_or_create(p, a, b, base_x, base_y, order, cofactor, oid);
   }

EC_Group::EC_Group(const std::vector<uint8_t>& ber)
   {
   m_data = BER_decode_EC_group(ber.data(), ber.size());
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

const BigInt& EC_Group::get_cofactor() const
   {
   return data().cofactor();
   }

BigInt EC_Group::mod_order(const BigInt& k) const
   {
   return data().mod_order(k);
   }

BigInt EC_Group::multiply_mod_order(const BigInt& x, const BigInt& y) const
   {
   return data().multiply_mod_order(x, y);
   }

const OID& EC_Group::get_curve_oid() const
   {
   return data().oid();
   }

PointGFp EC_Group::OS2ECP(const uint8_t bits[], size_t len) const
   {
   return Botan::OS2ECP(bits, len, data().curve());
   }

PointGFp EC_Group::point(const BigInt& x, const BigInt& y) const
   {
   return PointGFp(data().curve(), x, y);
   }

PointGFp EC_Group::point_multiply(const BigInt& x, const PointGFp& pt, const BigInt& y) const
   {
   return multi_exponentiate(get_base_point(), x, pt, y);
   }

PointGFp EC_Group::zero_point() const
   {
   return PointGFp(data().curve());
   }

std::vector<uint8_t>
EC_Group::DER_encode(EC_Group_Encoding form) const
   {
   if(form == EC_DOMPAR_ENC_EXPLICIT)
      {
      const size_t ecpVers1 = 1;
      OID curve_type("1.2.840.10045.1.1"); // prime field

      const size_t p_bytes = get_p_bytes();

      return DER_Encoder()
         .start_cons(SEQUENCE)
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
            .encode(EC2OSP(get_base_point(), PointGFp::UNCOMPRESSED), OCTET_STRING)
            .encode(get_order())
            .encode(get_cofactor())
         .end_cons()
         .get_contents_unlocked();
      }
   else if(form == EC_DOMPAR_ENC_OID)
      {
      const OID oid = get_curve_oid();
      if(oid.empty())
         {
         throw Encoding_Error("Cannot encode EC_Group as OID because OID not set");
         }
      return DER_Encoder().encode(oid).get_contents_unlocked();
      }
   else if(form == EC_DOMPAR_ENC_IMPLICITCA)
      return DER_Encoder().encode_null().get_contents_unlocked();
   else
      throw Internal_Error("EC_Group::DER_encode: Unknown encoding");
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
           get_base_point() == other.get_base_point());
   }

bool EC_Group::verify_group(RandomNumberGenerator& rng,
                            bool) const
   {
   //compute the discriminant
   Modular_Reducer p(get_p());
   BigInt discriminant = p.multiply(4, get_a());
   discriminant += p.multiply(27, get_b());
   discriminant = p.reduce(discriminant);
   //check the discriminant
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
   if(!get_base_point().on_the_curve())
      {
      return false;
      }
   if((get_base_point() * get_cofactor()).is_zero())
      {
      return false;
      }
   //check if order is prime
   if(!is_prime(get_order(), rng, 128))
      {
      return false;
      }
   //check if order of the base point is correct
   if(!(get_base_point() * get_order()).is_zero())
      {
      return false;
      }
   return true;
   }

}
