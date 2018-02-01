/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ec_group.h>
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/pem.h>
#include <botan/reducer.h>

namespace Botan {

struct EC_Group_Data
   {
   CurveGFp m_curve;
   PointGFp m_base_point;
   BigInt m_order;
   BigInt m_cofactor;
   OID m_oid;
   size_t m_p_bits, m_p_bytes;
   };

namespace {

std::shared_ptr<EC_Group_Data> new_EC_group_data(const BigInt& p,
                                                 const BigInt& a,
                                                 const BigInt& b,
                                                 const BigInt& g_x,
                                                 const BigInt& g_y,
                                                 const BigInt& order,
                                                 const BigInt& cofactor,
                                                 const OID& oid = OID())
   {
   std::shared_ptr<EC_Group_Data> data = std::make_shared<EC_Group_Data>();

   data->m_curve = CurveGFp(p, a, b);
   data->m_base_point = PointGFp(data->m_curve, g_x, g_y);
   data->m_order = order;
   data->m_cofactor = cofactor;
   data->m_oid = oid;

   data->m_p_bits = p.bits();
   data->m_p_bytes = p.bytes();
   return data;
   }

std::shared_ptr<EC_Group_Data> new_EC_group_data(const BigInt& p,
                                                 const BigInt& a,
                                                 const BigInt& b,
                                                 const std::vector<uint8_t>& base_point,
                                                 const BigInt& order,
                                                 const BigInt& cofactor,
                                                 const OID& oid = OID())
   {
   std::shared_ptr<EC_Group_Data> data = std::make_shared<EC_Group_Data>();

   data->m_curve = CurveGFp(p, a, b);
   data->m_base_point = Botan::OS2ECP(base_point, data->m_curve);
   data->m_order = order;
   data->m_cofactor = cofactor;
   data->m_oid = oid;

   data->m_p_bits = p.bits();
   data->m_p_bytes = p.bytes();
   return data;
   }

std::shared_ptr<EC_Group_Data> lookup_EC_group_by_oid(const OID& oid);

std::shared_ptr<EC_Group_Data> BER_decode_EC_group(const uint8_t bits[], size_t len)
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
      return lookup_EC_group_by_oid(dom_par_oid);
      }
   else if(obj.type() == SEQUENCE)
      {
      BigInt p, a, b, order, cofactor;
      std::vector<uint8_t> sv_base_point;

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
           .decode(sv_base_point, OCTET_STRING)
           .decode(order)
           .decode(cofactor)
         .end_cons()
         .verify_end();

      return new_EC_group_data(p, a, b, sv_base_point, order, cofactor);
      }
   else
      {
      throw Decoding_Error("Unexpected tag while decoding ECC domain params");
      }
   }

std::shared_ptr<EC_Group_Data> BER_decode_EC_group(const std::string& pem)
   {
   secure_vector<uint8_t> ber = PEM_Code::decode_check_label(pem, "EC PARAMETERS");
   return BER_decode_EC_group(ber.data(), ber.size());
   }

std::shared_ptr<EC_Group_Data> lookup_EC_group_by_oid(const OID& oid)
   {
   if(oid.empty())
      throw Invalid_Argument("lookup_EC_group_by_oid with empty oid");

   const std::string oid_name = OIDS::oid2str(oid);
   if(oid_name.empty())
      throw Invalid_Argument("Unknown EC group OID " + oid.as_string());

   const std::string pem = EC_Group::PEM_for_named_group(oid_name);
   if(pem.empty())
      throw Invalid_Argument("EC group OID (" + oid_name + ") is not known");
   std::shared_ptr<EC_Group_Data> data = BER_decode_EC_group(pem);
   data->m_oid = oid;
   return data;
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
   this->m_data = lookup_EC_group_by_oid(domain_oid);
   }

EC_Group::EC_Group(const std::string& str)
   {
   if(str == "")
      return; // no initialization / uninitialized

   try
      {
      OID oid = OIDS::lookup(str);
      if(oid.empty() == false)
         m_data = lookup_EC_group_by_oid(oid);
      }
   catch(Invalid_OID)
      {
      }

   if(m_data == nullptr)
      {
      // OK try it as PEM ...
      this->m_data = BER_decode_EC_group(str);
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
   m_data = new_EC_group_data(p, a, b, base_x, base_y, order, cofactor, oid);
   }

EC_Group::EC_Group(const CurveGFp& curve,
                   const PointGFp& base_point,
                   const BigInt& order,
                   const BigInt& cofactor)
   {
   m_data = new_EC_group_data(curve.get_p(),
                              curve.get_a(),
                              curve.get_b(),
                              base_point.get_affine_x(),
                              base_point.get_affine_y(),
                              order,
                              cofactor);
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
   return data().m_curve;
   }

size_t EC_Group::get_p_bits() const
   {
   return data().m_p_bits;
   }

size_t EC_Group::get_p_bytes() const
   {
   return data().m_p_bytes;
   }

const BigInt& EC_Group::get_p() const
   {
   return data().m_curve.get_p();
   }

const BigInt& EC_Group::get_a() const
   {
   return data().m_curve.get_a();
   }

const BigInt& EC_Group::get_b() const
   {
   return data().m_curve.get_b();
   }

const PointGFp& EC_Group::get_base_point() const
   {
   return data().m_base_point;
   }

const BigInt& EC_Group::get_order() const
   {
   return data().m_order;
   }

const BigInt& EC_Group::get_cofactor() const
   {
   return data().m_cofactor;
   }

const OID& EC_Group::get_curve_oid() const
   {
   return data().m_oid;
   }

PointGFp EC_Group::OS2ECP(const uint8_t bits[], size_t len) const
   {
   return Botan::OS2ECP(bits, len, data().m_curve);
   }

PointGFp EC_Group::point(const BigInt& x, const BigInt& y) const
   {
   return PointGFp(data().m_curve, x, y);
   }

PointGFp EC_Group::zero_point() const
   {
   return PointGFp(data().m_curve);
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
