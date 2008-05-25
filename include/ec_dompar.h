/*************************************************
* ECDSA Domain Parameters Header File            *
* (C) 2007  Falko Strenzke, FlexSecure GmbH      *
*************************************************/

#ifndef EC_DOMPAR_H__
#define EC_DOMPAR_H__

#include <botan/point_gfp.h>
#include <botan/gfp_element.h>
#include <botan/curve_gfp.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/alg_id.h>
#include <botan/enums.h>

namespace Botan
{

/**
* This class represents elliptic curce domain parameters
*/
class EC_Domain_Params
   {
      friend EC_Domain_Params get_EC_Dom_Pars_by_oid(std::string oid);
   public:

      /**
      * Construct Domain paramers from specified parameters
      * @param curve elliptic curve
      * @param base_point a base point
      * @param order the order of the base point
      * @param cofactor the cofactor
      */
      EC_Domain_Params(Botan::math::ec::CurveGFp const& curve, Botan::math::ec::PointGFp const& base_point, BigInt const& order, BigInt const& cofactor);

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      Botan::math::ec::CurveGFp const get_curve() const
         {
         return Botan::math::ec::CurveGFp(m_curve);
         }

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      Botan::math::ec::PointGFp const get_base_point() const
         {
         return Botan::math::ec::PointGFp(m_base_point);
         }

      /**
      * Return the order of the base point
      * @result order of the base point
      */
      BigInt const get_order() const
         {
         return BigInt(m_order);
         }

      /**
      * Return the cofactor
      * @result the cofactor
      */
      BigInt const get_cofactor() const
         {
         return BigInt(m_cofactor);
         }

      /**
      * Return the OID of these domain parameters
      * @result the OID
      */
      std::string const get_oid() const
         {
         return m_oid;
         }

      /**
      * Write this object to a stream
      * @param output the output stream to write to
      * @param dom_par the domain parameters to write
      * @result the output stream
      */
      friend std::ostream& operator<< ( std::ostream& output, const EC_Domain_Params& dom_par );

   private:
      Botan::math::ec::CurveGFp m_curve;
      Botan::math::ec::PointGFp m_base_point;
      BigInt m_order;
      BigInt m_cofactor;
      std::string m_oid;


   };

bool operator==(EC_Domain_Params const& lhs, EC_Domain_Params const& rhs);

inline bool operator!=(EC_Domain_Params const& lhs, EC_Domain_Params const& rhs)
   {
   return !(lhs == rhs);
   }
SecureVector<byte> const encode_der_ec_dompar(EC_Domain_Params const& dom_pars, EC_dompar_enc enc_type);
EC_Domain_Params const decode_ber_ec_dompar(SecureVector<byte> const& encoded);

/**
* Factory function, the only way to obtain EC domain parameters with an OID.
* The demanded OID has to be registered in the InSiTo configuration. Consult the file
* policy.cpp for the default configuration.
* @param the oid of the demanded EC domain parameters
* @result the EC domain parameters associated with the OID
*/
EC_Domain_Params get_EC_Dom_Pars_by_oid(std::string oid);

}

#endif
