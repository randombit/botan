/*
* ECDSA Domain Parameters
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECC_DOMAIN_PARAMETERS_H__
#define BOTAN_ECC_DOMAIN_PARAMETERS_H__

#include <botan/point_gfp.h>
#include <botan/gfp_element.h>
#include <botan/curve_gfp.h>
#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/alg_id.h>
#include <botan/pubkey_enums.h>

namespace Botan {

/**
* This class represents elliptic curce domain parameters
*/
class BOTAN_DLL EC_Domain_Params
   {
   public:

      /**
      * Construct Domain paramers from specified parameters
      * @param curve elliptic curve
      * @param base_point a base point
      * @param order the order of the base point
      * @param cofactor the cofactor
      */
      EC_Domain_Params(const CurveGFp& curve,
                       const PointGFp& base_point,
                       const BigInt& order,
                       const BigInt& cofactor);

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      const CurveGFp& get_curve() const
         {
         return m_curve;
         }

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      const PointGFp& get_base_point() const
         {
         return m_base_point;
         }

      /**
      * Return the order of the base point
      * @result order of the base point
      */
      const BigInt& get_order() const
         {
         return m_order;
         }

      /**
      * Return the cofactor
      * @result the cofactor
      */
      const BigInt& get_cofactor() const
         {
         return m_cofactor;
         }

      /**
      * Return the OID of these domain parameters
      * @result the OID
      */
      std::string get_oid() const { return m_oid; }

   private:
      friend EC_Domain_Params get_EC_Dom_Pars_by_oid(std::string oid);

      CurveGFp m_curve;
      PointGFp m_base_point;
      BigInt m_order;
      BigInt m_cofactor;
      std::string m_oid;
   };

bool operator==(EC_Domain_Params const& lhs, EC_Domain_Params const& rhs);

inline bool operator!=(const EC_Domain_Params& lhs,
                       const EC_Domain_Params& rhs)
   {
   return !(lhs == rhs);
   }

enum EC_dompar_enc { ENC_EXPLICIT = 0, ENC_IMPLICITCA = 1, ENC_OID = 2 };

SecureVector<byte> encode_der_ec_dompar(EC_Domain_Params const& dom_pars,
                                        EC_dompar_enc enc_type);

EC_Domain_Params decode_ber_ec_dompar(SecureVector<byte> const& encoded);

/**
* Factory function, the only way to obtain EC domain parameters with
* an OID.  The demanded OID has to be registered in the InSiTo
* configuration. Consult the file ec_dompar.cpp for the default
* configuration.
* @param oid the oid of the demanded EC domain parameters
* @result the EC domain parameters associated with the OID
*/
EC_Domain_Params get_EC_Dom_Pars_by_oid(std::string oid);

}

#endif
