/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECC_DOMAIN_PARAMETERS_H__
#define BOTAN_ECC_DOMAIN_PARAMETERS_H__

#include <botan/point_gfp.h>
#include <botan/curve_gfp.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/alg_id.h>
#include <botan/pubkey_enums.h>

namespace Botan {

/**
* This class represents elliptic curce domain parameters
*/
enum EC_Domain_Params_Encoding {
   EC_DOMPAR_ENC_EXPLICIT = 0,
   EC_DOMPAR_ENC_IMPLICITCA = 1,
   EC_DOMPAR_ENC_OID = 2
};

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
                       const BigInt& cofactor) :
         curve(curve),
         base_point(base_point),
         order(order),
         cofactor(cofactor),
         oid("")
         {}

      /**
      * Decode a BER encoded ECC domain parameter set
      * @param ber_encoding the bytes of the BER encoding
      */
      EC_Domain_Params(const MemoryRegion<byte>& ber_encoding);

      /**
      * Create the DER encoding of this domain
      * @param form of encoding to use
      * @returns bytes encododed as DER
      */
      SecureVector<byte> DER_encode(EC_Domain_Params_Encoding form) const;

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      const CurveGFp& get_curve() const { return curve; }

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      const PointGFp& get_base_point() const { return base_point; }

      /**
      * Return the order of the base point
      * @result order of the base point
      */
      const BigInt& get_order() const { return order; }

      /**
      * Return the cofactor
      * @result the cofactor
      */
      const BigInt& get_cofactor() const { return cofactor; }

      /**
      * Return the OID of these domain parameters
      * @result the OID
      */
      std::string get_oid() const { return oid; }

      bool operator==(const EC_Domain_Params& other) const
         {
         return ((get_curve() == other.get_curve()) &&
                 (get_base_point() == other.get_base_point()) &&
                 (get_order() == other.get_order()) &&
                 (get_cofactor() == other.get_cofactor()));
         }

   private:
      friend EC_Domain_Params get_EC_Dom_Pars_by_oid(std::string oid);

      CurveGFp curve;
      PointGFp base_point;
      BigInt order, cofactor;
      std::string oid;
   };

inline bool operator!=(const EC_Domain_Params& lhs,
                       const EC_Domain_Params& rhs)
   {
   return !(lhs == rhs);
   }

/**
* Factory function, the only way to obtain EC domain parameters with
* an OID.  The demanded OID has to be registered in the InSiTo
* configuration. Consult the file ec_dompar.cpp for the default
* configuration.
* @param oid the oid of the demanded EC domain parameters
* @result the EC domain parameters associated with the OID
*/
EC_Domain_Params BOTAN_DLL get_EC_Dom_Pars_by_oid(std::string oid);

}

#endif
