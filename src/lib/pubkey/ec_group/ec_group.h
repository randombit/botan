/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECC_DOMAIN_PARAMETERS_H_
#define BOTAN_ECC_DOMAIN_PARAMETERS_H_

#include <botan/point_gfp.h>
#include <botan/curve_gfp.h>
#include <botan/asn1_oid.h>
#include <memory>
#include <set>

namespace Botan {

/**
* This class represents elliptic curce domain parameters
*/
enum EC_Group_Encoding {
   EC_DOMPAR_ENC_EXPLICIT = 0,
   EC_DOMPAR_ENC_IMPLICITCA = 1,
   EC_DOMPAR_ENC_OID = 2
};

class EC_Group_Data;
class EC_Group_Data_Map;

/**
* Class representing an elliptic curve
*/
class BOTAN_PUBLIC_API(2,0) EC_Group final
   {
   public:

      /**
      * Construct Domain paramers from specified parameters
      * @param curve elliptic curve
      * @param base_point a base point
      * @param order the order of the base point
      * @param cofactor the cofactor
      */
      BOTAN_DEPRECATED("Use version taking all BigInts")
      EC_Group(const CurveGFp& curve,
               const PointGFp& base_point,
               const BigInt& order,
               const BigInt& cofactor) :
         EC_Group(curve.get_p(),
                  curve.get_a(),
                  curve.get_b(),
                  base_point.get_affine_x(),
                  base_point.get_affine_y(),
                  order,
                  cofactor) {}

      /**
      * Construct Domain paramers from specified parameters
      * @param p the elliptic curve p
      * @param a the elliptic curve a param
      * @param b the elliptic curve b param
      * @param base_x the x coordinate of the base point
      * @param base_y the y coordinate of the base point
      * @param order the order of the base point
      * @param cofactor the cofactor
      * @param oid an optional OID used to identify this curve
      */
      EC_Group(const BigInt& p,
               const BigInt& a,
               const BigInt& b,
               const BigInt& base_x,
               const BigInt& base_y,
               const BigInt& order,
               const BigInt& cofactor,
               const OID& oid = OID());

      /**
      * Decode a BER encoded ECC domain parameter set
      * @param ber_encoding the bytes of the BER encoding
      */
      explicit EC_Group(const std::vector<uint8_t>& ber_encoding);

      /**
      * Create an EC domain by OID (or throw if unknown)
      * @param oid the OID of the EC domain to create
      */
      explicit EC_Group(const OID& oid);

      /**
      * Create an EC domain from PEM encoding (as from PEM_encode), or
      * from an OID name (eg "secp256r1", or "1.2.840.10045.3.1.7")
      * @param pem_or_oid PEM-encoded data, or an OID
      */
      explicit EC_Group(const std::string& pem_or_oid);

      /**
      * Create an uninitialized EC_Group
      */
      EC_Group();

      ~EC_Group();

      /**
      * Create the DER encoding of this domain
      * @param form of encoding to use
      * @returns bytes encododed as DER
      */
      std::vector<uint8_t> DER_encode(EC_Group_Encoding form) const;

      /**
      * Return the PEM encoding (always in explicit form)
      * @return string containing PEM data
      */
      std::string PEM_encode() const;

      /**
      * Return domain parameter curve
      * @result domain parameter curve
      */
      BOTAN_DEPRECATED("Avoid CurveGFp") const CurveGFp& get_curve() const;

      /**
      * Return the size of p in bits (same as get_p().bits())
      */
      size_t get_p_bits() const;

      /**
      * Return the size of p in bits (same as get_p().bytes())
      */
      size_t get_p_bytes() const;

      /**
      * Return the prime modulus of the field
      */
      const BigInt& get_p() const;

      /**
      * Return the a parameter of the elliptic curve equation
      */
      const BigInt& get_a() const;

      /**
      * Return the b parameter of the elliptic curve equation
      */
      const BigInt& get_b() const;

      /**
      * Return group base point
      * @result base point
      */
      const PointGFp& get_base_point() const;

      /**
      * Return the order of the base point
      * @result order of the base point
      */
      const BigInt& get_order() const;

      /**
      * Return the OID of these domain parameters
      * @result the OID as a string
      */
      std::string BOTAN_DEPRECATED("Use get_curve_oid") get_oid() const { return get_curve_oid().as_string(); }

      /**
      * Return the OID of these domain parameters
      * @result the OID
      */
      const OID& get_curve_oid() const;

      /**
      * Return the cofactor
      * @result the cofactor
      */
      const BigInt& get_cofactor() const;

      /**
      * Return a point on this curve with the affine values x, y
      */
      PointGFp point(const BigInt& x, const BigInt& y) const;

      /**
      * Return the zero (or infinite) point on this curve
      */
      PointGFp zero_point() const;

      PointGFp OS2ECP(const uint8_t bits[], size_t len) const;

      template<typename Alloc>
      PointGFp OS2ECP(const std::vector<uint8_t, Alloc>& vec) const
         {
         return this->OS2ECP(vec.data(), vec.size());
         }

      bool initialized() const { return (m_data != nullptr); }

      /**
       * Verify EC_Group domain
       * @returns true if group is valid. false otherwise
       */
      bool verify_group(RandomNumberGenerator& rng,
                        bool strong = false) const;

      bool operator==(const EC_Group& other) const;

      /**
      * Return PEM representation of named EC group
      * Deprecated: Use EC_Group(name).PEM_encode() if this is needed
      */
      static std::string BOTAN_DEPRECATED("See header comment") PEM_for_named_group(const std::string& name);

      /**
      * Return a set of known named EC groups
      */
      static const std::set<std::string>& known_named_groups();

      /*
      * For internal use only
      */
      static std::shared_ptr<EC_Group_Data> EC_group_info(const OID& oid);

   private:
      static EC_Group_Data_Map& ec_group_data();

      static std::shared_ptr<EC_Group_Data> BER_decode_EC_group(const uint8_t bits[], size_t len);

      static std::shared_ptr<EC_Group_Data>
         load_EC_group_info(const char* p,
                            const char* a,
                            const char* b,
                            const char* g_x,
                            const char* g_y,
                            const char* order,
                            const OID& oid);

      // Member data
      const EC_Group_Data& data() const;
      std::shared_ptr<EC_Group_Data> m_data;
   };

inline bool operator!=(const EC_Group& lhs,
                       const EC_Group& rhs)
   {
   return !(lhs == rhs);
   }

// For compatibility with 1.8
typedef EC_Group EC_Domain_Params;

}

#endif
