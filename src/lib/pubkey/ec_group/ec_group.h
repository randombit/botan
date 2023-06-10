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

#include <botan/asn1_obj.h>
#include <botan/ec_point.h>
#include <memory>
#include <set>
#include <span>

namespace Botan {

/**
* This class represents elliptic curce domain parameters
*/
enum class EC_Group_Encoding {
   Explicit,
   ImplicitCA,
   NamedCurve,

   EC_DOMPAR_ENC_EXPLICIT = Explicit,
   EC_DOMPAR_ENC_IMPLICITCA = ImplicitCA,
   EC_DOMPAR_ENC_OID = NamedCurve
};

enum class EC_Group_Source {
   Builtin,
   ExternalSource,
};

class EC_Group_Data;
class EC_Group_Data_Map;

/**
* Class representing an elliptic curve
*
* The internal representation is stored in a shared_ptr, so copying an
* EC_Group is inexpensive.
*/
class BOTAN_PUBLIC_API(2, 0) EC_Group final {
   public:
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
      * @param ber the bytes of the BER encoding
      * @param ber_len the length of ber
      */
      explicit EC_Group(const uint8_t ber[], size_t ber_len);

      template <typename Alloc>
      EC_Group(const std::vector<uint8_t, Alloc>& ber) : EC_Group(ber.data(), ber.size()) {}

      /**
      * Create an EC domain by OID (or throw if unknown)
      * @param oid the OID of the EC domain to create
      */
      explicit EC_Group(const OID& oid);

      /**
      * Create an EC domain from PEM encoding (as from PEM_encode), or
      * from an OID name (eg "secp256r1", or "1.2.840.10045.3.1.7")
      * @param pem_or_oid PEM-encoded data, or an OID

      * @warning Support for PEM in this function is deprecated. Use
      * EC_Group_from_PEM
      */
      explicit EC_Group(std::string_view pem_or_oid);

      static EC_Group EC_Group_from_PEM(std::string_view pem);

      /**
      * Create an uninitialized EC_Group
      */
      EC_Group();

      ~EC_Group();

      EC_Group(const EC_Group&) = default;
      EC_Group(EC_Group&&) = default;

      EC_Group& operator=(const EC_Group&) = default;
      EC_Group& operator=(EC_Group&&) = default;

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
      * Return if a == -3 mod p
      */
      bool a_is_minus_3() const;

      /**
      * Return if a == 0 mod p
      */
      bool a_is_zero() const;

      /**
      * Return the size of p in bits (same as get_p().bits())
      */
      size_t get_p_bits() const;

      /**
      * Return the size of p in bits (same as get_p().bytes())
      */
      size_t get_p_bytes() const;

      /**
      * Return the size of group order in bits (same as get_order().bits())
      */
      size_t get_order_bits() const;

      /**
      * Return the size of p in bytes (same as get_order().bytes())
      */
      size_t get_order_bytes() const;

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
      const EC_Point& get_base_point() const;

      /**
      * Return the x coordinate of the base point
      */
      const BigInt& get_g_x() const;

      /**
      * Return the y coordinate of the base point
      */
      const BigInt& get_g_y() const;

      /**
      * Return the order of the base point
      * @result order of the base point
      */
      const BigInt& get_order() const;

      /**
      * Return the cofactor
      * @result the cofactor
      */
      const BigInt& get_cofactor() const;

      /*
      * Reduce x modulo the order
      */
      BigInt mod_order(const BigInt& x) const;

      /*
      * Return inverse of x modulo the order
      */
      BigInt inverse_mod_order(const BigInt& x) const;

      /*
      * Reduce (x*x) modulo the order
      */
      BigInt square_mod_order(const BigInt& x) const;

      /*
      * Reduce (x*y) modulo the order
      */
      BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const;

      /*
      * Reduce (x*y*z) modulo the order
      */
      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const;

      /*
      * Return x^3 modulo the order
      */
      inline BigInt cube_mod_order(const BigInt& x) const { return multiply_mod_order(x, square_mod_order(x)); }

      /**
      * Check if y is a plausible point on the curve
      *
      * In particular, checks that it is a point on the curve, not infinity,
      * and that it has order matching the group.
      */
      bool verify_public_element(const EC_Point& y) const;

      /**
      * Return the OID of these domain parameters
      * @result the OID
      */
      const OID& get_curve_oid() const;

      /**
      * Return a point on this curve with the affine values x, y
      */
      EC_Point point(const BigInt& x, const BigInt& y) const;

      /**
      * Multi exponentiate. Not constant time.
      * @return base_point*x + pt*y
      */
      EC_Point point_multiply(const BigInt& x, const EC_Point& pt, const BigInt& y) const;

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * @param k the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return base_point*k
      */
      EC_Point blinded_base_point_multiply(const BigInt& k, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const;

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * Returns just the x coordinate of the point
      *
      * @param k the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return x coordinate of base_point*k
      */
      BigInt blinded_base_point_multiply_x(const BigInt& k, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const;

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * @param point input point
      * @param k the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return point*k
      */
      EC_Point blinded_var_point_multiply(const EC_Point& point,
                                          const BigInt& k,
                                          RandomNumberGenerator& rng,
                                          std::vector<BigInt>& ws) const;

      /**
      * Return a random scalar ie an integer in [1,order)
      */
      BigInt random_scalar(RandomNumberGenerator& rng) const;

      /**
      * Hash onto the curve.
      * For some curve types no mapping is currently available, in this
      * case this function will throw an exception.
      *
      * @param hash_fn the hash function to use (typically "SHA-256" or "SHA-512")
      * @param input the input to hash
      * @param input_len length of input in bytes
      * @param domain_sep a domain seperator
      * @param domain_sep_len length of domain_sep in bytes
      * @param random_oracle if the mapped point must be uniform (use
               "true" here unless you know what you are doing)
      */
      EC_Point hash_to_curve(std::string_view hash_fn,
                             const uint8_t input[],
                             size_t input_len,
                             const uint8_t domain_sep[],
                             size_t domain_sep_len,
                             bool random_oracle = true) const;

      /**
      * Hash onto the curve.
      * For some curve types no mapping is currently available, in this
      * case this function will throw an exception.
      *
      * @param hash_fn the hash function to use (typically "SHA-256" or "SHA-512")
      * @param input the input to hash
      * @param input_len length of input in bytes
      * @param domain_sep a domain seperator
      * @param random_oracle if the mapped point must be uniform (use
               "true" here unless you know what you are doing)
      */
      EC_Point hash_to_curve(std::string_view hash_fn,
                             const uint8_t input[],
                             size_t input_len,
                             std::string_view domain_sep,
                             bool random_oracle = true) const;

      /**
      * Return the zero (or infinite) point on this curve
      */
      EC_Point zero_point() const;

      size_t point_size(EC_Point_Format format) const;

      EC_Point OS2ECP(const uint8_t bits[], size_t len) const;

      EC_Point OS2ECP(std::span<const uint8_t> encoded_point) const {
         return this->OS2ECP(encoded_point.data(), encoded_point.size());
      }

      bool initialized() const { return (m_data != nullptr); }

      /**
       * Verify EC_Group domain
       * @returns true if group is valid. false otherwise
       */
      bool verify_group(RandomNumberGenerator& rng, bool strong = false) const;

      bool operator==(const EC_Group& other) const;

      EC_Group_Source source() const;

      /**
      * Return a set of known named EC groups
      */
      static const std::set<std::string>& known_named_groups();

      /*
      * For internal use only
      */
      static std::shared_ptr<EC_Group_Data> EC_group_info(const OID& oid);

      /*
      * For internal use only
      */
      static size_t clear_registered_curve_data();

      /*
      * For internal use only
      */
      static OID EC_group_identity_from_order(const BigInt& order);

   private:
      static EC_Group_Data_Map& ec_group_data();

      static std::shared_ptr<EC_Group_Data> BER_decode_EC_group(const uint8_t bits[],
                                                                size_t len,
                                                                EC_Group_Source source);

      static std::shared_ptr<EC_Group_Data> load_EC_group_info(const char* p,
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

inline bool operator!=(const EC_Group& lhs, const EC_Group& rhs) {
   return !(lhs == rhs);
}

}  // namespace Botan

#endif
