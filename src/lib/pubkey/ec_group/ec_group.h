/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010,2024 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ECC_DOMAIN_PARAMETERS_H_
#define BOTAN_ECC_DOMAIN_PARAMETERS_H_

#include <botan/asn1_obj.h>
#include <botan/bigint.h>
#include <botan/ec_apoint.h>
#include <botan/ec_point_format.h>
#include <botan/ec_scalar.h>
#include <memory>
#include <set>
#include <span>

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
   #include <botan/ec_point.h>
#endif

namespace Botan {

/**
* This enum indicates the method used to encode the EC parameters
*
* @warning All support for explicit or implicit domain encodings
* will be removed in Botan4. Only named curves will be supported.
*
* TODO(Botan4) remove this enum
*/
enum class EC_Group_Encoding {
   Explicit,
   ImplicitCA,
   NamedCurve,

   EC_DOMPAR_ENC_EXPLICIT = Explicit,
   EC_DOMPAR_ENC_IMPLICITCA = ImplicitCA,
   EC_DOMPAR_ENC_OID = NamedCurve
};

/**
* This enum indicates the source of the elliptic curve parameters
* in use.
*
* Builtin means the curve is a known standard one which was compiled
* in the library.
*
* ExternalSource means the curve parameters came from either an explicit
* curve encoding or an application defined curve.
*/
enum class EC_Group_Source {
   Builtin,
   ExternalSource,
};

/**
* Enum indicating the way the group in question is implemented
*
* This is returned by EC_Group::engine
*/
enum class EC_Group_Engine {
   /// Using per curve implementation; fastest available
   Optimized,
   /// A generic implementation that handles many curves in one implementation
   Generic,
   /// The old implementation, used as a fallback if none of the other
   /// implementations can be used
   /// TODO(Botan4) remove this
   Legacy,
};

class EC_Mul2Table_Data;
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
      * Construct elliptic curve from the specified parameters
      *
      * This is used for example to create custom (application-specific) curves.
      *
      * Some build configurations do not support application specific curves, in
      * which case this constructor will throw an exception. You can check for
      * this situation beforehand using the function
      * EC_Group::supports_application_specific_group()
      *
      * @param p the elliptic curve p
      * @param a the elliptic curve a param
      * @param b the elliptic curve b param
      * @param base_x the x coordinate of the base point
      * @param base_y the y coordinate of the base point
      * @param order the order of the base point
      * @param cofactor the cofactor
      * @param oid an optional OID used to identify this curve
      *
      * @warning This constructor is deprecated and will be removed in Botan 4
      *
      * @warning support for cofactors > 1 is deprecated and will be removed
      *
      * @warning support for prime fields > 521 bits is deprecated and
      * will be removed.
      *
      * @warning Support for explicitly encoded curve parameters is deprecated.
      * An OID must be assigned.
      */
      BOTAN_DEPRECATED("Use alternate constructor")
      EC_Group(const BigInt& p,
               const BigInt& a,
               const BigInt& b,
               const BigInt& base_x,
               const BigInt& base_y,
               const BigInt& order,
               const BigInt& cofactor,
               const OID& oid = OID());

      /**
      * Construct elliptic curve from the specified parameters
      *
      * This is used for example to create custom (application-specific) curves.
      *
      * Some build configurations do not support application specific curves, in
      * which case this constructor will throw an exception. You can check for
      * this situation beforehand using the function
      * EC_Group::supports_application_specific_group()
      *
      * Unlike the deprecated constructor, this constructor imposes additional
      * restrictions on the parameters, namely:
      *
      *  - An object identifier must be provided
      *
      *  - The prime must be at least 192 bits and at most 512 bits, and a multiple
      *    of 32 bits. Currently, as long as BOTAN_DISABLE_DEPRECATED_FEATURES is not
      *    set, this constructor accepts primes as small as 128 bits - this lower
      *    bound will be removed in the next major release.
      *
      *  - As an extension of the above restriction, the prime can also be exactly
      *    the 521-bit Mersenne prime (2**521-1) or exactly the 239-bit prime used in
      *    X9.62 239 bit groups (2**239 - 2**143 - 2**95 + 2**47 - 1)
      *
      *  - The prime must be congruent to 3 modulo 4
      *
      *  - The group order must have the same bit length as the prime. It is allowed
      *    for the order to be larger than p, but they must have the same bit length.
      *
      *  - Only prime order curves (with cofactor == 1) are allowed
      *
      * @warning use only elliptic curve parameters that you trust
      *
      * @param oid an object identifier used to identify this curve
      * @param p the elliptic curve prime (at most 521 bits)
      * @param a the elliptic curve a param
      * @param b the elliptic curve b param
      * @param base_x the x coordinate of the group generator
      * @param base_y the y coordinate of the group generator
      * @param order the order of the group
      */
      EC_Group(const OID& oid,
               const BigInt& p,
               const BigInt& a,
               const BigInt& b,
               const BigInt& base_x,
               const BigInt& base_y,
               const BigInt& order);

      /**
      * Decode a BER encoded ECC domain parameter set
      * @param ber the bytes of the BER encoding
      */
      explicit EC_Group(std::span<const uint8_t> ber);

      BOTAN_DEPRECATED("Use EC_Group(std::span)")
      EC_Group(const uint8_t ber[], size_t ber_len) : EC_Group(std::span{ber, ber_len}) {}

      /**
      * Create an EC domain by OID (or throw if unknown)
      * @param oid the OID of the EC domain to create
      */
      BOTAN_DEPRECATED("Use EC_Group::from_OID") explicit EC_Group(const OID& oid) { *this = EC_Group::from_OID(oid); }

      /**
      * Create an EC domain from PEM encoding (as from PEM_encode()), or
      * from an OID name (eg "secp256r1", or "1.2.840.10045.3.1.7")
      * @param pem_or_oid PEM-encoded data, or an OID
      *
      * @warning Support for PEM in this function is deprecated. Use
      * EC_Group::from_PEM or EC_Group::from_OID or EC_Group::from_name
      */
      BOTAN_DEPRECATED("Use EC_Group::from_{name,OID,PEM}") explicit EC_Group(std::string_view pem_or_oid);

      /**
      * Initialize an EC group from the PEM/ASN.1 encoding
      */
      static EC_Group from_PEM(std::string_view pem);

      /**
      * Initialize an EC group from a group named by an object identifier
      */
      static EC_Group from_OID(const OID& oid);

      /**
      * Initialize an EC group from a group common name (eg "secp256r1")
      */
      static EC_Group from_name(std::string_view name);

      BOTAN_DEPRECATED("Use EC_Group::from_PEM") static EC_Group EC_Group_from_PEM(std::string_view pem) {
         return EC_Group::from_PEM(pem);
      }

      /**
      * Create an uninitialized EC_Group
      */
      BOTAN_DEPRECATED("Deprecated no replacement") EC_Group();

      ~EC_Group();

      EC_Group(const EC_Group&);
      EC_Group(EC_Group&&) = default;

      EC_Group& operator=(const EC_Group&);
      EC_Group& operator=(EC_Group&&) = default;

      bool initialized() const { return (m_data != nullptr); }

      /**
       * Verify EC_Group domain
       * @returns true if group is valid. false otherwise
       */
      bool verify_group(RandomNumberGenerator& rng, bool strong = false) const;

      bool operator==(const EC_Group& other) const;

      EC_Group_Source source() const;

      /**
      * Return true if in this build configuration it is possible to
      * register an application specific elliptic curve.
      */
      static bool supports_application_specific_group();

      /**
      * Return true if in this build configuration EC_Group::from_name(name) will succeed
      */
      static bool supports_named_group(std::string_view name);

      /**
      * Return true if this EC_Group was derived from an explicit encoding
      *
      * Explicit encoding of groups is deprecated; when support for explicit curves
      * is removed in a future major release, this function will also be removed.
      */
      bool used_explicit_encoding() const { return m_explicit_encoding; }

      /**
      * Return how this EC_Group is implemented under the hood
      *
      * This is mostly useful for diagnostic or debugging purposes
      */
      EC_Group_Engine engine() const;

      /**
      * Return a set of known named EC groups
      *
      * This returns the set of groups for which from_name should succeed
      * Note that the set of included groups can vary based on the
      * build configuration.
      */
      static const std::set<std::string>& known_named_groups();

      /**
      * Create the DER encoding of this domain
      * @param form of encoding to use
      * @returns the group information encoded as DER
      */
      BOTAN_DEPRECATED("Use the variant that does not take EC_Group_Encoding")
      std::vector<uint8_t> DER_encode(EC_Group_Encoding form) const;

      /**
      * Create the DER encoding of this domain, using namedCurve format
      * @returns the group information encoded as DER
      */
      std::vector<uint8_t> DER_encode() const;

      /**
      * Return the PEM encoding (always in explicit form)
      * @return string containing PEM data
      */
      std::string PEM_encode() const;

      /**
      * Return the size of p in bits (same as get_p().bits())
      */
      size_t get_p_bits() const;

      /**
      * Return the size of p in bytes (same as get_p().bytes())
      */
      size_t get_p_bytes() const;

      /**
      * Return the size of group order in bits (same as get_order().bits())
      */
      size_t get_order_bits() const;

      /**
      * Return the size of the group order in bytes (same as get_order().bytes())
      */
      size_t get_order_bytes() const;

      /// Table for computing g*x + h*y
      class BOTAN_PUBLIC_API(3, 6) Mul2Table final {
         public:
            /**
            * Create a table for computing g*x + h*y
            */
            Mul2Table(const EC_AffinePoint& h);

            /**
            * Return the elliptic curve point g*x + h*y
            *
            * Where g is the group generator and h is the value passed to the constructor
            *
            * Returns nullopt if g*x + h*y was the point at infinity
            *
            * @warning this function is variable time with respect to x and y
            */
            std::optional<EC_AffinePoint> mul2_vartime(const EC_Scalar& x, const EC_Scalar& y) const;

            /**
            * Check if v equals the x coordinate of g*x + h*y reduced modulo the order
            *
            * Where g is the group generator and h is the value passed to the constructor
            *
            * Returns false if unequal, including if g*x + h*y was the point at infinity
            *
            * @warning this function is variable time with respect to x and y
            */
            bool mul2_vartime_x_mod_order_eq(const EC_Scalar& v, const EC_Scalar& x, const EC_Scalar& y) const;

            /**
            * Check if v equals the x coordinate of g*x*c + h*y*c reduced modulo the order
            *
            * Where g is the group generator and h is the value passed to the constructor
            *
            * Returns false if unequal, including if g*x*c + h*y*c was the point at infinity
            *
            * @warning this function is variable time with respect to x and y
            */
            bool mul2_vartime_x_mod_order_eq(const EC_Scalar& v,
                                             const EC_Scalar& c,
                                             const EC_Scalar& x,
                                             const EC_Scalar& y) const;

            ~Mul2Table();

         private:
            std::unique_ptr<EC_Mul2Table_Data> m_tbl;
      };

      /**
      * Return the OID of these domain parameters
      * @result the OID
      */
      const OID& get_curve_oid() const;

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
      * TODO(Botan4): Remove this
      */
      const BigInt& get_cofactor() const;

      /**
      * Return true if the cofactor is > 1
      * TODO(Botan4): Remove this
      */
      bool has_cofactor() const;

      /*
      * For internal use only
      * TODO(Botan4): Add underscore prefix
      */
      static std::shared_ptr<EC_Group_Data> EC_group_info(const OID& oid);

      /*
      * For internal use only
      * TODO(Botan4): Add underscore prefix
      */
      static size_t clear_registered_curve_data();

      /*
      * For internal use only
      * TODO(Botan4): Add underscore prefix
      */
      static OID EC_group_identity_from_order(const BigInt& order);

      /*
      * For internal use only
      */
      const std::shared_ptr<EC_Group_Data>& _data() const { return m_data; }

#if defined(BOTAN_HAS_LEGACY_EC_POINT)
      /**
      * Check if y is a plausible point on the curve
      *
      * In particular, checks that it is a point on the curve, not infinity,
      * and that it has order matching the group.
      */
      bool verify_public_element(const EC_Point& y) const;

      /**
      * OS2ECP (Octet String To Elliptic Curve Point)
      *
      * Deserialize an encoded point. Verifies that the point is on the curve.
      */
      BOTAN_DEPRECATED("Use EC_AffinePoint::deserialize") EC_Point OS2ECP(const uint8_t bits[], size_t len) const {
         return EC_AffinePoint(*this, std::span{bits, len}).to_legacy_point();
      }

      BOTAN_DEPRECATED("Use EC_AffinePoint::deserialize")
      EC_Point OS2ECP(std::span<const uint8_t> encoded_point) const {
         return EC_AffinePoint(*this, encoded_point).to_legacy_point();
      }

      /**
      * Return group base point
      * @result base point
      */
      BOTAN_DEPRECATED("Use EC_AffinePoint::generator") const EC_Point& get_base_point() const;

      // Everything below here will be removed in a future release:

      /**
      * Return the canonical group generator
      * @result standard generator of the curve
      */
      BOTAN_DEPRECATED("Use EC_AffinePoint::generator") const EC_Point& generator() const;

      /**
      * Multi exponentiate. Not constant time.
      * @return base_point*x + h*y
      */
      BOTAN_DEPRECATED("Use EC_Group::Mul2Table")
      EC_Point point_multiply(const BigInt& x_bn, const EC_Point& h_pt, const BigInt& y_bn) const {
         auto x = EC_Scalar::from_bigint(*this, x_bn);
         auto y = EC_Scalar::from_bigint(*this, y_bn);
         auto h = EC_AffinePoint(*this, h_pt);

         Mul2Table gh_mul(h);

         if(auto r = gh_mul.mul2_vartime(x, y)) {
            return r->to_legacy_point();
         } else {
            return EC_AffinePoint::identity(*this).to_legacy_point();
         }
      }

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * @param k_bn the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return base_point*k
      */
      BOTAN_DEPRECATED("Use EC_AffinePoint and EC_Scalar")
      EC_Point
         blinded_base_point_multiply(const BigInt& k_bn, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const {
         auto k = EC_Scalar::from_bigint(*this, k_bn);
         auto pt = EC_AffinePoint::g_mul(k, rng, ws);
         return pt.to_legacy_point();
      }

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * Returns just the x coordinate of the point
      *
      * @param k_bn the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return x coordinate of base_point*k
      */
      BOTAN_DEPRECATED("Use EC_AffinePoint and EC_Scalar")
      BigInt
         blinded_base_point_multiply_x(const BigInt& k_bn, RandomNumberGenerator& rng, std::vector<BigInt>& ws) const {
         auto k = EC_Scalar::from_bigint(*this, k_bn);
         return BigInt(EC_AffinePoint::g_mul(k, rng, ws).x_bytes());
      }

      /**
      * Blinded point multiplication, attempts resistance to side channels
      * @param point input point
      * @param k_bn the scalar
      * @param rng a random number generator
      * @param ws a temp workspace
      * @return point*k
      */
      BOTAN_DEPRECATED("Use EC_AffinePoint and EC_Scalar")
      EC_Point blinded_var_point_multiply(const EC_Point& point,
                                          const BigInt& k_bn,
                                          RandomNumberGenerator& rng,
                                          std::vector<BigInt>& ws) const {
         auto k = EC_Scalar::from_bigint(*this, k_bn);
         auto pt = EC_AffinePoint(*this, point);
         return pt.mul(k, rng, ws).to_legacy_point();
      }

      /**
      * Return a random scalar ie an integer in [1,order)
      */
      BOTAN_DEPRECATED("Use EC_Scalar::random") BigInt random_scalar(RandomNumberGenerator& rng) const {
         return EC_Scalar::random(*this, rng).to_bigint();
      }

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
      BOTAN_DEPRECATED("Use EC_AffinePoint")
      EC_Point hash_to_curve(std::string_view hash_fn,
                             const uint8_t input[],
                             size_t input_len,
                             const uint8_t domain_sep[],
                             size_t domain_sep_len,
                             bool random_oracle = true) const {
         auto inp = std::span{input, input_len};
         auto dst = std::span{domain_sep, domain_sep_len};

         if(random_oracle) {
            return EC_AffinePoint::hash_to_curve_ro(*this, hash_fn, inp, dst).to_legacy_point();
         } else {
            return EC_AffinePoint::hash_to_curve_nu(*this, hash_fn, inp, dst).to_legacy_point();
         }
      }

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
      BOTAN_DEPRECATED("Use EC_AffinePoint")
      EC_Point hash_to_curve(std::string_view hash_fn,
                             const uint8_t input[],
                             size_t input_len,
                             std::string_view domain_sep,
                             bool random_oracle = true) const {
         auto inp = std::span{input, input_len};
         auto dst = std::span{reinterpret_cast<const uint8_t*>(domain_sep.data()), domain_sep.size()};

         if(random_oracle) {
            return EC_AffinePoint::hash_to_curve_ro(*this, hash_fn, inp, dst).to_legacy_point();
         } else {
            return EC_AffinePoint::hash_to_curve_nu(*this, hash_fn, inp, dst).to_legacy_point();
         }
      }

      /**
      * Return a point on this curve with the affine values x, y
      */
      BOTAN_DEPRECATED("Deprecated - use EC_AffinePoint") EC_Point point(const BigInt& x, const BigInt& y) const {
         if(auto pt = EC_AffinePoint::from_bigint_xy(*this, x, y)) {
            return pt->to_legacy_point();
         } else {
            throw Decoding_Error("Invalid x/y coordinates for elliptic curve point");
         }
      }

      /**
      * Return the zero (or infinite) point on this curve
      */
      BOTAN_DEPRECATED("Deprecated no replacement") EC_Point zero_point() const {
         return EC_AffinePoint::identity(*this).to_legacy_point();
      }
#endif

      /**
      * Return if a == -3 mod p
      */
      BOTAN_DEPRECATED("Deprecated no replacement") bool a_is_minus_3() const { return get_a() + 3 == get_p(); }

      /**
      * Return if a == 0 mod p
      */
      BOTAN_DEPRECATED("Deprecated no replacement") bool a_is_zero() const { return get_a().is_zero(); }

      /*
      * Reduce x modulo the order
      */
      BOTAN_DEPRECATED("Use EC_Scalar") BigInt mod_order(const BigInt& x) const {
         return EC_Scalar::from_bytes_mod_order(*this, x.serialize()).to_bigint();
      }

      /*
      * Return inverse of x modulo the order
      */
      BOTAN_DEPRECATED("Use EC_Scalar") BigInt inverse_mod_order(const BigInt& x) const {
         return EC_Scalar::from_bigint(*this, x).invert().to_bigint();
      }

      /*
      * Reduce (x*x) modulo the order
      */
      BOTAN_DEPRECATED("Use EC_Scalar") BigInt square_mod_order(const BigInt& x) const {
         auto xs = EC_Scalar::from_bigint(*this, x);
         xs.square_self();
         return xs.to_bigint();
      }

      /*
      * Reduce (x*y) modulo the order
      */
      BOTAN_DEPRECATED("Use EC_Scalar") BigInt multiply_mod_order(const BigInt& x, const BigInt& y) const {
         auto xs = EC_Scalar::from_bigint(*this, x);
         auto ys = EC_Scalar::from_bigint(*this, y);
         return (xs * ys).to_bigint();
      }

      /*
      * Reduce (x*y*z) modulo the order
      */
      BOTAN_DEPRECATED("Use EC_Scalar")
      BigInt multiply_mod_order(const BigInt& x, const BigInt& y, const BigInt& z) const {
         auto xs = EC_Scalar::from_bigint(*this, x);
         auto ys = EC_Scalar::from_bigint(*this, y);
         auto zs = EC_Scalar::from_bigint(*this, z);
         return (xs * ys * zs).to_bigint();
      }

      /*
      * Return x^3 modulo the order
      */
      BOTAN_DEPRECATED("Deprecated no replacement") BigInt cube_mod_order(const BigInt& x) const {
         auto xs = EC_Scalar::from_bigint(*this, x);
         return (xs * xs * xs).to_bigint();
      }

      BOTAN_DEPRECATED("Just serialize the point and check") size_t point_size(EC_Point_Format format) const {
         // Hybrid and standard format are (x,y), compressed is y, +1 format byte
         if(format == EC_Point_Format::Compressed) {
            return (1 + get_p_bytes());
         } else {
            return (1 + 2 * get_p_bytes());
         }
      }

   private:
      static EC_Group_Data_Map& ec_group_data();

      EC_Group(std::shared_ptr<EC_Group_Data>&& data);

      static std::pair<std::shared_ptr<EC_Group_Data>, bool> BER_decode_EC_group(std::span<const uint8_t> ber,
                                                                                 EC_Group_Source source);

      static std::shared_ptr<EC_Group_Data> load_EC_group_info(const char* p,
                                                               const char* a,
                                                               const char* b,
                                                               const char* g_x,
                                                               const char* g_y,
                                                               const char* order,
                                                               const OID& oid);

      const EC_Group_Data& data() const;

      // Member data
      std::shared_ptr<EC_Group_Data> m_data;
      bool m_explicit_encoding = false;
};

inline bool operator!=(const EC_Group& lhs, const EC_Group& rhs) {
   return !(lhs == rhs);
}

}  // namespace Botan

#endif
