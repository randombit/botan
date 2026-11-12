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
#include <botan/ec_apoint.h>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class BigInt;
class EC_Scalar;

/**
* This enum indicates the format used to encode an elliptic curve point
* as an octet string, as specified in SEC1 section 2.3.3
*/
enum class EC_Point_Format : uint8_t {
   Uncompressed = 0,
   Compressed = 1,
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
enum class EC_Group_Source : uint8_t {
   Builtin,
   ExternalSource,
};

/**
* Enum indicating the way the group in question is implemented
*
* This is returned by EC_Group::engine
*/
enum class EC_Group_Engine : uint8_t {
   /// Using per curve implementation; fastest available
   Optimized,
   /// A generic implementation that handles many curves in one implementation
   Generic,
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
      * Calling this function registers these parameters within the persistent state
      * of the library; for example once this call completes, an ECDSA key
      * specifying its namedCurve matching the provided OID can be decoded, and
      * this remains true even after the EC_Group created has been destroyed.
      * If necessary you can unregister the group using EC_Group::unregister.
      *
      * Some build configurations do not support application specific curves, in
      * which case this function will throw an exception. You can check for
      * this situation beforehand using the function
      * EC_Group::supports_application_specific_group()
      *
      * The following constraints are imposed on the parameters:
      *
      *  - An object identifier must be provided
      *
      *  - The prime must be at least 192 bits and at most 512 bits, and a multiple
      *    of 32 bits.
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
      BOTAN_DEPRECATED("Use EC_Group::register_custom_group")
      EC_Group(const OID& oid,
               const BigInt& p,
               const BigInt& a,
               const BigInt& b,
               const BigInt& base_x,
               const BigInt& base_y,
               const BigInt& order);

      /**
      * Construct elliptic curve from the specified parameters
      *
      * This is used for example to create custom (application-specific) curves.
      *
      * This function registers these parameters within the persistent state
      * of the library; for example once this call completes, an ECDSA key
      * specifying its namedCurve matching the provided OID can be decoded, and
      * this remains true even after the EC_Group returned here has been destroyed.
      * If necessary you can unregister the group using EC_Group::unregister.
      *
      * Some build configurations do not support application specific curves, in
      * which case this function will throw an exception. You can check for
      * this situation beforehand using the function
      * EC_Group::supports_application_specific_group()
      *
      * The following constraints are imposed on the parameters:
      *
      *  - An object identifier must be provided
      *
      *  - The prime must be at least 192 bits and at most 512 bits, and a multiple
      *    of 32 bits. Currently, as long as BOTAN_DISABLE_DEPRECATED_FEATURES is not
      *    set, this function will accept primes as small as 128 bits - this lower
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
      static EC_Group register_custom_group(const OID& oid,
                                            const BigInt& p,
                                            const BigInt& a,
                                            const BigInt& b,
                                            const BigInt& base_x,
                                            const BigInt& base_y,
                                            const BigInt& order);

      /**
      * Decode a DER encoded ECC domain parameter set
      * @param der the bytes of the DER encoding
      */
      explicit EC_Group(std::span<const uint8_t> der);

      /**
      * Decode a DER encoded ECC domain parameter set
      * @param der the bytes of the DER encoding
      * @param der_len the length of der in bytes
      */
      BOTAN_DEPRECATED("Use EC_Group(std::span)")
      EC_Group(const uint8_t der[], size_t der_len) : EC_Group(std::span{der, der_len}) {}

      /**
      * Create an EC group from a curve name, eg "secp256r1"
      *
      * This is equivalent to EC_Group::from_name
      */
      BOTAN_DEPRECATED("Use EC_Group::from_name")
      explicit EC_Group(std::string_view name) : EC_Group(EC_Group::from_name(name)) {}

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

      /**
      * Unregister a previously registered group.
      *
      * Using this is discouraged for normal use. This is only useful or necessary if
      * you are registering a very large number of distinct groups, and need to worry about memory constraints.
      *
      * Returns true if the group was found and unregistered.
      */
      static bool unregister(const OID& oid);

      ~EC_Group();

      /**
      * Copy constructor
      */
      EC_Group(const EC_Group&);

      /**
      * Move constructor
      *
      * This copies, so a moved-from group remains valid
      */
      EC_Group(EC_Group&& other) noexcept;

      /**
      * Copy assignment
      * @return reference to this
      */
      EC_Group& operator=(const EC_Group&);

      /**
      * Move assignment
      * @return reference to this
      *
      * This copies, so a moved-from group remains valid
      */
      EC_Group& operator=(EC_Group&& other) noexcept;

      /**
       * Verify EC_Group domain
       *
       * Groups are either builtin or were fully validated by register_custom_group
       * when they were created, so this always returns true.
       */
      bool verify_group(RandomNumberGenerator& rng, bool strong = false) const;

      /**
      * Test if two groups describe the same curve
      * @param other the group to compare against
      * @return true if the two groups are equal
      */
      bool operator==(const EC_Group& other) const;

      /**
      * Return how this group was created, eg from a builtin table or by
      * decoding an external encoding
      */
      EC_Group_Source source() const;

      /**
      * Return true if in this build configuration it is possible to
      * register an application specific elliptic curve.
      */
      static bool supports_application_specific_group();

      /**
      * Return true if EC_Group::from_name(name) should succeed for this name
      * either because it is a group compiled into the library or it is a group
      * which has already been registered by the application at runtime.
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
      * This returns a set of groups for which from_name should succeed.
      *
      * Note that the set of included groups can vary based on the build
      * configuration, and that this list does not include any groups registered
      * by the application at runtime.
      */
      static const std::set<std::string>& known_named_groups();

      /**
      * Create the DER encoding of this domain, using namedCurve format
      * @returns the group information encoded as DER
      */
      std::vector<uint8_t> DER_encode() const;

      /**
      * Return the PEM encoding, using namedCurve format
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

      /**
      * Table for computing g*x + h*y
      */
      class BOTAN_PUBLIC_API(3, 6) Mul2Table final {
         public:
            /**
            * Create a table for computing g*x + h*y
            */
            BOTAN_FUTURE_EXPLICIT Mul2Table(const EC_AffinePoint& h);

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

            Mul2Table(const Mul2Table& other) = delete;
            Mul2Table& operator=(const Mul2Table& other) = delete;

            /**
            * Move constructor
            * @param other the table to move from
            */
            Mul2Table(Mul2Table&& other) noexcept;

            /**
            * Move assignment
            * @param other the table to move from
            * @return reference to this
            */
            Mul2Table& operator=(Mul2Table&& other) noexcept;

         private:
            std::unique_ptr<EC_Mul2Table_Data> m_tbl;
      };

      /**
      * Return true if RFC 9380 hash to curve is supported for this group
      * with the specified hash function
      *
      * If this returns true then EC_AffinePoint::hash_to_curve_ro and
      * EC_AffinePoint::hash_to_curve_nu will work for this group and hash.
      *
      * This checks that the hash function is available and satisfies the
      * RFC 9380 requirements for this group (in particular that the hash
      * output is at least twice the target security level), that the curve
      * implementation supports hash to curve, and that the required message
      * expansion (currently just expand_message_xmd) is included in the build.
      */
      bool hash_to_curve_supported(std::string_view hash_fn) const;

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
      * Look up the parameters of a builtin group by OID
      *
      * For internal use only
      *
      * @param oid the OID of the group to look up
      * @return the group data, or nullptr if the OID is not a known group
      *
      * TODO(Botan4): Move this to an internal header
      */
      static std::shared_ptr<EC_Group_Data> EC_group_info(const OID& oid);

      /**
      * Discard all cached and application registered group data
      *
      * For internal use only
      *
      * @warning this invalidates pointers and can cause memory corruption.
      * This function exists only to be called in tests.
      *
      * @return the number of groups which were discarded
      *
      * TODO(Botan4): Move this to an internal header
      */
      static size_t clear_registered_curve_data();

      /**
      * Identify a builtin group by its order
      *
      * For internal use only
      *
      * @param order the group order to look up
      * @return the OID of the matching group, or an empty OID if none matches
      *
      * TODO(Botan4): Move this to an internal header
      */
      static OID EC_group_identity_from_order(const BigInt& order);

      /**
      * For internal use only
      * @return the inner representation of this group
      */
      const std::shared_ptr<const EC_Group_Data>& _data() const { return m_data; }

   private:
      friend class EC_Group_Data_Map;
      friend class EC_Scalar;
      friend class EC_AffinePoint;

      static EC_Group_Data_Map& ec_group_data();

      explicit EC_Group(std::shared_ptr<const EC_Group_Data> data);

      static bool verify_generator_order(std::shared_ptr<const EC_Group_Data> data);

      static std::pair<std::shared_ptr<const EC_Group_Data>, bool> DER_decode_EC_group(std::span<const uint8_t> der);

      static std::shared_ptr<EC_Group_Data> load_EC_group_info(const char* p,
                                                               const char* a,
                                                               const char* b,
                                                               const char* g_x,
                                                               const char* g_y,
                                                               const char* order,
                                                               const OID& oid);

      const EC_Group_Data& data() const;

      // Member data
      std::shared_ptr<const EC_Group_Data> m_data;
      bool m_explicit_encoding = false;
};

/**
* Test if two groups describe different curves
* @param lhs the first group
* @param rhs the second group
* @return true if the two groups are not equal
*/
inline bool operator!=(const EC_Group& lhs, const EC_Group& rhs) {
   return !(lhs == rhs);
}

}  // namespace Botan

#endif
