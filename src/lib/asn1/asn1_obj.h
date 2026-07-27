/*
* (C) 1999-2007,2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASN1_OBJECT_TYPES_H_
#define BOTAN_ASN1_OBJECT_TYPES_H_

#include <botan/exceptn.h>
#include <iosfwd>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class BER_Decoder;
class DER_Encoder;
class ASN1_Time;  // in asn1_time.h

/**
* Alias for ASN1_Time, reflecting the name used by the X.509 ASN.1 modules
*/
typedef ASN1_Time X509_Time;

/**
* ASN.1 Class Tags
*/
enum class ASN1_Class : uint32_t /* NOLINT(performance-enum-size) */ {
   Universal = 0b0000'0000,
   Application = 0b0100'0000,
   ContextSpecific = 0b1000'0000,
   Private = 0b1100'0000,

   Constructed = 0b0010'0000,
   ExplicitContextSpecific = Constructed | ContextSpecific,

   NoObject = 0xFF00
};

/**
* ASN.1 Type Tags
*/
enum class ASN1_Type : uint32_t /* NOLINT(performance-enum-size) */ {
   Eoc = 0x00,
   Boolean = 0x01,
   Integer = 0x02,
   BitString = 0x03,
   OctetString = 0x04,
   Null = 0x05,
   ObjectId = 0x06,
   Enumerated = 0x0A,
   Sequence = 0x10,
   Set = 0x11,

   Utf8String = 0x0C,
   NumericString = 0x12,
   PrintableString = 0x13,
   TeletexString = 0x14,
   Ia5String = 0x16,
   VisibleString = 0x1A,
   UniversalString = 0x1C,
   BmpString = 0x1E,

   UtcTime = 0x17,
   GeneralizedTime = 0x18,

   NoObject = 0xFF00,
};

/**
* Return true if the two class tags have any bits in common
*/
inline bool intersects(ASN1_Class x, ASN1_Class y) {
   return (static_cast<uint32_t>(x) & static_cast<uint32_t>(y)) != 0;
}

/**
* Return the bitwise combination of two type tags
*/
inline ASN1_Type operator|(ASN1_Type x, ASN1_Type y) {
   return static_cast<ASN1_Type>(static_cast<uint32_t>(x) | static_cast<uint32_t>(y));
}

/**
* Return the bitwise combination of two class tags
*/
inline ASN1_Class operator|(ASN1_Class x, ASN1_Class y) {
   return static_cast<ASN1_Class>(static_cast<uint32_t>(x) | static_cast<uint32_t>(y));
}

/**
* Combine a type tag and a class tag into a single tagging value
*/
inline uint32_t operator|(ASN1_Type x, ASN1_Class y) {
   return static_cast<uint32_t>(x) | static_cast<uint32_t>(y);
}

/**
* Combine a class tag and a type tag into a single tagging value
*/
inline uint32_t operator|(ASN1_Class x, ASN1_Type y) {
   return static_cast<uint32_t>(x) | static_cast<uint32_t>(y);
}

/**
* Return a descriptive string for an ASN.1 type tag
*/
std::string BOTAN_UNSTABLE_API asn1_tag_to_string(ASN1_Type type);

/**
* Return a descriptive string for an ASN.1 class tag
*/
std::string BOTAN_UNSTABLE_API asn1_class_to_string(ASN1_Class type);

/**
* Basic ASN.1 Object Interface
*/
class BOTAN_PUBLIC_API(2, 0) ASN1_Object {
   public:
      /**
      * Encode whatever this object is into to
      * @param to the DER_Encoder that will be written to
      */
      virtual void encode_into(DER_Encoder& to) const = 0;

      /**
      * Decode whatever this object is from from
      * @param from the BER_Decoder that will be read from
      */
      virtual void decode_from(BER_Decoder& from) = 0;

      /**
      * Return the encoding of this object. This is a convenience
      * method when just one object needs to be serialized. Use
      * DER_Encoder for complicated encodings.
      */
      std::vector<uint8_t> BER_encode() const;

      /**
      * Default constructor
      */
      ASN1_Object() = default;

      /**
      * Copy constructor
      */
      ASN1_Object(const ASN1_Object&) = default;

      /**
      * Copy assignment
      */
      ASN1_Object& operator=(const ASN1_Object&) = default;

      /**
      * Move constructor
      */
      ASN1_Object(ASN1_Object&&) = default;

      /**
      * Move assignment
      */
      ASN1_Object& operator=(ASN1_Object&&) = default;

      virtual ~ASN1_Object() = default;
};

/**
* ASN.1 BIT STRING with explicit unused-bit count.
*/
class BOTAN_PUBLIC_API(3, 13) ASN1_BitString final {
   public:
      /**
      * Create an empty BIT STRING
      */
      ASN1_BitString() = default;

      /**
      * Create a BIT STRING from the given bits
      *
      * @param bytes the bits, without the leading unused-bit count octet
      * @param unused_bits the number of unused bits in the final byte
      *
      * Throws Invalid_Argument if unused_bits is 8 or larger, if unused_bits is
      * non-zero for an empty BIT STRING, or if any of the unused bits are set.
      */
      ASN1_BitString(std::vector<uint8_t> bytes, size_t unused_bits);

      /**
      * Create a BIT STRING from the given bits
      *
      * @param bytes the bits, without the leading unused-bit count octet
      * @param unused_bits the number of unused bits in the final byte
      *
      * Throws Invalid_Argument if unused_bits is 8 or larger, if unused_bits is
      * non-zero for an empty BIT STRING, or if any of the unused bits are set.
      */
      ASN1_BitString(std::span<const uint8_t> bytes, size_t unused_bits);

      /**
      * Return the bits, without the leading unused-bit count octet
      */
      std::span<const uint8_t> bytes() const { return std::span{m_bytes}; }

      /**
      * Return the number of unused bits in the final byte
      */
      size_t unused_bits() const { return m_unused_bits; }

      /**
      * Return the number of significant bits in this BIT STRING
      */
      size_t bit_length() const;

      /**
      * Return the value of a single bit, counting from the most significant bit
      * of the first byte
      *
      * Throws Invalid_Argument if bit is not less than bit_length()
      */
      bool bit_at(size_t bit) const;

   private:
      std::vector<uint8_t> m_bytes;
      size_t m_unused_bits = 0;
};

/**
* BER Encoded Object
*/
class BOTAN_PUBLIC_API(2, 0) BER_Object final {
   public:
      /**
      * Create an unset BER_Object
      */
      BER_Object() = default;

      /**
      * Copy constructor
      */
      BER_Object(const BER_Object& other) = default;

      /**
      * Move constructor
      */
      BER_Object(BER_Object&& other) = default;

      /**
      * Copy assignment
      */
      BER_Object& operator=(const BER_Object& other) = default;

      /**
      * Move assignment
      */
      BER_Object& operator=(BER_Object&& other) = default;

      ~BER_Object();

      /**
      * Return true if this object holds a value, ie if it was not read past the
      * end of the input
      */
      bool is_set() const { return m_type_tag != ASN1_Type::NoObject; }

      /**
      * Return the type and class tags combined into a single value
      */
      uint32_t tagging() const { return type_tag() | class_tag(); }

      /**
      * Return the type tag of this object
      */
      ASN1_Type type_tag() const { return m_type_tag; }

      /**
      * Return the class tag of this object
      */
      ASN1_Class class_tag() const { return m_class_tag; }

      /**
      * Return the type tag of this object, an alias for type_tag()
      */
      ASN1_Type type() const { return m_type_tag; }

      /**
      * Return the class tag of this object, an alias for class_tag()
      */
      ASN1_Class get_class() const { return m_class_tag; }

      /**
      * Return a pointer to the contents of this object, excluding the tag and
      * length header
      */
      const uint8_t* bits() const { return m_value.data(); }

      /**
      * Return the length in bytes of the contents of this object
      */
      size_t length() const { return m_value.size(); }

      /**
      * Return the contents of this object, excluding the tag and length header
      */
      std::span<const uint8_t> data() const { return std::span{m_value}; }

      /**
      * Throw BER_Decoding_Error unless this object has the expected tagging
      *
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      * @param descr a description of the object, used in the exception message
      */
      void assert_is_a(ASN1_Type type_tag, ASN1_Class class_tag, std::string_view descr = "object") const;

      /**
      * Return true if this object has the given tagging
      *
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      bool is_a(ASN1_Type type_tag, ASN1_Class class_tag) const;

      /**
      * Return true if this object has the given tagging
      *
      * @param type_tag the expected type tag, typically a context specific tag number
      * @param class_tag the expected class tag
      */
      bool is_a(int type_tag, ASN1_Class class_tag) const;

   private:
      ASN1_Type m_type_tag = ASN1_Type::NoObject;
      ASN1_Class m_class_tag = ASN1_Class::Universal;
      std::vector<uint8_t> m_value;

      friend class BER_Decoder;

      void set_tagging(ASN1_Type type_tag, ASN1_Class class_tag);

      uint8_t* mutable_bits(size_t length) {
         m_value.resize(length);
         return m_value.data();
      }
};

/*
* ASN.1 Utility Functions
*/
class DataSource;

namespace ASN1 {

/**
* Return the DER tag and length header of a SEQUENCE with the given contents length
* @param contents_len the length in bytes of the SEQUENCE contents
*/
std::vector<uint8_t> der_sequence_header(size_t contents_len);

/**
* Return the contents wrapped in a DER SEQUENCE
* @param val the contents of the SEQUENCE
*/
std::vector<uint8_t> put_in_sequence(const std::vector<uint8_t>& val);

/**
* Return the contents wrapped in a DER SEQUENCE
* @param bits the contents of the SEQUENCE
* @param len the length of bits in bytes
*/
std::vector<uint8_t> put_in_sequence(const uint8_t bits[], size_t len);

/**
* Return the contents of a BER object interpreted as a string
* @param obj the object whose contents are converted
*/
std::string to_string(const BER_Object& obj);

/**
* Heuristics tests; is this object possibly BER?
* @param src a data source that will be peeked at but not modified
*/
bool maybe_BER(DataSource& src);

}  // namespace ASN1

/**
* General BER Decoding Error Exception
*/
class BOTAN_PUBLIC_API(2, 0) BER_Decoding_Error : public Decoding_Error {
   public:
      /**
      * Create a BER decoding error
      * @param err a description of the problem encountered
      */
      explicit BER_Decoding_Error(std::string_view err);
};

/**
* Exception For Incorrect BER Taggings
*/
class BOTAN_PUBLIC_API(2, 0) BER_Bad_Tag final : public BER_Decoding_Error {
   public:
      /**
      * Create a bad tag error
      * @param msg a description of the problem encountered
      * @param tagging the offending tagging value
      */
      BER_Bad_Tag(std::string_view msg, uint32_t tagging);
};

/**
* This class represents ASN.1 object identifiers.
*/
class BOTAN_PUBLIC_API(2, 0) OID final : public ASN1_Object {
   public:
      /**
      * Create an uninitialised OID object
      */
      explicit OID() = default;

      /**
      * Construct an OID from a string.
      * @param str a string in the form "a.b.c" etc., where a,b,c are integers
      *
      * Note: it is currently required that each integer fit into 32 bits
      */
      explicit OID(std::string_view str);

      /**
      * Initialize an OID from a sequence of integer values
      */
      OID(std::initializer_list<uint32_t> init);

      /**
      * Initialize an OID from a vector of integer values
      */
      explicit OID(std::vector<uint32_t>&& init);

      /**
      * Construct an OID from a string.
      * @param str a string in the form "a.b.c" etc., where a,b,c are numbers
      *        or any known OID name (for example "RSA" or "X509v3.SubjectKeyIdentifier")
      */
      static OID from_string(std::string_view str);

      /**
      * Construct an OID from a name
      * @param name any known OID name (for example "RSA" or "X509v3.SubjectKeyIdentifier")
      */
      static std::optional<OID> from_name(std::string_view name);

      /**
      * Register a new OID in the internal table
      */
      static void register_oid(const OID& oid, std::string_view name);

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      /**
      * Find out whether this OID is empty
      * @return true is no OID value is set
      */
      bool empty() const { return m_id.empty(); }

      /**
      * Find out whether this OID has a value
      * @return true is this OID has a value
      */
      bool has_value() const { return !empty(); }

      /**
      * Get this OID as a dotted-decimal string
      * @return string representing this OID
      */
      std::string to_string() const;

      /**
      * If there is a known name associated with this OID, return that.
      * Otherwise return the result of to_string
      */
      std::string to_formatted_string() const;

      /**
      * If there is a known name associated with this OID, return that.
      * Otherwise return the empty string.
      */
      std::string human_name_or_empty() const;

      /**
      * If there is a known name associated with this OID, return that.
      * Otherwise return nullopt.
      */
      std::optional<std::string> registered_name() const;

      /**
      * Return true if the OID in *this is registered in the internal
      * set of constants as a known OID.
      */
      bool registered_oid() const;

      /**
      * Compare two OIDs.
      * @return true if they are equal, false otherwise
      */
      bool operator==(const OID& other) const { return m_id == other.m_id; }

      /**
      * Return a hash code for this OID
      *
      * This value is only meant as a std::unordered_map hash and
      * can change value from release to release.
      */
      uint64_t hash_code() const;

      /**
      * Check if this OID matches the provided value
      */
      bool matches(std::initializer_list<uint32_t> other) const;

      /**
      * Get this OID as list (vector) of its components.
      * @return vector representing this OID
      */
      BOTAN_DEPRECATED("Do not access the integer values, use eg to_string")
      const std::vector<uint32_t>& get_components() const {
         return m_id;
      }

      /**
      * Get this OID as list (vector) of its components.
      * @return vector representing this OID
      */
      BOTAN_DEPRECATED("Do not access the integer values, use eg to_string")
      const std::vector<uint32_t>& get_id() const {
         return m_id;
      }

   private:
      std::vector<uint32_t> m_id;
};

/**
* Write an OID to a stream, in the format produced by OID::to_string
* @param out the stream to write to
* @param oid the OID to write
* @return the stream
*/
BOTAN_PUBLIC_API(3, 0) std::ostream& operator<<(std::ostream& out, const OID& oid);

/**
* Compare two OIDs.
* @param a the first OID
* @param b the second OID
* @return true if a is not equal to b
*/
inline bool operator!=(const OID& a, const OID& b) {
   return !(a == b);
}

/**
* Compare two OIDs.
* @param a the first OID
* @param b the second OID
* @return true if a is lexicographically smaller than b
*/
BOTAN_PUBLIC_API(2, 0) bool operator<(const OID& a, const OID& b);

/**
* ASN.1 string type
* This class normalizes all inputs to a UTF-8 std::string
*/
class BOTAN_PUBLIC_API(2, 0) ASN1_String final : public ASN1_Object {
   public:
      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      /**
      * Return the string type tag this value was encoded with
      */
      ASN1_Type tagging() const { return m_tag; }

      /**
      * Return the value of this string, converted to UTF-8
      */
      const std::string& value() const { return m_utf8_str; }

      /**
      * Return the length in bytes of the UTF-8 representation of this string
      */
      size_t size() const { return value().size(); }

      /**
      * Return true if this string is empty
      */
      bool empty() const { return m_utf8_str.empty(); }

      /**
      * Return true iff this is a tag for a known string type we can handle.
      */
      static bool is_string_type(ASN1_Type tag);

      /**
      * Compare two strings, ignoring the type tag they were encoded with
      */
      bool operator==(const ASN1_String& other) const { return value() == other.value(); }

      friend bool operator<(const ASN1_String& a, const ASN1_String& b) { return a.value() < b.value(); }

      /**
      * Create a string, tagged as PrintableString if possible and otherwise as
      * Utf8String
      *
      * @param utf8 the value of the string, encoded as UTF-8
      */
      explicit ASN1_String(std::string_view utf8 = "");

      /**
      * Create a string with a specific type tag
      *
      * @param utf8 the value of the string, encoded as UTF-8
      * @param tag the string type tag to encode this value with
      *
      * Throws Invalid_Argument if tag is not a string type that is a subset of
      * UTF-8, or if utf8 is not a valid value for that type.
      */
      ASN1_String(std::string_view utf8, ASN1_Type tag);

   private:
      std::vector<uint8_t> m_data;
      std::string m_utf8_str;
      ASN1_Type m_tag;
};

/**
* Algorithm Identifier
*/
class BOTAN_PUBLIC_API(2, 0) AlgorithmIdentifier final : public ASN1_Object {
   public:
      /**
      * Selects how an absent parameters field is encoded
      */
      enum Encoding_Option : uint8_t { USE_NULL_PARAM, USE_EMPTY_PARAM }; /* NOLINT(*-use-enum-class) */

      void encode_into(DER_Encoder& to) const override;
      void decode_from(BER_Decoder& from) override;

      /**
      * Create an empty AlgorithmIdentifier
      */
      AlgorithmIdentifier() = default;

      /**
      * Create an AlgorithmIdentifier with no parameters
      * @param oid the algorithm OID
      * @param enc whether the empty parameters are encoded as NULL or omitted
      */
      AlgorithmIdentifier(const OID& oid, Encoding_Option enc);

      /**
      * Create an AlgorithmIdentifier with no parameters
      * @param oid_name a name or dotted decimal string identifying the algorithm
      * @param enc whether the empty parameters are encoded as NULL or omitted
      */
      AlgorithmIdentifier(std::string_view oid_name, Encoding_Option enc);

      /**
      * Create an AlgorithmIdentifier
      * @param oid the algorithm OID
      * @param params the DER encoded parameters
      */
      AlgorithmIdentifier(const OID& oid, const std::vector<uint8_t>& params);

      /**
      * Create an AlgorithmIdentifier
      * @param oid_name a name or dotted decimal string identifying the algorithm
      * @param params the DER encoded parameters
      */
      AlgorithmIdentifier(std::string_view oid_name, const std::vector<uint8_t>& params);

      /**
      * Return the algorithm OID
      */
      const OID& oid() const { return m_oid; }

      /**
      * Return the DER encoded parameters, which may be empty
      */
      const std::vector<uint8_t>& parameters() const { return m_parameters; }

      /**
      * Return the algorithm OID
      */
      BOTAN_DEPRECATED("Use AlgorithmIdentifier::oid") const OID& get_oid() const { return m_oid; }

      /**
      * Return the DER encoded parameters, which may be empty
      */
      BOTAN_DEPRECATED("Use AlgorithmIdentifier::parameters") const std::vector<uint8_t>& get_parameters() const {
         return m_parameters;
      }

      /**
      * Return true if the parameters consist of a single DER encoded NULL
      */
      bool parameters_are_null() const;

      /**
      * Return true if the parameters field is absent
      */
      bool parameters_are_empty() const { return m_parameters.empty(); }

      /**
      * Return true if the parameters field is absent or a single DER encoded NULL
      */
      bool parameters_are_null_or_empty() const { return parameters_are_empty() || parameters_are_null(); }

      /**
      * Return true if neither the OID nor the parameters have been set
      */
      bool empty() const { return m_oid.empty() && m_parameters.empty(); }

   private:
      OID m_oid;
      std::vector<uint8_t> m_parameters;
};

/**
* Compare two AlgorithmIdentifiers
*
* An absent parameters field and a parameters field consisting of a DER NULL are
* treated as equivalent.
*
* @param x the first AlgorithmIdentifier
* @param y the second AlgorithmIdentifier
* @return true if x is equal to y
*/
BOTAN_PUBLIC_API(2, 0) bool operator==(const AlgorithmIdentifier& x, const AlgorithmIdentifier& y);

/**
* Compare two AlgorithmIdentifiers
*
* @param x the first AlgorithmIdentifier
* @param y the second AlgorithmIdentifier
* @return true if x is not equal to y
*/
BOTAN_PUBLIC_API(2, 0) bool operator!=(const AlgorithmIdentifier& x, const AlgorithmIdentifier& y);

}  // namespace Botan

/**
* Specialization of std::hash allowing OIDs to be used as keys in unordered containers
*/
template <>
class std::hash<Botan::OID> {
   public:
      /**
      * Return a hash of the OID; see OID::hash_code
      */
      size_t operator()(const Botan::OID& oid) const noexcept { return static_cast<size_t>(oid.hash_code()); }
};

/*
In 3.11 ASN1_Time was split out to its own header as <chrono> is huge in C++20
However we continue to include this header (when not building the library),
to avoid breaking applications which would expect it to still be available.

TODO(Botan4) remove this
*/
#if defined(BOTAN_AMALGAMATION_H_) || (!defined(BOTAN_IS_BEING_BUILT) && !defined(__clang_analyzer__))
   #include <botan/asn1_time.h>
#endif

#endif
