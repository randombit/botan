/*
* BER Decoder
* (C) 1999-2010,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_BER_DECODER_H_
#define BOTAN_BER_DECODER_H_

#include <botan/asn1_obj.h>
#include <botan/secmem.h>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <type_traits>
#include <utility>

namespace Botan {

class BigInt;
class DataSource;

/**
* BER Decoding Object
*/
class BOTAN_PUBLIC_API(2, 0) BER_Decoder final {
   public:
      /**
      * Controls what encoding rules the decoder accepts.
      */
      class BOTAN_PUBLIC_API(3, 12) Limits final {
         public:
            /**
            * The default maximum size in bytes of a single decoded object.
            */
            static constexpr size_t DefaultMaxObjectSize = 128 * 1024 * 1024;

            /**
            * Accept only DER encodings
            */
            static Limits DER() { return Limits(false, 0, false, DefaultMaxObjectSize, false); }

            /**
            * Accept non-canonical BER encodings.
            *
            * @param max_nested_indef maximum number of nested indefinite-length encodings accepted
            */
            static Limits BER(size_t max_nested_indef = 16) {
               return Limits(true, max_nested_indef, false, DefaultMaxObjectSize, false);
            }

            /**
            * If true, non-canonical BER encodings are accepted
            */
            bool allow_ber_encoding() const { return m_allow_ber; }

            /**
            * If true, only DER encodings are accepted
            */
            bool require_der_encoding() const { return !allow_ber_encoding(); }

            /**
            * The maximum number of nested indefinite-length encodings accepted
            */
            size_t max_nested_indefinite_length() const { return m_max_nested_indef; }

            /**
            * If true, a standalone EOC marker (one that does not terminate an
            * indefinite-length encoding) is skipped rather than rejected. Some
            * BER producers emit trailing EOC markers; accepting them is needed to
            * parse such data (eg CMS signatures in PDFs). Off by default.
            */
            bool allow_standalone_eoc() const { return m_allow_standalone_eoc; }

            /**
            * The maximum size in bytes of a single decoded object, or nullopt if
            * no object size limit is enforced.
            */
            std::optional<size_t> max_object_size() const { return m_max_object_size; }

            /**
            * If true, a DER component that is explicitly encoded with a value
            * equal to its DEFAULT is rejected (such components must be omitted in
            * DER). Only applies in DER mode and only to fields decoded via
            * decode_default(). Off by default, since Botan and many other
            * implementations emit such components. See decode_default().
            */
            bool reject_default_value_encoding() const { return m_reject_default_value_encoding; }

            /**
            * Return a copy of these limits that tolerates standalone EOC markers.
            * See allow_standalone_eoc().
            */
            Limits with_standalone_eoc_allowed() const {
               Limits copy = *this;
               copy.m_allow_standalone_eoc = true;
               return copy;
            }

            /**
            * Return a copy of these limits with the given maximum object size.
            * A value of nullopt disables the object size limit. See
            * max_object_size().
            */
            Limits with_max_object_size(std::optional<size_t> max_object_size) const {
               Limits copy = *this;
               copy.m_max_object_size = max_object_size;
               return copy;
            }

            /**
            * Return a copy of these limits that rejects DER components encoded
            * equal to their DEFAULT value. See reject_default_value_encoding().
            */
            Limits with_default_value_encoding_rejected() const {
               Limits copy = *this;
               copy.m_reject_default_value_encoding = true;
               return copy;
            }

            /**
            * Compare two sets of limits for equality
            */
            bool operator==(const Limits&) const = default;

         private:
            Limits(bool allow_ber,
                   size_t max_nested_indef,
                   bool allow_standalone_eoc,
                   std::optional<size_t> max_object_size,
                   bool reject_default_value_encoding) :
                  m_allow_ber(allow_ber),
                  m_max_nested_indef(max_nested_indef),
                  m_allow_standalone_eoc(allow_standalone_eoc),
                  m_max_object_size(max_object_size),
                  m_reject_default_value_encoding(reject_default_value_encoding) {}

            bool m_allow_ber;
            size_t m_max_nested_indef;
            bool m_allow_standalone_eoc;
            std::optional<size_t> m_max_object_size;
            bool m_reject_default_value_encoding;
      };

      /**
      * Set up to BER decode the data in buf of length len
      */
      BOTAN_DEPRECATED("Use BER_Decoder(span) constructor")
      BER_Decoder(const uint8_t buf[], size_t len, Limits limits = Limits::BER()) :
            BER_Decoder(std::span{buf, len}, limits) {}

      /**
      * Set up to BER decode the data in buf
      */
      explicit BER_Decoder(std::span<const uint8_t> buf, Limits limits = Limits::BER());

      /**
      * Set up to BER decode the data in src
      */
      explicit BER_Decoder(DataSource& src, Limits limits = Limits::BER());

      /**
      * Set up to BER decode the data in obj
      */
      BOTAN_FUTURE_EXPLICIT BER_Decoder(const BER_Object& obj, Limits limits = Limits::BER()) :
            BER_Decoder(obj.data(), limits) {}

      /**
      * Set up to BER decode the data in obj
      * TODO(Botan4) remove this?
      */
      BOTAN_FUTURE_EXPLICIT BER_Decoder(BER_Object&& obj) : BER_Decoder(std::move(obj), nullptr) {}

      /**
      * Set up to BER decode the data in obj, taking ownership of its contents
      */
      BER_Decoder(BER_Object&& obj, Limits limits);

      BER_Decoder(const BER_Decoder& other) = delete;

      /**
      * Move constructor
      */
      BER_Decoder(BER_Decoder&& other) noexcept;

      BER_Decoder& operator=(const BER_Decoder&) = delete;

      /**
      * Move assignment
      */
      BER_Decoder& operator=(BER_Decoder&&) noexcept;

      /**
      * Returns the limits currently applied to this decoder
      */
      Limits limits() const { return m_limits; }

      /**
      * Get the next object in the data stream.
      * If EOF, returns an object with type NO_OBJECT.
      */
      BER_Object get_next_object();

      /**
      * Get the next object in the data stream, storing it in @p ber
      *
      * If EOF, @p ber is set to an object with type NO_OBJECT.
      */
      BER_Decoder& get_next(BER_Object& ber) {
         ber = get_next_object();
         return (*this);
      }

      /**
      * Peek at the next object without removing it from the stream
      *
      * If an object has been pushed, then it returns that object.
      * Otherwise it reads the next object and pushes it. Thus, a you
      * call peek_next_object followed by push_back without a
      * subsequent read, it will fail.
      */
      const BER_Object& peek_next_object();

      /**
      * Push an object back onto the stream. Throws if another
      * object was previously pushed and has not been subsequently
      * read out.
      */
      void push_back(const BER_Object& obj);

      /**
      * Push an object back onto the stream. Throws if another
      * object was previously pushed and has not been subsequently
      * read out.
      */
      void push_back(BER_Object&& obj);

      /**
      * Return true if there is at least one more item remaining
      */
      bool more_items() const;

      /**
      * Verify the stream is concluded, throws otherwise.
      * Returns (*this)
      */
      BER_Decoder& verify_end();

      /**
      * Verify the stream is concluded, throws otherwise.
      * Returns (*this)
      */
      BER_Decoder& verify_end(std::string_view err_msg);

      /**
      * Discard any data that remains unread
      * Returns (*this)
      */
      BER_Decoder& discard_remaining();

      /**
      * Start decoding a constructed object, returning a decoder for its contents.
      * The returned decoder must be closed with end_cons().
      *
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder start_cons(ASN1_Type type_tag, ASN1_Class class_tag);

      /**
      * Start decoding a SEQUENCE, returning a decoder for its contents.
      * The returned decoder must be closed with end_cons().
      */
      BER_Decoder start_sequence() { return start_cons(ASN1_Type::Sequence, ASN1_Class::Universal); }

      /**
      * Start decoding a SET, returning a decoder for its contents.
      * The returned decoder must be closed with end_cons().
      */
      BER_Decoder start_set() { return start_cons(ASN1_Type::Set, ASN1_Class::Universal); }

      /**
      * Start decoding an IMPLICIT context specific constructed object, returning
      * a decoder for its contents. The returned decoder must be closed with
      * end_cons().
      *
      * @param tag the expected context specific tag number
      */
      BER_Decoder start_context_specific(uint32_t tag) {
         return start_cons(ASN1_Type(tag), ASN1_Class::ContextSpecific);
      }

      /**
      * Start decoding an EXPLICIT context specific constructed object, returning
      * a decoder for its contents. The returned decoder must be closed with
      * end_cons().
      *
      * @param tag the expected context specific tag number
      */
      BER_Decoder start_explicit_context_specific(uint32_t tag) {
         return start_cons(ASN1_Type(tag), ASN1_Class::ExplicitContextSpecific);
      }

      /**
      * Finish decoding a constructed data, throws if any data remains.
      * Returns the parent of *this (ie the object on which start_cons was called).
      */
      BER_Decoder& end_cons();

      /**
      * Get next object and copy value to POD type
      * Asserts value length is equal to POD type sizeof.
      * Asserts Type tag and optional Class tag according to parameters.
      * Copy value to POD type (struct, union, C-style array, std::array, etc.).
      * @param out POD type reference where to copy object value
      * @param type_tag ASN1_Type enum to assert type on object read
      * @param class_tag ASN1_Type enum to assert class on object read (default: CONTEXT_SPECIFIC)
      * @return this reference
      */
      template <typename T>
      BER_Decoder& get_next_value(T& out, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific)
         requires std::is_standard_layout_v<T> && std::is_trivial_v<T>
      {
         const BER_Object obj = get_next_value(sizeof(T), type_tag, class_tag);

         std::memcpy(reinterpret_cast<uint8_t*>(&out), obj.bits(), obj.length());

         return (*this);
      }

      /**
      * Save all the bytes remaining in the source
      *
      * @param out where the remaining bytes are written
      */
      template <typename Alloc>
      BER_Decoder& raw_bytes(std::vector<uint8_t, Alloc>& out) {
         out.clear();
         uint8_t buf[64];
         while(const size_t got = this->read_bytes(std::span{buf})) {
            out.insert(out.end(), buf, buf + got);
         }
         return (*this);
      }

      /**
      * Decode a BER encoded NULL, throwing if the next object is anything else
      */
      BER_Decoder& decode_null();

      /**
      * Decode a BER encoded BOOLEAN
      */
      BER_Decoder& decode(bool& out) { return decode(out, ASN1_Type::Boolean, ASN1_Class::Universal); }

      /**
      * Decode a small BER encoded INTEGER
      */
      BER_Decoder& decode(size_t& out) { return decode(out, ASN1_Type::Integer, ASN1_Class::Universal); }

      /**
      * Decode a BER encoded INTEGER
      */
      BER_Decoder& decode(BigInt& out) { return decode(out, ASN1_Type::Integer, ASN1_Class::Universal); }

      /**
      * Decode the next object as an OCTET STRING and return its contents
      */
      std::vector<uint8_t> get_next_octet_string() {
         std::vector<uint8_t> out_vec;
         decode(out_vec, ASN1_Type::OctetString);
         return out_vec;
      }

      /**
      * BER decode a BIT STRING or OCTET STRING
      *
      * @param out where the contents are written
      * @param real_type either ASN1_Type::OctetString or ASN1_Type::BitString
      */
      template <typename Alloc>
      BER_Decoder& decode(std::vector<uint8_t, Alloc>& out, ASN1_Type real_type) {
         return decode(out, real_type, real_type, ASN1_Class::Universal);
      }

      /**
      * Decode a BOOLEAN with an IMPLICIT tagging
      *
      * @param v where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder& decode(bool& v, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Decode a small INTEGER with an IMPLICIT tagging
      *
      * @param v where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder& decode(size_t& v, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Decode an INTEGER with an IMPLICIT tagging
      *
      * @param v where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder& decode(BigInt& v, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Decode a BIT STRING or OCTET STRING with an IMPLICIT tagging
      *
      * @param v where the contents are written
      * @param real_type either ASN1_Type::OctetString or ASN1_Type::BitString
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder& decode(std::vector<uint8_t>& v,
                          ASN1_Type real_type,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Decode a BIT STRING or OCTET STRING with an IMPLICIT tagging
      *
      * @param v where the contents are written
      * @param real_type either ASN1_Type::OctetString or ASN1_Type::BitString
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder& decode(secure_vector<uint8_t>& v,
                          ASN1_Type real_type,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Decode a BIT STRING, retaining the count of unused bits
      *
      * @param out where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder& decode_bitstring(ASN1_BitString& out,
                                    ASN1_Type type_tag = ASN1_Type::BitString,
                                    ASN1_Class class_tag = ASN1_Class::Universal);

      /**
      * Decode a BIT STRING, throwing unless it has no unused bits
      *
      * @param out where the bits are written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      template <typename Alloc>
      BER_Decoder& decode_octet_aligned_bitstring(std::vector<uint8_t, Alloc>& out,
                                                  ASN1_Type type_tag = ASN1_Type::BitString,
                                                  ASN1_Class class_tag = ASN1_Class::Universal) {
         ASN1_BitString bits;
         decode_bitstring(bits, type_tag, class_tag);

         if(bits.unused_bits() != 0) {
            throw Decoding_Error("Expected octet-aligned BIT STRING");
         }

         out.assign(bits.bytes().begin(), bits.bytes().end());
         return (*this);
      }

      /**
      * Decode a BIT STRING that is actually a bit set, such as X.509 KeyUsage
      *
      * The first bit of the encoding becomes the most significant of the @p width
      * bits of @p bits. Throws if more than @p width bits are encoded, or in DER
      * mode if the encoding is not minimal (ie the final bit is unset).
      *
      * @param bits where the bit set is written
      * @param width the number of named bits, at most 64
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      BER_Decoder& decode_named_bitstring(uint64_t& bits,
                                          size_t width,
                                          ASN1_Type type_tag = ASN1_Type::BitString,
                                          ASN1_Class class_tag = ASN1_Class::Universal);

      /**
      * Request an object decode itself from this stream
      *
      * @param obj the object to decode into
      * @param type_tag must be NoObject; implicit tagging is not supported here
      * @param class_tag must be NoObject; implicit tagging is not supported here
      */
      BER_Decoder& decode(ASN1_Object& obj,
                          ASN1_Type type_tag = ASN1_Type::NoObject,
                          ASN1_Class class_tag = ASN1_Class::NoObject);

      /**
      * Decode an integer value which is typed as an octet string
      */
      BER_Decoder& decode_octet_string_bigint(BigInt& b);

      /**
      * Decode a non-negative INTEGER that fits in at most @p T_bytes bytes
      *
      * Throws BER_Decoding_Error if the value is negative or too large.
      *
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      * @param T_bytes the maximum size of the value in bytes, at most 8
      */
      uint64_t decode_constrained_integer(ASN1_Type type_tag, ASN1_Class class_tag, size_t T_bytes);

      /**
      * Decode an INTEGER into an integral type, throwing if it does not fit
      *
      * @param out where the value is written
      */
      template <typename T>
      BER_Decoder& decode_integer_type(T& out) {
         return decode_integer_type<T>(out, ASN1_Type::Integer, ASN1_Class::Universal);
      }

      /**
      * Decode an INTEGER with an IMPLICIT tagging into an integral type,
      * throwing if it does not fit
      *
      * @param out where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      template <typename T>
      BER_Decoder& decode_integer_type(T& out, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific) {
         out = static_cast<T>(decode_constrained_integer(type_tag, class_tag, sizeof(out)));
         return (*this);
      }

      /**
      * Decode an OPTIONAL field, setting @p out to @p default_value if absent
      *
      * @param out where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      * @param default_value the value used if the field is not present
      */
      template <typename T>
      BER_Decoder& decode_optional(T& out, ASN1_Type type_tag, ASN1_Class class_tag, const T& default_value = T()) {
         std::optional<T> optval;
         this->decode_optional(optval, type_tag, class_tag);
         out = optval ? *optval : default_value;
         return (*this);
      }

      /**
      * Decode a field carrying an ASN.1 DEFAULT value: if the field is absent
      * @p out is set to @p default_value. Unlike decode_optional this is only
      * for fields with a DEFAULT (not bare OPTIONAL fields): when the decoder is
      * configured with Limits::with_default_value_encoding_rejected() and is in
      * DER mode, a field that is present but equal to @p default_value is
      * rejected, since DER requires such components to be omitted.
      */
      template <typename T>
      BER_Decoder& decode_default(T& out, ASN1_Type type_tag, ASN1_Class class_tag, const T& default_value) {
         std::optional<T> optval;
         this->decode_optional(optval, type_tag, class_tag);
         if(optval.has_value()) {
            if(m_limits.require_der_encoding() && m_limits.reject_default_value_encoding() &&
               *optval == default_value) {
               throw BER_Decoding_Error("DER component encoded with its DEFAULT value");
            }
            out = std::move(*optval);
         } else {
            out = default_value;
         }
         return (*this);
      }

      /**
      * Decode an OPTIONAL field, setting @p optval to nullopt if absent
      *
      * @param optval where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      */
      template <typename T>
      BER_Decoder& decode_optional(std::optional<T>& optval, ASN1_Type type_tag, ASN1_Class class_tag);

      /**
      * Decode an OPTIONAL IMPLICIT tagged field, setting @p out to
      * @p default_value if absent
      *
      * @param out where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      * @param real_type the type tag the contents should be parsed as
      * @param real_class the class tag the contents should be parsed as
      * @param default_value the value used if the field is not present
      */
      template <typename T>
      BER_Decoder& decode_optional_implicit(T& out,
                                            ASN1_Type type_tag,
                                            ASN1_Class class_tag,
                                            ASN1_Type real_type,
                                            ASN1_Class real_class,
                                            const T& default_value = T());

      /**
      * Decode an OPTIONAL field identified by a context-specific tag number.
      *
      * If the next object is tagged [tag_no] with class @p class_tag, @p fn is
      * invoked to decode it (fn must consume exactly that object). Otherwise the
      * stream is left unchanged and fn is not called.
      *
      * For a SEQUENCE of optional tagged fields that (per DER) appear at most
      * once and in increasing tag order: call this once per field in tag order,
      * then end_cons(), which rejects any unconsumed object (i.e. a duplicate,
      * out-of-order, or unknown-tag field).
      */
      template <typename F>
      BER_Decoder& decode_optional_field(uint32_t tag_no, ASN1_Class class_tag, F&& fn) {
         if(peek_next_object().is_a(tag_no, class_tag)) {
            std::forward<F>(fn)(*this);
         }
         return (*this);
      }

      /**
      * Decode an already-extracted BER_Object as if its tag were
      * `real_type`/`real_class`. Used to consume IMPLICIT-tagged values
      * whose body matches a different universal type (e.g. a
      * context-specific [8] body that should be parsed as an OID).
      */
      template <typename T>
      BER_Decoder& decode_implicit(BER_Object obj, T& out, ASN1_Type real_type, ASN1_Class real_class) {
         obj.set_tagging(real_type, real_class);
         push_back(std::move(obj));
         if constexpr(std::is_base_of_v<ASN1_Object, T>) {
            // The object was re-tagged above; decode_from checks the real tag itself
            return decode(out);
         } else {
            return decode(out, real_type, real_class);
         }
      }

      /**
      * Read the next object, requiring it be tagged `type_tag`/`class_tag`, and
      * decode it as if its tag were `real_type`/`real_class`.
      *
      * @param out where the value is written
      * @param type_tag the expected type tag
      * @param class_tag the expected class tag
      * @param real_type the type tag the contents should be parsed as
      * @param real_class the class tag the contents should be parsed as
      */
      template <typename T>
      BER_Decoder& decode_implicit(
         T& out, ASN1_Type type_tag, ASN1_Class class_tag, ASN1_Type real_type, ASN1_Class real_class) {
         BER_Object obj = get_next_object();
         obj.assert_is_a(type_tag, class_tag);
         return decode_implicit(std::move(obj), out, real_type, real_class);
      }

      /**
      * Decode a constructed object containing a list of homogeneously typed values
      *
      * @param vec where the values are appended
      * @param type_tag the expected type tag of the constructed object
      * @param class_tag the expected class tag of the constructed object
      */
      template <typename T>
      BER_Decoder& decode_list(std::vector<T>& vec,
                               ASN1_Type type_tag = ASN1_Type::Sequence,
                               ASN1_Class class_tag = ASN1_Class::Universal);

      /**
      * Decode a list of homogeneously typed values if one is present
      *
      * @param vec where the values are appended
      * @param type_tag the expected type tag of the constructed object
      * @param class_tag the expected class tag of the constructed object
      * @return true if the list was present
      */
      template <typename T>
      bool decode_optional_list(std::vector<T>& vec,
                                ASN1_Type type_tag = ASN1_Type::Sequence,
                                ASN1_Class class_tag = ASN1_Class::Universal);

      /**
      * Decode a value and throw unless it equals the expected value
      *
      * @param expected the value the encoding must have
      * @param error_msg the message of the exception thrown on a mismatch
      */
      template <typename T>
      BER_Decoder& decode_and_check(const T& expected, std::string_view error_msg) {
         T actual;
         decode(actual);

         if(actual != expected) {
            throw Decoding_Error(error_msg);
         }

         return (*this);
      }

      /**
      * Decode an OPTIONAL string type, clearing @p out if it is absent
      *
      * @param out where the contents are written
      * @param real_type the type tag the contents should be parsed as
      * @param expected_tag the expected tag number
      * @param class_tag the expected class tag
      */
      template <typename Alloc>
      BER_Decoder& decode_optional_string(std::vector<uint8_t, Alloc>& out,
                                          ASN1_Type real_type,
                                          uint32_t expected_tag,
                                          ASN1_Class class_tag = ASN1_Class::ContextSpecific) {
         BER_Object obj = get_next_object();

         const ASN1_Type type_tag = static_cast<ASN1_Type>(expected_tag);

         if(obj.is_a(type_tag, class_tag)) {
            if(class_tag == ASN1_Class::ExplicitContextSpecific) {
               BER_Decoder(obj, m_limits).decode(out, real_type).verify_end();
            } else {
               push_back(std::move(obj));
               decode(out, real_type, type_tag, class_tag);
            }
         } else {
            out.clear();
            push_back(std::move(obj));
         }

         return (*this);
      }

      /**
      * Decode an OPTIONAL string type, clearing @p out if it is absent
      *
      * @param out where the contents are written
      * @param real_type the type tag the contents should be parsed as
      * @param expected_tag the expected type tag
      * @param class_tag the expected class tag
      */
      template <typename Alloc>
      BER_Decoder& decode_optional_string(std::vector<uint8_t, Alloc>& out,
                                          ASN1_Type real_type,
                                          ASN1_Type expected_tag,
                                          ASN1_Class class_tag = ASN1_Class::ContextSpecific) {
         return decode_optional_string(out, real_type, static_cast<uint32_t>(expected_tag), class_tag);
      }

      /**
      * Decode an OPTIONAL BIT STRING with no unused bits, clearing @p out if it
      * is absent
      *
      * @param out where the bits are written
      * @param expected_tag the expected tag number
      * @param class_tag the expected class tag
      */
      template <typename Alloc>
      BER_Decoder& decode_optional_octet_aligned_bitstring(std::vector<uint8_t, Alloc>& out,
                                                           uint32_t expected_tag,
                                                           ASN1_Class class_tag = ASN1_Class::ContextSpecific) {
         BER_Object obj = get_next_object();

         const ASN1_Type type_tag = static_cast<ASN1_Type>(expected_tag);

         if(obj.is_a(type_tag, class_tag)) {
            if(class_tag == ASN1_Class::ExplicitContextSpecific) {
               BER_Decoder(obj, m_limits).decode_octet_aligned_bitstring(out).verify_end();
            } else {
               push_back(std::move(obj));
               decode_octet_aligned_bitstring(out, type_tag, class_tag);
            }
         } else {
            out.clear();
            push_back(std::move(obj));
         }

         return (*this);
      }

      /**
      * Decode an OPTIONAL BIT STRING with no unused bits, clearing @p out if it
      * is absent
      *
      * @param out where the bits are written
      * @param expected_tag the expected type tag
      * @param class_tag the expected class tag
      */
      template <typename Alloc>
      BER_Decoder& decode_optional_octet_aligned_bitstring(std::vector<uint8_t, Alloc>& out,
                                                           ASN1_Type expected_tag,
                                                           ASN1_Class class_tag = ASN1_Class::ContextSpecific) {
         return decode_optional_octet_aligned_bitstring(out, static_cast<uint32_t>(expected_tag), class_tag);
      }

      ~BER_Decoder();

   private:
      BER_Decoder(BER_Object&& obj, BER_Decoder* parent);

      std::optional<uint8_t> read_next_byte();

      size_t read_bytes(std::span<uint8_t> out);

      BER_Object get_next_value(size_t sizeofT, ASN1_Type type_tag, ASN1_Class class_tag);

      Limits m_limits;
      BER_Decoder* m_parent = nullptr;
      BER_Object m_pushed;
      // either m_data_src.get() or an unowned pointer
      DataSource* m_source;
      std::unique_ptr<DataSource> m_data_src;
};

/**
* Decode an OPTIONAL or DEFAULT element
*/
template <typename T>
BER_Decoder& BER_Decoder::decode_optional(std::optional<T>& optval, ASN1_Type type_tag, ASN1_Class class_tag) {
   BER_Object obj = get_next_object();

   if(obj.is_a(type_tag, class_tag)) {
      T out{};
      if(class_tag == ASN1_Class::ExplicitContextSpecific) {
         BER_Decoder(obj, m_limits).decode(out).verify_end();
      } else {
         this->push_back(std::move(obj));
         if constexpr(std::is_base_of_v<ASN1_Object, T>) {
            // Object types check the tag in decode_from; a re-tagging
            // implicit override of an object is not supported here
            this->decode(out);
         } else {
            this->decode(out, type_tag, class_tag);
         }
      }
      optval = std::move(out);
   } else {
      this->push_back(std::move(obj));
      optval = std::nullopt;
   }

   return (*this);
}

/**
* Decode an OPTIONAL or DEFAULT element with an IMPLICIT tagging
*/
template <typename T>
BER_Decoder& BER_Decoder::decode_optional_implicit(T& out,
                                                   ASN1_Type type_tag,
                                                   ASN1_Class class_tag,
                                                   ASN1_Type real_type,
                                                   ASN1_Class real_class,
                                                   const T& default_value) {
   BER_Object obj = get_next_object();

   if(obj.is_a(type_tag, class_tag)) {
      decode_implicit(std::move(obj), out, real_type, real_class);
   } else {
      // Not what we wanted, push it back on the stream
      out = default_value;
      push_back(std::move(obj));
   }

   return (*this);
}

/**
* Decode a list of homogeneously typed values
*/
template <typename T>
BER_Decoder& BER_Decoder::decode_list(std::vector<T>& vec, ASN1_Type type_tag, ASN1_Class class_tag) {
   BER_Decoder list = start_cons(type_tag, class_tag);

   while(list.more_items()) {
      T value;
      list.decode(value);
      vec.push_back(std::move(value));
   }

   list.end_cons();

   return (*this);
}

/**
* Decode an optional list of homogeneously typed values
*/
template <typename T>
bool BER_Decoder::decode_optional_list(std::vector<T>& vec, ASN1_Type type_tag, ASN1_Class class_tag) {
   if(peek_next_object().is_a(type_tag, class_tag)) {
      decode_list(vec, type_tag, class_tag);
      return true;
   }

   return false;
}

}  // namespace Botan

#endif
