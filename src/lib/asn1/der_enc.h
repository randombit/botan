/*
* DER Encoder
* (C) 1999-2007,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DER_ENCODER_H_
#define BOTAN_DER_ENCODER_H_

#include <botan/asn1_obj.h>
#include <botan/secmem.h>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace Botan {

class BigInt;

/**
* General DER Encoding Object
*/
class BOTAN_PUBLIC_API(2, 0) DER_Encoder final {
   public:
      /**
      * Callback type invoked with each chunk of encoded output
      */
      typedef std::function<void(const uint8_t[], size_t)> append_fn;

      /**
      * DER encode, writing to an internal buffer
      * Use get_contents or get_contents_unlocked to read the results
      * after all encoding is completed.
      */
      DER_Encoder() = default;

      /**
      * DER encode, writing to @param vec
      * If this constructor is used, get_contents* may not be called.
      */
      BOTAN_FUTURE_EXPLICIT DER_Encoder(secure_vector<uint8_t>& vec);

      /**
      * DER encode, writing to @param vec
      * If this constructor is used, get_contents* may not be called.
      */
      BOTAN_FUTURE_EXPLICIT DER_Encoder(std::vector<uint8_t>& vec);

      /**
      * DER encode, calling append to write output
      * If this constructor is used, get_contents* may not be called.
      */
      BOTAN_FUTURE_EXPLICIT DER_Encoder(append_fn append) : m_append_output(std::move(append)) {}

      /**
      * Return the encoded contents
      *
      * Throws Invalid_State if any constructed encoding is still open, or if
      * this encoder was constructed with an output vector or append function.
      */
      secure_vector<uint8_t> get_contents();

      /**
      * Return the encoded contents as a std::vector
      *
      * If using this function, instead pass a std::vector to the
      * constructor of DER_Encoder where the output will be placed. This
      * avoids several unnecessary copies.
      */
      BOTAN_DEPRECATED("Use DER_Encoder(vector) instead") std::vector<uint8_t> get_contents_unlocked();

      /**
      * Start a constructed encoding with the given tagging. Must be closed with
      * end_cons(). Contents are emitted in the order they are encoded.
      *
      * @param type_tag the type tag of the constructed encoding
      * @param class_tag the class tag of the constructed encoding
      */
      DER_Encoder& start_cons(ASN1_Type type_tag, ASN1_Class class_tag);

      /**
      * Start a SEQUENCE. Must be closed with end_cons().
      */
      DER_Encoder& start_sequence() { return start_cons(ASN1_Type::Sequence, ASN1_Class::Universal); }

      /**
      * Start a SET/SET OF. Must be closed with end_cons(). Contents are DER sorted.
      */
      DER_Encoder& start_set() { return start_cons(ASN1_Type::Set, ASN1_Class::Universal); }

      /**
       * Start a SET/SET OF with an alternate tag. Contents are still DER sorted.
       *
       * @param type_tag the type tag of the constructed encoding
       * @param class_tag the class tag of the constructed encoding
       */
      DER_Encoder& start_set(ASN1_Type type_tag, ASN1_Class class_tag);

      /**
      * Start a SET/SET OF with a context specific tag. Contents are still DER sorted.
      *
      * @param tag the context specific tag number
      */
      DER_Encoder& start_set(uint32_t tag) { return start_set(ASN1_Type(tag), ASN1_Class::ContextSpecific); }

      /**
      * Start an IMPLICIT context specific constructed encoding
      *
      * @param tag the context specific tag number
      */
      DER_Encoder& start_context_specific(uint32_t tag) {
         return start_cons(ASN1_Type(tag), ASN1_Class::ContextSpecific);
      }

      /**
      * Start an EXPLICIT context specific constructed encoding
      *
      * @param tag the context specific tag number
      */
      DER_Encoder& start_explicit_context_specific(uint32_t tag) {
         return start_cons(ASN1_Type(tag), ASN1_Class::ExplicitContextSpecific);
      }

      /**
      * Finish the innermost open constructed encoding
      *
      * Throws Invalid_State if no constructed encoding is open.
      */
      DER_Encoder& end_cons();

      /**
      * Start a context specific constructed encoding, an alias for
      * start_context_specific()
      *
      * @param type_tag the context specific tag number
      */
      DER_Encoder& start_explicit(uint16_t type_tag);

      /**
      * Finish the innermost open constructed encoding, an alias for end_cons()
      */
      DER_Encoder& end_explicit();

      /**
      * Insert raw bytes directly into the output stream
      */
      DER_Encoder& raw_bytes(const uint8_t val[], size_t len);

      /**
      * Insert raw bytes directly into the output stream
      */
      DER_Encoder& raw_bytes(std::span<const uint8_t> val) { return raw_bytes(val.data(), val.size()); }

      /**
      * Encode a NULL
      */
      DER_Encoder& encode_null();

      /**
      * Encode a BOOLEAN
      */
      DER_Encoder& encode(bool b);

      /**
      * Encode an INTEGER
      */
      DER_Encoder& encode(size_t s);

      /**
      * Encode an INTEGER
      */
      DER_Encoder& encode(const BigInt& n);

      /**
      * Encode an OCTET STRING or an octet aligned BIT STRING
      *
      * @param val the contents of the object
      * @param real_type either ASN1_Type::OctetString or ASN1_Type::BitString
      */
      DER_Encoder& encode(std::span<const uint8_t> val, ASN1_Type real_type);

      /**
       * Encode a BIT STRING, with `bits` not including the initial unused-bits octet.
       */
      DER_Encoder& encode_bitstring(std::span<const uint8_t> bits,
                                    size_t unused_bits = 0,
                                    ASN1_Type type_tag = ASN1_Type::BitString,
                                    ASN1_Class class_tag = ASN1_Class::Universal);

      /**
      * Encode a BIT STRING
      *
      * @param bits the value to encode
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      */
      DER_Encoder& encode_bitstring(const ASN1_BitString& bits,
                                    ASN1_Type type_tag = ASN1_Type::BitString,
                                    ASN1_Class class_tag = ASN1_Class::Universal);

      /**
      * Encode a BIT STRING with no unused bits
      *
      * @param bytes the bits to encode
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      */
      DER_Encoder& encode_octet_aligned_bitstring(std::span<const uint8_t> bytes,
                                                  ASN1_Type type_tag = ASN1_Type::BitString,
                                                  ASN1_Class class_tag = ASN1_Class::Universal) {
         return encode_bitstring(bytes, 0, type_tag, class_tag);
      }

      /**
      * Helper for encoding BIT STRING elements that are actually bit sets, rather
      * than being OCTET STRINGS with the wrong type.
      */
      DER_Encoder& encode_named_bitstring(uint64_t bits,
                                          size_t width,
                                          ASN1_Type type_tag = ASN1_Type::BitString,
                                          ASN1_Class class_tag = ASN1_Class::Universal);

      /**
      * Encode an OCTET STRING or an octet aligned BIT STRING
      *
      * @param val the contents of the object
      * @param len the length of val in bytes
      * @param real_type either ASN1_Type::OctetString or ASN1_Type::BitString
      */
      DER_Encoder& encode(const uint8_t val[], size_t len, ASN1_Type real_type) {
         return this->encode(std::span{val, len}, real_type);
      }

      /**
      * Encode a BOOLEAN with an IMPLICIT tagging
      *
      * @param b the value to encode
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      */
      DER_Encoder& encode(bool b, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Encode an INTEGER with an IMPLICIT tagging
      *
      * @param s the value to encode
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      */
      DER_Encoder& encode(size_t s, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Encode an INTEGER with an IMPLICIT tagging
      *
      * @param n the value to encode
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      */
      DER_Encoder& encode(const BigInt& n, ASN1_Type type_tag, ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Encode an OCTET STRING or octet aligned BIT STRING with an IMPLICIT tagging
      *
      * @param value the contents of the object
      * @param real_type either ASN1_Type::OctetString or ASN1_Type::BitString
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      */
      DER_Encoder& encode(std::span<const uint8_t> value,
                          ASN1_Type real_type,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific);

      /**
      * Encode an OCTET STRING or octet aligned BIT STRING with an IMPLICIT tagging
      *
      * @param v the contents of the object
      * @param len the length of v in bytes
      * @param real_type either ASN1_Type::OctetString or ASN1_Type::BitString
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      */
      DER_Encoder& encode(const uint8_t v[],
                          size_t len,
                          ASN1_Type real_type,
                          ASN1_Type type_tag,
                          ASN1_Class class_tag = ASN1_Class::ContextSpecific) {
         return encode(std::span{v, len}, real_type, type_tag, class_tag);
      }

      /**
      * Encode a value unless it is equal to the DEFAULT
      *
      * @param value the value to encode
      * @param default_value the value which should be omitted
      */
      template <typename T>
      BOTAN_DEPRECATED("Use the version that takes a std::optional")
      DER_Encoder& encode_optional(const T& value, const T& default_value) {
         if(value != default_value) {
            encode(value);
         }
         return (*this);
      }

      /**
      * Encode a value if it is set, otherwise write nothing
      *
      * @param value the value to encode
      */
      template <typename T>
      DER_Encoder& encode_optional(const std::optional<T>& value) {
         if(value) {
            encode(*value);
         }
         return (*this);
      }

      /**
      * Encode each element of the vector in turn
      *
      * @param values the values to encode
      */
      template <typename T>
      DER_Encoder& encode_list(const std::vector<T>& values) {
         for(size_t i = 0; i != values.size(); ++i) {
            encode(values[i]);
         }
         return (*this);
      }

      /**
      * Request for an object to encode itself to this stream
      *
      * @param obj the object to encode
      */
      DER_Encoder& encode(const ASN1_Object& obj);

      /**
      * Write the contents of another encoder to this stream if pred is true
      *
      * @param pred if false nothing is written
      * @param enc the encoder whose contents are written
      */
      DER_Encoder& encode_if(bool pred, DER_Encoder& enc) {
         if(pred) {
            return raw_bytes(enc.get_contents());
         }
         return (*this);
      }

      /**
      * Encode an object if pred is true
      *
      * @param pred if false nothing is written
      * @param obj the object to encode
      */
      DER_Encoder& encode_if(bool pred, const ASN1_Object& obj) {
         if(pred) {
            encode(obj);
         }
         return (*this);
      }

      /**
      * Encode an INTEGER if pred is true
      *
      * @param pred if false nothing is written
      * @param num the value to encode
      */
      DER_Encoder& encode_if(bool pred, size_t num) {
         if(pred) {
            encode(num);
         }
         return (*this);
      }

      /**
      * Encode a BOOLEAN if pred is true
      *
      * @param pred if false nothing is written
      * @param num the value to encode
      */
      DER_Encoder& encode_if(bool pred, bool num) {
         if(pred) {
            encode(num);
         }
         return (*this);
      }

      /**
      * Write a tag and length header followed by the given contents
      *
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      * @param rep the contents of the object
      * @param length the length of rep in bytes
      */
      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag, const uint8_t rep[], size_t length);

      /**
      * Write a tag and length header followed by the given contents
      *
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      * @param rep the contents of the object
      */
      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag, std::span<const uint8_t> rep) {
         return add_object(type_tag, class_tag, rep.data(), rep.size());
      }

      /**
      * Write a tag and length header followed by the given contents
      *
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      * @param rep the contents of the object
      */
      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag, const std::vector<uint8_t>& rep) {
         return add_object(type_tag, class_tag, std::span{rep});
      }

      /**
      * Write a tag and length header followed by the given contents
      *
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      * @param rep the contents of the object
      */
      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag, const secure_vector<uint8_t>& rep) {
         return add_object(type_tag, class_tag, std::span{rep});
      }

      /**
      * Write a tag and length header followed by the given contents
      *
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      * @param str the contents of the object
      */
      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag, std::string_view str);

      /**
      * Write a tag and length header followed by a single byte of contents
      *
      * @param type_tag the type tag to encode with
      * @param class_tag the class tag to encode with
      * @param val the contents of the object
      */
      DER_Encoder& add_object(ASN1_Type type_tag, ASN1_Class class_tag, uint8_t val);

      /**
       * Encode `value` and emit just its body bytes under an IMPLICIT
       * `type_tag`/`class_tag` (e.g. for `[N] IMPLICIT OBJECT IDENTIFIER` where the
       * body is an OID's arc bytes but the tag must be `[N]`). The
       * primitive/constructed bit is copied from `value`.
       */
      template <typename T>
      DER_Encoder& encode_implicit(const T& value,
                                   ASN1_Type type_tag,
                                   ASN1_Class class_tag = ASN1_Class::ContextSpecific) {
         std::vector<uint8_t> tlv;
         DER_Encoder(tlv).encode(value);
         return add_object_tlv(type_tag, class_tag, std::move(tlv));
      }

   private:
      DER_Encoder& add_object_tlv(ASN1_Type type_tag, ASN1_Class class_tag, std::vector<uint8_t> tlv);

      DER_Encoder& start_cons(ASN1_Type type_tag, ASN1_Class class_tag, bool sort_contents);

      class DER_Sequence final {
         public:
            uint32_t tag_of() const;

            void push_contents(DER_Encoder& der);

            void add_bytes(const uint8_t val[], size_t len);

            void add_bytes(const uint8_t hdr[], size_t hdr_len, const uint8_t val[], size_t val_len);

            DER_Sequence(ASN1_Type type_tag, ASN1_Class class_tag, bool sort_contents);

            DER_Sequence(DER_Sequence&& seq) noexcept :
                  m_type_tag(seq.m_type_tag),
                  m_class_tag(seq.m_class_tag),
                  m_sort_contents(seq.m_sort_contents),
                  m_contents(std::move(seq.m_contents)),
                  m_set_contents(std::move(seq.m_set_contents)) {}

            DER_Sequence& operator=(DER_Sequence&& seq) noexcept {
               std::swap(m_type_tag, seq.m_type_tag);
               std::swap(m_class_tag, seq.m_class_tag);
               std::swap(m_sort_contents, seq.m_sort_contents);
               std::swap(m_contents, seq.m_contents);
               std::swap(m_set_contents, seq.m_set_contents);
               return (*this);
            }

            DER_Sequence(const DER_Sequence& seq) = default;
            DER_Sequence& operator=(const DER_Sequence& seq) = default;
            ~DER_Sequence() = default;

         private:
            ASN1_Type m_type_tag;
            ASN1_Class m_class_tag;
            bool m_sort_contents;
            secure_vector<uint8_t> m_contents;
            std::vector<secure_vector<uint8_t>> m_set_contents;
      };

      append_fn m_append_output;
      secure_vector<uint8_t> m_default_outbuf;
      std::vector<DER_Sequence> m_subsequences;
};

}  // namespace Botan

#endif
