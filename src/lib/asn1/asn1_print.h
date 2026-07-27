/*
* (C) 2014,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASN1_PRINT_H_
#define BOTAN_ASN1_PRINT_H_

#include <botan/asn1_obj.h>
#include <iosfwd>
#include <string>
#include <vector>

namespace Botan {

class BigInt;
class BER_Decoder;

/**
* Format ASN.1 data and call a virtual to format
*/
class BOTAN_PUBLIC_API(2, 4) ASN1_Formatter /* NOLINT(*-special-member-functions) */ {
   public:
      virtual ~ASN1_Formatter() = default;

      /**
      * Create a formatter with the given settings
      *
      * @param print_context_specific if true, try to parse nested context specific data.
      * @param max_depth do not recurse more than this many times. If zero, recursion
      *        is unbounded.
      * @param require_der if true then non-canonical BER data is rejected
      */
      ASN1_Formatter(bool print_context_specific, size_t max_depth, bool require_der = false) :
            m_print_context_specific(print_context_specific), m_max_depth(max_depth), m_require_der(require_der) {}

      /**
      * Format the given ASN.1 data, writing the result to a stream
      *
      * @param out the stream to write the formatted output to
      * @param in the DER or BER encoded data
      * @param len the length of in in bytes
      */
      void print_to_stream(std::ostream& out, const uint8_t in[], size_t len) const;

      /**
      * Return the given ASN.1 data in formatted form
      *
      * @param in the DER or BER encoded data
      * @param len the length of in in bytes
      */
      std::string print(const uint8_t in[], size_t len) const;

      /**
      * Return the given ASN.1 data in formatted form
      *
      * @param vec the DER or BER encoded data
      */
      template <typename Alloc>
      std::string print(const std::vector<uint8_t, Alloc>& vec) const {
         return print(vec.data(), vec.size());
      }

   protected:
      /**
      * This is called for each element
      */
      virtual std::string format(
         ASN1_Type type_tag, ASN1_Class class_tag, size_t level, size_t length, std::string_view value) const = 0;

      /**
      * This is called to format binary elements that we don't know how to
      * convert to a string. The result will be passed as value to format; the
      * tags are included as a hint to aid decoding.
      *
      * TODO(Botan4) change the vector to a span
      */
      virtual std::string format_bin(ASN1_Type type_tag,
                                     ASN1_Class class_tag,
                                     const std::vector<uint8_t>& vec) const = 0;

      /**
      * This is called to format integers
      */
      virtual std::string format_bn(const BigInt& bn) const = 0;

   private:
      void decode(std::ostream& output, BER_Decoder& decoder, size_t level) const;

      const bool m_print_context_specific;
      const size_t m_max_depth;
      const bool m_require_der;
};

/**
* Format ASN.1 data into human readable output. The exact form of the output for
* any particular input is not guaranteed and may change from release to release.
*/
class BOTAN_PUBLIC_API(2, 4) ASN1_Pretty_Printer final : public ASN1_Formatter {
   public:
      /**
      * Create a pretty printer with the given settings
      *
      * @param print_limit strings larger than this are not printed
      * @param print_binary_limit binary strings larger than this are not printed
      * @param print_context_specific if true, try to parse nested context specific data.
      * @param initial_level the initial depth (0 or 1 are the only reasonable values)
      * @param value_column ASN.1 values are lined up at this column in output
      * @param max_depth do not recurse more than this many times. If zero, recursion
      *        is unbounded.
      * @param require_der if true then non-canonical BER data is rejected
      */
      explicit ASN1_Pretty_Printer(size_t print_limit = 4096,
                                   size_t print_binary_limit = 2048,
                                   bool print_context_specific = true,
                                   size_t initial_level = 0,
                                   size_t value_column = 60,
                                   size_t max_depth = 64,
                                   bool require_der = false) :
            ASN1_Formatter(print_context_specific, max_depth, require_der),
            m_print_limit(print_limit),
            m_print_binary_limit(print_binary_limit),
            m_initial_level(initial_level),
            m_value_column(value_column) {}

   private:
      std::string format(
         ASN1_Type type_tag, ASN1_Class class_tag, size_t level, size_t length, std::string_view value) const override;

      std::string format_bin(ASN1_Type type_tag, ASN1_Class class_tag, const std::vector<uint8_t>& vec) const override;

      std::string format_bn(const BigInt& bn) const override;

      const size_t m_print_limit;
      const size_t m_print_binary_limit;
      const size_t m_initial_level;
      const size_t m_value_column;
};

}  // namespace Botan

#endif
