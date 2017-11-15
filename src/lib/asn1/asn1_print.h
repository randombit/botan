/*
* (C) 2014,2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASN1_PRINT_H_
#define BOTAN_ASN1_PRINT_H_

#include <botan/types.h>
#include <string>
#include <vector>
#include <iosfwd>

namespace Botan {

class BER_Decoder;

/**
* Format ASN.1 data into human readable strings
*/
class BOTAN_DLL ASN1_Pretty_Printer
   {
   public:
      /**
      * @param print_limit strings larger than this are not printed
      * @param print_binary_limit binary strings larger than this are not printed
      * @param print_context_specific if true, try to parse nested context specific data.
      * @param initial_level the initial depth (0 or 1 are the only reasonable values)
      * @param value_column ASN.1 values are lined up at this column in output
      */
      ASN1_Pretty_Printer(size_t print_limit = 256,
                          size_t print_binary_limit = 256,
                          bool print_context_specific = true,
                          size_t initial_level = 0,
                          size_t value_column = 60) :
         m_print_limit(print_limit),
         m_print_binary_limit(print_binary_limit),
         m_initial_level(initial_level),
         m_value_column(value_column),
         m_print_context_specific(print_context_specific)
         {}

      void print_to_stream(std::ostream& out,
                           const uint8_t in[],
                           size_t len) const;

      std::string print(const uint8_t in[], size_t len) const;

      template<typename Alloc>
      std::string print(const std::vector<uint8_t, Alloc>& vec) const
         {
         return print(vec.data(), vec.size());
         }

   private:
      void emit(std::ostream& out,
                const std::string& type,
                size_t level, size_t length,
                const std::string& value = "") const;

      void decode(std::ostream& output,
                  BER_Decoder& decoder,
                  size_t level) const;

      std::string format_binary(const std::vector<uint8_t>& in) const;

      const size_t m_print_limit;
      const size_t m_print_binary_limit;
      const size_t m_initial_level;
      const size_t m_value_column;
      const bool m_print_context_specific;
   };

}

#endif
