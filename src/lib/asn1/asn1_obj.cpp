/*
* ASN.1 Internals
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/data_src.h>
#include <botan/internal/stl_util.h>

namespace Botan {

std::string asn1_tag_to_string(ASN1_Tag type)
   {
   switch(type)
      {
      case Botan::PRINTABLE_STRING:
         return "PRINTABLE STRING";

      case Botan::NUMERIC_STRING:
         return "NUMERIC STRING";

      case Botan::IA5_STRING:
         return "IA5 STRING";

      case Botan::T61_STRING:
         return "T61 STRING";

      case Botan::UTF8_STRING:
         return "UTF8 STRING";

      case Botan::VISIBLE_STRING:
         return "VISIBLE STRING";

      case Botan::BMP_STRING:
         return "BMP STRING";

      case Botan::UTC_TIME:
         return "UTC TIME";

      case Botan::GENERALIZED_TIME:
         return "GENERALIZED TIME";

      case Botan::OCTET_STRING:
         return "OCTET STRING";

      case Botan::BIT_STRING:
         return "BIT STRING";

      case Botan::ENUMERATED:
         return "ENUMERATED";

      case Botan::INTEGER:
         return "INTEGER";

      case Botan::NULL_TAG:
         return "NULL";

      case Botan::OBJECT_ID:
         return "OBJECT";

      case Botan::BOOLEAN:
         return "BOOLEAN";

      default:
         return "TAG(" + std::to_string(static_cast<size_t>(type)) + ")";
      }
   }

/*
* BER Decoding Exceptions
*/
BER_Decoding_Error::BER_Decoding_Error(const std::string& str) :
   Decoding_Error("BER: " + str) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str, ASN1_Tag tag) :
      BER_Decoding_Error(str + ": " + std::to_string(tag)) {}

BER_Bad_Tag::BER_Bad_Tag(const std::string& str,
                         ASN1_Tag tag1, ASN1_Tag tag2) :
   BER_Decoding_Error(str + ": " + std::to_string(tag1) + "/" + std::to_string(tag2)) {}

namespace ASN1 {

/*
* Put some arbitrary bytes into a SEQUENCE
*/
std::vector<uint8_t> put_in_sequence(const std::vector<uint8_t>& contents)
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .raw_bytes(contents)
      .end_cons()
   .get_contents_unlocked();
   }

/*
* Convert a BER object into a string object
*/
std::string to_string(const BER_Object& obj)
   {
   return to_string(obj.value);
   }

/*
* Do heuristic tests for BER data
*/
bool maybe_BER(DataSource& source)
   {
   uint8_t first_u8;
   if(!source.peek_byte(first_u8))
      {
      BOTAN_ASSERT_EQUAL(source.read_byte(first_u8), 0, "Expected EOF");
      throw Stream_IO_Error("ASN1::maybe_BER: Source was empty");
      }

   if(first_u8 == (SEQUENCE | CONSTRUCTED))
      return true;
   return false;
   }

}

}
