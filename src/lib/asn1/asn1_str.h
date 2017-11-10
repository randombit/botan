/*
* ASN.1 string type
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASN1_STRING_H_
#define BOTAN_ASN1_STRING_H_

#include <botan/asn1_obj.h>

namespace Botan {

/**
* ASN.1 string type
* This class normalizes all inputs to a UTF-8 std::string
*/
class BOTAN_PUBLIC_API(2,0) ASN1_String final : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const override;
      void decode_from(class BER_Decoder&) override;

      ASN1_Tag tagging() const { return m_tag; }

      const std::string& value() const { return m_utf8_str; }

      std::string BOTAN_DEPRECATED("Use value() to get UTF-8 string instead")
         iso_8859() const;

      explicit ASN1_String(const std::string& utf8 = "");
      ASN1_String(const std::string& utf8, ASN1_Tag tag);
   private:
      std::vector<uint8_t> m_data;
      std::string m_utf8_str;
      ASN1_Tag m_tag;
   };

}

#endif
