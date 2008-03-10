/*************************************************
* ASN.1 OID Header File                          *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ASN1_OID_H__
#define BOTAN_ASN1_OID_H__

#include <botan/asn1_int.h>
#include <string>
#include <vector>

namespace Botan {

/*************************************************
* ASN.1 Object Identifier                        *
*************************************************/
class OID : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      bool is_empty() const { return id.size() == 0; }
      std::vector<u32bit> get_id() const { return id; }
      std::string as_string() const;

      bool operator==(const OID&) const;
      void clear();

      OID& operator+=(u32bit);
      OID(const std::string& = "");
   private:
      std::vector<u32bit> id;
   };

/*************************************************
* Append another component onto the OID          *
*************************************************/
OID operator+(const OID&, u32bit);

/*************************************************
* Compare two OIDs                               *
*************************************************/
bool operator!=(const OID&, const OID&);
bool operator<(const OID&, const OID&);

}

#endif
