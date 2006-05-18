/*************************************************
* Attribute Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asn1_obj.h>
#include <botan/oids.h>

namespace Botan {

/*************************************************
* Create an Attribute                            *
*************************************************/
Attribute::Attribute(const OID& attr_oid, const MemoryRegion<byte>& attr_value)
   {
   oid = attr_oid;
   parameters = attr_value;
   }

/*************************************************
* Create an Attribute                            *
*************************************************/
Attribute::Attribute(const std::string& attr_oid,
                     const MemoryRegion<byte>& attr_value)
   {
   oid = OIDS::lookup(attr_oid);
   parameters = attr_value;
   }

/*************************************************
* DER encode a Attribute                         *
*************************************************/
void Attribute::encode_into(DER_Encoder& der) const
   {
   der.start_sequence()
      .encode(oid)
      .start_set()
         .add_raw_octets(parameters)
      .end_set()
   .end_sequence();
   }

namespace BER {

/*************************************************
* Decode a BER encoded Attribute                 *
*************************************************/
void decode(BER_Decoder& source, Attribute& attr)
   {
   BER_Decoder decoder = BER::get_subsequence(source);
   BER::decode(decoder, attr.oid);

   BER_Decoder attributes = BER::get_subset(decoder);
   attr.parameters = attributes.get_remaining();
   attributes.verify_end();

   decoder.verify_end();
   }

}

}
