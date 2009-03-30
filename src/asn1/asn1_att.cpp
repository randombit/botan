/*
* Attribute
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>

namespace Botan {

/*
* Create an Attribute
*/
Attribute::Attribute(const OID& attr_oid, const MemoryRegion<byte>& attr_value)
   {
   oid = attr_oid;
   parameters = attr_value;
   }

/*
* Create an Attribute
*/
Attribute::Attribute(const std::string& attr_oid,
                     const MemoryRegion<byte>& attr_value)
   {
   oid = OIDS::lookup(attr_oid);
   parameters = attr_value;
   }

/*
* DER encode a Attribute
*/
void Attribute::encode_into(DER_Encoder& codec) const
   {
   codec.start_cons(SEQUENCE)
      .encode(oid)
      .start_cons(SET)
         .raw_bytes(parameters)
      .end_cons()
   .end_cons();
   }

/*
* Decode a BER encoded Attribute
*/
void Attribute::decode_from(BER_Decoder& codec)
   {
   codec.start_cons(SEQUENCE)
      .decode(oid)
      .start_cons(SET)
         .raw_bytes(parameters)
      .end_cons()
   .end_cons();
   }

}
