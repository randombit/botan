/*************************************************
* Extension Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>

namespace Botan {

/*************************************************
* Create an Extension                            *
*************************************************/
Extension::Extension(const OID& extn_oid, const MemoryRegion<byte>& extn_value)
   {
   oid = extn_oid;
   value = extn_value;
   critical = false;
   }

/*************************************************
* Create an Extension                            *
*************************************************/
Extension::Extension(const std::string& extn_oid,
                     const MemoryRegion<byte>& extn_value)
   {
   oid = OIDS::lookup(extn_oid);
   value = extn_value;
   critical = false;
   }

/*************************************************
* DER encode a Extension                         *
*************************************************/
void Extension::encode_into(DER_Encoder& codec) const
   {
   codec.start_cons(SEQUENCE)
         .encode(oid)
         .encode_optional(critical, false)
         .encode(value, OCTET_STRING)
      .end_cons();
   }

/*************************************************
* Decode a BER encoded Extension                 *
*************************************************/
void Extension::decode_from(BER_Decoder& codec)
   {
   codec.start_cons(SEQUENCE)
         .decode(oid)
         .decode_optional(critical, BOOLEAN, UNIVERSAL, false)
         .decode(value, OCTET_STRING)
      .end_cons();
   }

}
