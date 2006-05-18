/*************************************************
* Extension Source File                          *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/asn1_obj.h>
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
void Extension::encode_into(DER_Encoder& der) const
   {
   der.start_sequence();
   der.encode(oid);
   if(critical)
      der.encode(true);
   // der.encode_with_default(critical, false);
   der.encode(value, OCTET_STRING);
   der.end_sequence();
   }

namespace BER {

/*************************************************
* Decode a BER encoded Extension                 *
*************************************************/
void decode(BER_Decoder& ber, Extension& extn)
   {
#if 1
   BER_Decoder extension = BER::get_subsequence(ber);
   BER::decode(extension, extn.oid);
   BER::decode_optional(extension, extn.critical, BOOLEAN, UNIVERSAL, false);
   extension.decode(extn.value, OCTET_STRING);
   extension.verify_end();
#else
   ber.start_subsequence()
         .decode(extn.oid)
         .decode_optional(extn.critical, BOOLEAN, UNIVERSAL, false)
         .decode(extn.value, OCTET_STRING)
      .end_subsequence();
#endif
   }

}

}
