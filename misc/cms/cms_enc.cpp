/*************************************************
* CMS Encoding Base Source File                  *
* (C) 1999-2003 The Botan Project                *
*************************************************/

#include <botan/cms_enc.h>
#include <botan/der_enc.h>
#include <botan/oids.h>
#include <botan/pem.h>

namespace Botan {

/*************************************************
* Setup the intitial layer of CMS data           *
*************************************************/
void CMS_Encoder::set_data(const byte buf[], u32bit length)
   {
   if(data.has_items())
      throw Invalid_State("Cannot call CMS_Encoder::set_data here");

   data.set(buf, length);
   type = "CMS.DataContent";
   }

/*************************************************
* Setup the intitial layer of CMS data           *
*************************************************/
void CMS_Encoder::set_data(const std::string& str)
   {
   set_data((const byte*)str.c_str(), str.length());
   }

/*************************************************
* Finalize and return the CMS encoded data       *
*************************************************/
SecureVector<byte> CMS_Encoder::get_contents()
   {
   DER_Encoder encoder;

   encoder.start_sequence();
     DER::encode(encoder, OIDS::lookup(type));
     encoder.start_explicit(ASN1_Tag(0));
       encoder.add_raw_octets(data);
     encoder.end_explicit(ASN1_Tag(0));
   encoder.end_sequence();

   data.clear();

   return encoder.get_contents();
   }

/*************************************************
* Add a new layer of encapsulation               *
*************************************************/
void CMS_Encoder::add_layer(const std::string& oid, DER_Encoder& new_layer)
   {
   data = new_layer.get_contents();
   type = oid;
   }

/*************************************************
* Return the PEM-encoded data                    *
*************************************************/
std::string CMS_Encoder::PEM_contents()
   {
   return PEM_Code::encode(get_contents(), "PKCS7");
   }

/*************************************************
* Make an EncapsulatedContentInfo                *
*************************************************/
SecureVector<byte> CMS_Encoder::make_econtent(const SecureVector<byte>& data,
                                              const std::string& type)
   {
   DER_Encoder encoder;

   encoder.start_sequence();
     DER::encode(encoder, OIDS::lookup(type));
     encoder.start_explicit(ASN1_Tag(0));
       DER::encode(encoder, data, OCTET_STRING);
     encoder.end_explicit(ASN1_Tag(0));
   encoder.end_sequence();

   return encoder.get_contents();
   }

}
