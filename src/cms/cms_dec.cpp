/*
* CMS Decoding
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cms_dec.h>
#include <botan/ber_dec.h>
#include <botan/asn1_int.h>
#include <botan/oids.h>
#include <botan/pem.h>

namespace Botan {

/*
* CMS_Decoder Constructor
*/
CMS_Decoder::CMS_Decoder(DataSource& in, const X509_Store& x509store,
                         User_Interface& ui_ref, PKCS8_PrivateKey* key) :
   ui(ui_ref), store(x509store)
   {
   status = GOOD;

   add_key(key);

   if(ASN1::maybe_BER(in) && !PEM_Code::matches(in))
      initial_read(in);
   else
      {
      DataSource_Memory ber(PEM_Code::decode_check_label(in, "PKCS7"));
      initial_read(ber);
      }
   }

/*
* Read the outermost ContentInfo
*/
void CMS_Decoder::initial_read(DataSource&)
   {
   // FIXME...

   /*
   BER_Decoder decoder(in);
   BER_Decoder content_info = decoder.start_cons(SEQUENCE);

   content_info.decode(next_type);


   BER_Decoder content_type = BER::get_subsequence(content_info, ASN1_Tag(0));
   data = content_type.get_remaining();
   */

   decode_layer();
   }

/*
* Add another private key to use
*/
void CMS_Decoder::add_key(PKCS8_PrivateKey* key)
   {
   if(!key)
      return;

#if 0
   for(u32bit j = 0; j != keys.size(); j++)
      if(keys[j]->key_id() == key->key_id())
         return;
#endif

   keys.push_back(key);
   }

/*
* Return the status information
*/
CMS_Decoder::Status CMS_Decoder::layer_status() const
   {
   return status;
   }

/*
* Return the final data content
*/
std::string CMS_Decoder::get_data() const
   {
   if(layer_type() != DATA)
      throw Invalid_State("CMS: Cannot retrieve data from non-DATA layer");
   return std::string((const char*)data.begin(), data.size());
   }

/*
* Return the content type of this layer
*/
CMS_Decoder::Content_Type CMS_Decoder::layer_type() const
   {
   if(type == OIDS::lookup("CMS.DataContent"))       return DATA;
   if(type == OIDS::lookup("CMS.EnvelopedData"))     return ENVELOPED;
   if(type == OIDS::lookup("CMS.CompressedData"))    return COMPRESSED;
   if(type == OIDS::lookup("CMS.SignedData"))        return SIGNED;
   if(type == OIDS::lookup("CMS.AuthenticatedData")) return AUTHENTICATED;
   if(type == OIDS::lookup("CMS.DigestedData"))      return DIGESTED;
   return UNKNOWN;
   }

/*
* Return some information about this layer
*/
std::string CMS_Decoder::layer_info() const
   {
   return info;
   }

/*
* Return some information about this layer
*/
void CMS_Decoder::read_econtent(BER_Decoder& decoder)
   {
   BER_Decoder econtent_info = decoder.start_cons(SEQUENCE);
   econtent_info.decode(next_type);

   // FIXME
   //BER_Decoder econtent = BER::get_subsequence(econtent_info, ASN1_Tag(0));
   //econtent.decode(data, OCTET_STRING);
   }

}
