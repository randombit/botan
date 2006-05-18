/*************************************************
* X.509 Certificate Extensions Source File       *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x509_ext.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/x509cert.h>
#include <botan/lookup.h>
#include <botan/oids.h>
#include <botan/conf.h>
#include <botan/bit_ops.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Encode a Certificate Extension                 *
*************************************************/
void Certificate_Extension::encode_into(DER_Encoder& der,
                                        bool is_critical) const
   {
   if(should_encode())
      {
#if 0
      der.start_seqeuence()
         .encode(oid_of())
         .encode_optional(is_critical, false)
         .encode(encode_inner(), OCTET_STRING)
      .end_sequence();
#else
      der.start_sequence();
      der.encode(oid_of());
      if(is_critical)
         der.encode(is_critical);
      der.encode(encode_inner(), OCTET_STRING);
      der.end_sequence();
#endif
      }
   }

/*************************************************
* Decode a Certificate Extension                 *
*************************************************/
void Certificate_Extension::decode_from(BER_Decoder& ber)
   {
   MemoryVector<byte> value;
   OID oid;

#if 0
   ber.start_sequence()
      .decode(oid)
      .decode_optional(is_critical, false)
      .decode(value, OCTET_STRING)
   .end_sequence();
#else
   BER_Decoder extension = BER::get_subsequence(ber);
   BER::decode(extension, oid);
   BER::decode_optional(extension, critical, BOOLEAN, UNIVERSAL, false);
   extension.decode(value, OCTET_STRING);
   extension.verify_end();
#endif

   decode_inner(value);
   }

/*************************************************
* Encode a Certificate Extension                 *
*************************************************/
void Certificate_Extension::encode_into(DER_Encoder& der) const
   {
   encode_into(der, critical);
   }

/*************************************************
* Return the OID of this extension               *
*************************************************/
OID Certificate_Extension::oid_of() const
   {
   return OIDS::lookup(oid_name());
   }

/*************************************************
* Encode a Certificate Extension                 *
*************************************************/
void Certificate_Extension::maybe_add(class DER_Encoder& der) const
   {
   const std::string opt_name = "x509/exts/" + config_id();
   std::string setting = Config::get_string(opt_name);

   if(setting != "no")
      encode_into(der, critical || (setting == "critical"));
   }

/*************************************************
* Encode an Extensions list                      *
*************************************************/
void Extensions::encode_into(class DER_Encoder& to_object) const
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      extensions[j]->maybe_add(to_object);
   }

/*************************************************
* Delete an Extensions list                      *
*************************************************/
Extensions::~Extensions()
   {
   for(u32bit j = 0; j != extensions.size(); ++j)
      delete extensions[j];
   }

namespace Cert_Extension {

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Basic_Constraints::encode_inner() const
   {
   DER_Encoder der;

   der.start_sequence();
   if(is_ca)
      {
      der.encode(true);
      if(path_limit != NO_CERT_PATH_LIMIT)
         der.encode(path_limit);
      }
   der.end_sequence();

   return der.get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Basic_Constraints::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder ber(in);

   BER_Decoder basic_constraints = BER::get_subsequence(ber);
   BER::decode_optional(basic_constraints, is_ca,
                        BOOLEAN, UNIVERSAL, false);
   BER::decode_optional(basic_constraints, path_limit,
                        INTEGER, UNIVERSAL, NO_CERT_PATH_LIMIT);
   basic_constraints.verify_end();
   }

/*************************************************
* Basic_Constraints Constructor                  *
*************************************************/
Basic_Constraints::Basic_Constraints(bool is_ca, u32bit path_limit)
   {
   this->is_ca = is_ca;
   this->path_limit = path_limit;
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Key_Usage::encode_inner() const
   {
   if(constraints == NO_CONSTRAINTS)
      throw Encoding_Error("Cannot encode zero usage constraints");

   const u32bit unused_bits = low_bit(constraints) - 1;

   SecureVector<byte> der;
   der.append(BIT_STRING);
   der.append(2 + ((unused_bits < 8) ? 1 : 0));
   der.append(unused_bits % 8);
   der.append((constraints >> 8) & 0xFF);
   if(constraints & 0xFF)
      der.append(constraints & 0xFF);

   return der;
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Key_Usage::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder ber(in);

   BER_Object obj = ber.get_next_object();

   if(obj.type_tag != BIT_STRING || obj.class_tag != UNIVERSAL)
      throw BER_Bad_Tag("Bad tag for usage constraint",
                        obj.type_tag, obj.class_tag);

   if(obj.value.size() != 2 && obj.value.size() != 3)
      throw BER_Decoding_Error("Bad size for BITSTRING in usage constraint");

   if(obj.value[0] >= 8)
      throw BER_Decoding_Error("Invalid unused bits in usage constraint");

   obj.value[obj.value.size()-1] &= (0xFF << obj.value[0]);

   u16bit usage = 0;
   for(u32bit j = 1; j != obj.value.size(); ++j)
      usage = (obj.value[j] << 8) | usage;

   constraints = Key_Constraints(usage);
   }

/*************************************************
* Key_Usage Constructor                          *
*************************************************/
Key_Usage::Key_Usage(Key_Constraints constraints)
   {
   this->constraints = constraints;
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Subject_Key_ID::encode_inner() const
   {
   return DER_Encoder().encode(key_id, OCTET_STRING).get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Subject_Key_ID::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder(in).decode(key_id, OCTET_STRING).verify_end();
   }

/*************************************************
* Subject_Key_ID Constructor                     *
*************************************************/
Subject_Key_ID::Subject_Key_ID(const MemoryRegion<byte>& pub_key)
   {
   std::auto_ptr<HashFunction> hash(get_hash("SHA-1"));
   key_id = hash->process(pub_key);
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Authority_Key_ID::encode_inner() const
   {
   return DER_Encoder()
         .start_sequence()
            .encode(key_id, OCTET_STRING, ASN1_Tag(0), CONTEXT_SPECIFIC)
         .end_sequence()
      .get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Authority_Key_ID::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder ber(in);

   }

/*************************************************
* Authority_Key_ID Constructor                   *
*************************************************/
Authority_Key_ID::Authority_Key_ID(const MemoryRegion<byte>& key_id)
   {
   this->key_id = key_id;
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Alternative_Name::encode_inner() const
   {
   return DER_Encoder().encode(alt_name).get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Alternative_Name::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder ber(in);

   }

/*************************************************
* Alternative_Name Constructor                   *
*************************************************/
Alternative_Name::Alternative_Name(const AlternativeName& alt_name,
                                   const std::string& oid_name_str,
                                   const std::string& config_name_str)
   {
   this->alt_name = alt_name;
   this->oid_name_str = oid_name_str;
   this->config_name_str = config_name_str;
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> Extended_Key_Usage::encode_inner() const
   {
   DER_Encoder der;

   der.start_sequence();
   for(u32bit j = 0; j != oids.size(); ++j)
      der.encode(oids[j]);
   der.end_sequence();

   return der.get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void Extended_Key_Usage::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder ber(in);

   }

/*************************************************
* Extended_Key_Usage Constructor                 *
*************************************************/
Extended_Key_Usage::Extended_Key_Usage(const std::vector<OID>& oids)
   {
   this->oids = oids;
   }

/*************************************************
* Encode the extension                           *
*************************************************/
MemoryVector<byte> CRL_Number::encode_inner() const
   {
   return DER_Encoder().encode(crl_number).get_contents();
   }

/*************************************************
* Decode the extension                           *
*************************************************/
void CRL_Number::decode_inner(const MemoryRegion<byte>& in)
   {
   BER_Decoder ber(in);

   }

/*************************************************
* CRL_Number Constructor                         *
*************************************************/
CRL_Number::CRL_Number(u32bit n) : crl_number(n)
   {
   }

}

}
