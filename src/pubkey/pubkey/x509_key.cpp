/*
* X.509 Public Key
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509_key.h>
#include <botan/filters.h>
#include <botan/asn1_obj.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/pk_algs.h>
#include <botan/oids.h>
#include <botan/pem.h>
#include <memory>

namespace Botan {

namespace X509 {

/*
* DER or PEM encode a X.509 public key
*/
void encode(const Public_Key& key, Pipe& pipe, X509_Encoding encoding)
   {
   std::auto_ptr<X509_Encoder> encoder(key.x509_encoder());
   if(!encoder.get())
      throw Encoding_Error("X509::encode: Key does not support encoding");

   MemoryVector<byte> der =
      DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(encoder->alg_id())
            .encode(encoder->key_bits(), BIT_STRING)
         .end_cons()
      .get_contents();

   if(encoding == PEM)
      pipe.write(PEM_Code::encode(der, "PUBLIC KEY"));
   else
      pipe.write(der);
   }

/*
* PEM encode a X.509 public key
*/
std::string PEM_encode(const Public_Key& key)
   {
   Pipe pem;
   pem.start_msg();
   encode(key, pem, PEM);
   pem.end_msg();
   return pem.read_all_as_string();
   }

/*
* Extract a public key and return it
*/
Public_Key* load_key(DataSource& source)
   {
   try {
      AlgorithmIdentifier alg_id;
      MemoryVector<byte> key_bits;

      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source))
         {
         BER_Decoder(source)
            .start_cons(SEQUENCE)
            .decode(alg_id)
            .decode(key_bits, BIT_STRING)
            .verify_end()
         .end_cons();
         }
      else
         {
         DataSource_Memory ber(
            PEM_Code::decode_check_label(source, "PUBLIC KEY")
            );

         BER_Decoder(ber)
            .start_cons(SEQUENCE)
            .decode(alg_id)
            .decode(key_bits, BIT_STRING)
            .verify_end()
         .end_cons();
         }

      if(key_bits.is_empty())
         throw Decoding_Error("X.509 public key decoding failed");

      const std::string alg_name = OIDS::lookup(alg_id.oid);
      if(alg_name == "")
         throw Decoding_Error("Unknown algorithm OID: " +
                              alg_id.oid.as_string());

      std::auto_ptr<Public_Key> key_obj(get_public_key(alg_name));
      if(!key_obj.get())
         throw Decoding_Error("Unknown PK algorithm/OID: " + alg_name + ", " +
                              alg_id.oid.as_string());

      std::auto_ptr<X509_Decoder> decoder(key_obj->x509_decoder());

      if(!decoder.get())
         throw Decoding_Error("Key does not support X.509 decoding");

      decoder->alg_id(alg_id);
      decoder->key_bits(key_bits);

      return key_obj.release();
      }
   catch(Decoding_Error)
      {
      throw Decoding_Error("X.509 public key decoding failed");
      }
   }

/*
* Extract a public key and return it
*/
Public_Key* load_key(const std::string& fsname)
   {
   DataSource_Stream source(fsname, true);
   return X509::load_key(source);
   }

/*
* Extract a public key and return it
*/
Public_Key* load_key(const MemoryRegion<byte>& mem)
   {
   DataSource_Memory source(mem);
   return X509::load_key(source);
   }

/*
* Make a copy of this public key
*/
Public_Key* copy_key(const Public_Key& key)
   {
   Pipe bits;
   bits.start_msg();
   X509::encode(key, bits, RAW_BER);
   bits.end_msg();
   DataSource_Memory source(bits.read_all());
   return X509::load_key(source);
   }

/*
* Find the allowable key constraints
*/
Key_Constraints find_constraints(const Public_Key& pub_key,
                                 Key_Constraints limits)
   {
   const Public_Key* key = &pub_key;
   u32bit constraints = 0;

   if(dynamic_cast<const PK_Encrypting_Key*>(key))
      constraints |= KEY_ENCIPHERMENT | DATA_ENCIPHERMENT;

   if(dynamic_cast<const PK_Key_Agreement_Key*>(key))
      constraints |= KEY_AGREEMENT;

   if(dynamic_cast<const PK_Verifying_wo_MR_Key*>(key) ||
      dynamic_cast<const PK_Verifying_with_MR_Key*>(key))
      constraints |= DIGITAL_SIGNATURE | NON_REPUDIATION;

   if(limits)
      constraints &= limits;

   return Key_Constraints(constraints);
   }

}

}
