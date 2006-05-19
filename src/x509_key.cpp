/*************************************************
* X.509 Public Key Source File                   *
* (C) 1999-2006 The Botan Project                *
*************************************************/

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

/*************************************************
* Compute the key id                             *
*************************************************/
u64bit X509_PublicKey::key_id() const
   {
   Pipe pipe(new Hash_Filter("SHA-1", 8));

   pipe.start_msg();
   pipe.write(algo_name());
   pipe.write(DER_encode_pub());
   pipe.write(DER_encode_params());
   pipe.end_msg();

   SecureVector<byte> output = pipe.read_all();

   if(output.size() != 8)
      throw Internal_Error("X509_PublicKey::key_id: Incorrect output size");

   u64bit id = 0;
   for(u32bit j = 0; j != 8; ++j)
      id = (id << 8) | output[j];
   return id;
   }

namespace X509 {

namespace {

/*************************************************
* Extract the fields of a subjectPublicKeyInfo   *
*************************************************/
void X509_extract_info(DataSource& source, AlgorithmIdentifier& alg_id,
                       MemoryVector<byte>& key)
   {
   BER_Decoder(source)
      .start_cons(SEQUENCE)
         .decode(alg_id)
         .decode(key, BIT_STRING)
         .verify_end()
      .end_cons();
   }

}

/*************************************************
* DER or PEM encode a X.509 public key           *
*************************************************/
void encode(const X509_PublicKey& key, Pipe& pipe, X509_Encoding encoding)
   {
   AlgorithmIdentifier alg_id(key.get_oid(), key.DER_encode_params());

   MemoryVector<byte> der =
      DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(alg_id)
            .encode(key.DER_encode_pub(), BIT_STRING)
         .end_cons()
      .get_contents();

   if(encoding == PEM)
      pipe.write(PEM_Code::encode(der, "PUBLIC KEY"));
   else
      pipe.write(der);
   }

/*************************************************
* PEM encode a X.509 public key                  *
*************************************************/
std::string PEM_encode(const X509_PublicKey& key)
   {
   Pipe pem;
   pem.start_msg();
   encode(key, pem, PEM);
   pem.end_msg();
   return pem.read_all_as_string();
   }

/*************************************************
* Extract a public key and return it             *
*************************************************/
X509_PublicKey* load_key(DataSource& source)
   {
   try {
      AlgorithmIdentifier alg_id;
      MemoryVector<byte> key;

      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source))
         X509_extract_info(source, alg_id, key);
      else
         {
         DataSource_Memory ber(
            PEM_Code::decode_check_label(source, "PUBLIC KEY")
            );
         X509_extract_info(ber, alg_id, key);
         }

      if(key.is_empty())
         throw Decoding_Error("X.509 public key decoding failed");

      const std::string alg_name = OIDS::lookup(alg_id.oid);
      if(alg_name == "")
         throw Decoding_Error("Unknown algorithm OID: " +
                              alg_id.oid.as_string());

      std::auto_ptr<X509_PublicKey> key_obj(get_public_key(alg_name));
      if(!key_obj.get())
         throw Decoding_Error("Unknown PK algorithm/OID: " + alg_name + ", " +
                              alg_id.oid.as_string());

      Pipe output;
      output.process_msg(alg_id.parameters);
      output.process_msg(key);
      key_obj->BER_decode_params(output);
      output.set_default_msg(1);
      key_obj->BER_decode_pub(output);

      return key_obj.release();
      }
   catch(Decoding_Error)
      {
      throw Decoding_Error("X.509 public key decoding failed");
      }
   }

/*************************************************
* Extract a public key and return it             *
*************************************************/
X509_PublicKey* load_key(const std::string& fsname)
   {
   DataSource_Stream source(fsname, true);
   return X509::load_key(source);
   }

/*************************************************
* Extract a public key and return it             *
*************************************************/
X509_PublicKey* load_key(const MemoryRegion<byte>& mem)
   {
   DataSource_Memory source(mem);
   return X509::load_key(source);
   }

/*************************************************
* Make a copy of this public key                 *
*************************************************/
X509_PublicKey* copy_key(const X509_PublicKey& key)
   {
   Pipe bits;
   bits.start_msg();
   X509::encode(key, bits, RAW_BER);
   bits.end_msg();
   DataSource_Memory source(bits.read_all());
   return X509::load_key(source);
   }

/*************************************************
* Find the allowable key constraints             *
*************************************************/
Key_Constraints find_constraints(const X509_PublicKey& pub_key,
                                 Key_Constraints limits)
   {
   const X509_PublicKey* key = &pub_key;
   u32bit constraints = 0;

   if(dynamic_cast<const PK_Encrypting_Key*>(key))
      constraints |= KEY_ENCIPHERMENT;

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
