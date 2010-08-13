/*
* PKCS #8
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/pkcs8.h>
#include <botan/get_pbe.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_obj.h>
#include <botan/pk_algs.h>
#include <botan/oids.h>
#include <botan/pem.h>
#include <memory>

namespace Botan {

namespace PKCS8 {

namespace {

/*
* Get info from an EncryptedPrivateKeyInfo
*/
SecureVector<byte> PKCS8_extract(DataSource& source,
                                 AlgorithmIdentifier& pbe_alg_id)
   {
   SecureVector<byte> key_data;

   BER_Decoder(source)
      .start_cons(SEQUENCE)
         .decode(pbe_alg_id)
         .decode(key_data, OCTET_STRING)
      .verify_end();

   return key_data;
   }

/*
* PEM decode and/or decrypt a private key
*/
SecureVector<byte> PKCS8_decode(DataSource& source, const User_Interface& ui,
                                AlgorithmIdentifier& pk_alg_id)
   {
   AlgorithmIdentifier pbe_alg_id;
   SecureVector<byte> key_data, key;
   bool is_encrypted = true;

   try {
      if(ASN1::maybe_BER(source) && !PEM_Code::matches(source))
         key_data = PKCS8_extract(source, pbe_alg_id);
      else
         {
         std::string label;
         key_data = PEM_Code::decode(source, label);
         if(label == "PRIVATE KEY")
            is_encrypted = false;
         else if(label == "ENCRYPTED PRIVATE KEY")
            {
            DataSource_Memory key_source(key_data);
            key_data = PKCS8_extract(key_source, pbe_alg_id);
            }
         else
            throw PKCS8_Exception("Unknown PEM label " + label);
         }

      if(key_data.is_empty())
         throw PKCS8_Exception("No key data found");
      }
   catch(Decoding_Error)
      {
      throw Decoding_Error("PKCS #8 private key decoding failed");
      }

   if(!is_encrypted)
      key = key_data;

   const u32bit MAX_TRIES = 3;

   u32bit tries = 0;
   while(true)
      {
      try {
         if(MAX_TRIES && tries >= MAX_TRIES)
            break;

         if(is_encrypted)
            {
            DataSource_Memory params(pbe_alg_id.parameters);
            std::auto_ptr<PBE> pbe(get_pbe(pbe_alg_id.oid, params));

            User_Interface::UI_Result result = User_Interface::OK;
            const std::string passphrase =
               ui.get_passphrase("PKCS #8 private key", source.id(), result);

            if(result == User_Interface::CANCEL_ACTION)
               break;

            pbe->set_key(passphrase);
            Pipe decryptor(pbe.release());

            decryptor.process_msg(key_data, key_data.size());
            key = decryptor.read_all();
            }

         u32bit version;

         BER_Decoder(key)
            .start_cons(SEQUENCE)
               .decode(version)
               .decode(pk_alg_id)
               .decode(key, OCTET_STRING)
               .discard_remaining()
            .end_cons();

         if(version != 0)
            throw Decoding_Error("PKCS #8: Unknown version number");

         break;
         }
      catch(Decoding_Error)
         {
         ++tries;
         }
      }

   if(key.is_empty())
      throw Decoding_Error("PKCS #8 private key decoding failed");
   return key;
   }

}

/*
* BER encode a PKCS #8 private key
*/
SecureVector<byte> BER_encode(const Private_Key& key)
   {
   std::auto_ptr<PKCS8_Encoder> encoder(key.pkcs8_encoder());
   if(!encoder.get())
      throw Encoding_Error("PKCS8::encode: Key does not support encoding");

   const u32bit PKCS8_VERSION = 0;

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(PKCS8_VERSION)
            .encode(encoder->alg_id())
            .encode(encoder->key_bits(), OCTET_STRING)
         .end_cons()
      .get_contents();
   }

/*
* PEM encode a PKCS #8 private key
*/
std::string PEM_encode(const Private_Key& key)
   {
   return PEM_Code::encode(PKCS8::BER_encode(key),
                           "PRIVATE KEY");
   }

/*
* Encrypt a PKCS #8 private key and return as BER
*/
SecureVector<byte> BER_encode(const Private_Key& key,
                              RandomNumberGenerator& rng,
                              const std::string& pass,
                              const std::string& pbe_algo)
   {
   const std::string DEFAULT_PBE = "PBE-PKCS5v20(SHA-1,AES-256/CBC)";

   std::auto_ptr<PBE> pbe(get_pbe(((pbe_algo != "") ? pbe_algo : DEFAULT_PBE)));

   pbe->new_params(rng);
   pbe->set_key(pass);

   AlgorithmIdentifier pbe_algid(pbe->get_oid(), pbe->encode_params());

   Pipe key_encrytor(pbe.release());
   key_encrytor.process_msg(PKCS8::BER_encode(key));

   return DER_Encoder()
         .start_cons(SEQUENCE)
            .encode(pbe_algid)
            .encode(key_encrytor.read_all(), OCTET_STRING)
         .end_cons()
      .get_contents();
   }

/*
* Encrypt and PEM encode a PKCS #8 private key
*/
std::string PEM_encode(const Private_Key& key,
                       RandomNumberGenerator& rng,
                       const std::string& pass,
                       const std::string& pbe_algo)
   {
   if(pass == "")
      return PEM_encode(key);

   return PEM_Code::encode(PKCS8::BER_encode(key, rng, pass, pbe_algo),
                           "ENCRYPTED PRIVATE KEY");
   }

/*
* DER or PEM encode a PKCS #8 private key
*/
void encode(const Private_Key& key, Pipe& pipe, X509_Encoding encoding)
   {
   if(encoding == PEM)
      pipe.write(PKCS8::PEM_encode(key));
   else
      pipe.write(PKCS8::BER_encode(key));
   }

/*
* Encode and encrypt a PKCS #8 private key
*/
void encrypt_key(const Private_Key& key,
                 Pipe& pipe,
                 RandomNumberGenerator& rng,
                 const std::string& pass,
                 const std::string& pbe_algo,
                 X509_Encoding encoding)
   {
   if(encoding == PEM)
      pipe.write(PKCS8::PEM_encode(key, rng, pass, pbe_algo));
   else
      pipe.write(PKCS8::BER_encode(key, rng, pass, pbe_algo));
   }

/*
* Extract a private key and return it
*/
Private_Key* load_key(DataSource& source,
                      RandomNumberGenerator& rng,
                      const User_Interface& ui)
   {
   AlgorithmIdentifier alg_id;
   SecureVector<byte> pkcs8_key = PKCS8_decode(source, ui, alg_id);

   const std::string alg_name = OIDS::lookup(alg_id.oid);
   if(alg_name == "" || alg_name == alg_id.oid.as_string())
      throw PKCS8_Exception("Unknown algorithm OID: " +
                            alg_id.oid.as_string());

   std::auto_ptr<Private_Key> key(get_private_key(alg_name));

   if(!key.get())
      throw PKCS8_Exception("Unknown PK algorithm/OID: " + alg_name + ", " +
                           alg_id.oid.as_string());

   std::auto_ptr<PKCS8_Decoder> decoder(key->pkcs8_decoder(rng));

   if(!decoder.get())
      throw Decoding_Error("Key does not support PKCS #8 decoding");

   decoder->alg_id(alg_id);
   decoder->key_bits(pkcs8_key);

   return key.release();
   }

/*
* Extract a private key and return it
*/
Private_Key* load_key(const std::string& fsname,
                      RandomNumberGenerator& rng,
                      const User_Interface& ui)
   {
   DataSource_Stream source(fsname, true);
   return PKCS8::load_key(source, rng, ui);
   }

/*
* Extract a private key and return it
*/
Private_Key* load_key(DataSource& source,
                      RandomNumberGenerator& rng,
                      const std::string& pass)
   {
   return PKCS8::load_key(source, rng, User_Interface(pass));
   }

/*
* Extract a private key and return it
*/
Private_Key* load_key(const std::string& fsname,
                      RandomNumberGenerator& rng,
                      const std::string& pass)
   {
   return PKCS8::load_key(fsname, rng, User_Interface(pass));
   }

/*
* Make a copy of this private key
*/
Private_Key* copy_key(const Private_Key& key,
                      RandomNumberGenerator& rng)
   {
   Pipe bits;

   bits.start_msg();
   PKCS8::encode(key, bits);
   bits.end_msg();

   DataSource_Memory source(bits.read_all());
   return PKCS8::load_key(source, rng);
   }

}

}
