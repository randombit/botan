/*
* CMS Encoding Operations
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cms_enc.h>
#include <botan/bigint.h>
#include <botan/cbc.h>
#include <botan/der_enc.h>
#include <botan/hash.h>
#include <botan/libstate.h>
#include <botan/oids.h>
#include <botan/pipe.h>
#include <botan/pubkey.h>
#include <memory>

namespace Botan {

namespace {

/*
* Choose an algorithm
*/
std::string choose_algo(const std::string& user_algo,
                        const std::string& default_algo)
   {
   if(user_algo == "")
      return global_state().deref_alias(default_algo);
   return global_state().deref_alias(user_algo);
   }

/*
* Encode a SignerIdentifier/RecipientIdentifier
*/
DER_Encoder& encode_si(DER_Encoder& der, const X509_Certificate& cert,
                       bool use_skid_encoding = false)
   {
   if(cert.subject_key_id().size() && use_skid_encoding)
      der.encode(cert.subject_key_id(), OCTET_STRING, ASN1_Tag(0));
   else
      {
      der.start_cons(SEQUENCE).
         encode(cert.issuer_dn()).
         encode(BigInt::decode(cert.serial_number())).
      end_cons();
      }

   return der;
   }

/*
* Compute the hash of some content
*/
SecureVector<byte> hash_of(const SecureVector<byte>& content,
                           const std::string& hash_name)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();
   std::auto_ptr<HashFunction> hash_fn(af.make_hash_function(hash_name));
   return hash_fn->process(content);
   }

/*
* Encode Attributes containing info on content
*/
SecureVector<byte> encode_attr(const SecureVector<byte>& data,
                               const std::string& type,
                               const std::string& hash)
   {
   SecureVector<byte> digest = hash_of(data, hash);

   DER_Encoder encoder;
   encoder.encode(OIDS::lookup(type));
   Attribute content_type("PKCS9.ContentType", encoder.get_contents());

   encoder.encode(digest, OCTET_STRING);
   Attribute message_digest("PKCS9.MessageDigest", encoder.get_contents());

   encoder.start_cons(SET)
      .encode(content_type)
      .encode(message_digest)
   .end_cons();

   return encoder.get_contents();
   }

}

/*
* Encrypt a message
*/
void CMS_Encoder::encrypt(RandomNumberGenerator& rng,
                          const X509_Certificate& to,
                          const std::string user_cipher)
   {
   const std::string cipher = choose_algo(user_cipher, "TripleDES");

   std::auto_ptr<Public_Key> key(to.subject_public_key());
   const std::string algo = key->algo_name();

   Key_Constraints constraints = to.constraints();

   if(algo == "RSA")
      {
      if(constraints != NO_CONSTRAINTS && !(constraints & KEY_ENCIPHERMENT))
         throw Invalid_Argument("CMS: Constraints not set for encryption");

      encrypt_ktri(rng, to, key.get(), cipher);
      }
   else if(algo == "DH")
      {
      if(constraints != NO_CONSTRAINTS && !(constraints & KEY_AGREEMENT))
         throw Invalid_Argument("CMS: Constraints not set for key agreement");

      encrypt_kari(rng, to, key.get(), cipher);
      }
   else
      throw Invalid_Argument("Unknown CMS PK encryption algorithm " + algo);
   }

/*
* Encrypt a message with a key transport algo
*/
void CMS_Encoder::encrypt_ktri(RandomNumberGenerator& rng,
                               const X509_Certificate& to,
                               Public_Key* pub_key,
                               const std::string& cipher)
   {
   const std::string padding = "EME-PKCS1-v1_5";
   const std::string pk_algo = pub_key->algo_name();

   PK_Encryptor_EME encryptor(*pub_key, padding);

   SymmetricKey cek = setup_key(rng, cipher);

   AlgorithmIdentifier alg_id(OIDS::lookup(pk_algo + '/' + padding),
                              AlgorithmIdentifier::USE_NULL_PARAM);

   DER_Encoder encoder;

   encoder.start_cons(SEQUENCE)
      .encode(static_cast<size_t>(0))
      .start_cons(SET)
         .start_cons(SEQUENCE)
            .encode(static_cast<size_t>(0));
            encode_si(encoder, to)
            .encode(alg_id)
            .encode(encryptor.encrypt(cek.bits_of(), rng), OCTET_STRING)
         .end_cons()
      .end_cons()
      .raw_bytes(do_encrypt(rng, cek, cipher))
   .end_cons();

   add_layer("CMS.EnvelopedData", encoder);
   }

/*
* Encrypt a message with a key agreement algo
*/
void CMS_Encoder::encrypt_kari(RandomNumberGenerator&,
                               const X509_Certificate&,
                               Public_Key*,
                               const std::string&)
   {
   throw Internal_Error("FIXME: unimplemented");

#if 0
   SymmetricKey cek = setup_key(rng, cipher);

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(2);
     encoder.start_cons(SET);
       encoder.start_sequence(ASN1_Tag(1));
         encoder.encode(3);
         encode_si(encoder, to);
         encoder.encode(AlgorithmIdentifier(pk_algo + "/" + padding));
         encoder.encode(encrypted_cek, OCTET_STRING);
       encoder.end_cons();
     encoder.end_cons();
     encoder.raw_bytes(do_encrypt(rng, cek, cipher));
   encoder.end_cons();

   add_layer("CMS.EnvelopedData", encoder);
#endif
   }

/*
* Encrypt a message with a shared key
*/
void CMS_Encoder::encrypt(RandomNumberGenerator& rng,
                          const SymmetricKey& kek,
                          const std::string& user_cipher)
   {
   throw Internal_Error("FIXME: untested");

   const std::string cipher = choose_algo(user_cipher, "TripleDES");
   SymmetricKey cek = setup_key(rng, cipher);

   SecureVector<byte> kek_id; // FIXME: ?

   DER_Encoder encoder;

   encoder.start_cons(SEQUENCE)
      .encode(static_cast<size_t>(2))
      .start_explicit(ASN1_Tag(2))
      .encode(static_cast<size_t>(4))
         .start_cons(SEQUENCE)
            .encode(kek_id, OCTET_STRING)
         .end_cons()
         .encode(AlgorithmIdentifier(OIDS::lookup("KeyWrap." + cipher),
                                     AlgorithmIdentifier::USE_NULL_PARAM))
         .encode(wrap_key(rng, cipher, cek, kek), OCTET_STRING)
      .end_cons()
      .raw_bytes(do_encrypt(rng, cek, cipher))
   .end_cons();

   add_layer("CMS.EnvelopedData", encoder);
   }

/*
* Encrypt a message with a passphrase
*/
void CMS_Encoder::encrypt(RandomNumberGenerator&,
                          const std::string&,
                          const std::string& user_cipher)
   {
   const std::string cipher = choose_algo(user_cipher, "TripleDES");
   throw Internal_Error("FIXME: unimplemented");
   /*
   SymmetricKey cek = setup_key(key);

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(0);
     encoder.raw_bytes(do_encrypt(rng, cek, cipher));
   encoder.end_cons();

   add_layer("CMS.EnvelopedData", encoder);
   */
   }

/*
* Encrypt the content with the chosen key/cipher
*/
SecureVector<byte> CMS_Encoder::do_encrypt(RandomNumberGenerator& rng,
                                           const SymmetricKey& key,
                                           const std::string& cipher_name)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   const BlockCipher* cipher = af.prototype_block_cipher(cipher_name);

   if(!cipher)
      throw Invalid_Argument("CMS: Can't encrypt with non-existent cipher " + cipher_name);

   if(!OIDS::have_oid(cipher->name() + "/CBC"))
      throw Encoding_Error("CMS: No OID assigned for " + cipher_name + "/CBC");

   InitializationVector iv(rng, cipher->block_size());

   AlgorithmIdentifier content_cipher;
   content_cipher.oid = OIDS::lookup(cipher->name() + "/CBC");
   content_cipher.parameters = encode_params(cipher->name(), key, iv);

   Pipe pipe(new CBC_Encryption(cipher->clone(), new PKCS7_Padding, key, iv));

   pipe.process_msg(data);

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(OIDS::lookup(type));
     encoder.encode(content_cipher);
     encoder.encode(pipe.read_all(), OCTET_STRING, ASN1_Tag(0));
   encoder.end_cons();

   return encoder.get_contents();
   }

/*
* Sign a message
*/
void CMS_Encoder::sign(const X509_Certificate& cert,
                       const Private_Key& key,
                       RandomNumberGenerator& rng,
                       const std::vector<X509_Certificate>& chain,
                       const std::string& hash,
                       const std::string& pad_algo)
   {
   std::string padding = pad_algo + "(" + hash + ")";

   Signature_Format format = IEEE_1363;

   PK_Signer signer(key, padding, format);

   AlgorithmIdentifier sig_algo(OIDS::lookup(key.algo_name() + "/" + padding),
                                AlgorithmIdentifier::USE_NULL_PARAM);

   SecureVector<byte> signed_attr = encode_attr(data, type, hash);
   signer.update(signed_attr);
   SecureVector<byte> signature = signer.signature(rng);
   signed_attr[0] = 0xA0;

   const size_t SI_VERSION = cert.subject_key_id().size() ? 3 : 1;
   const size_t CMS_VERSION = (type != "CMS.DataContent") ? 3 : SI_VERSION;

   DER_Encoder encoder;

   encoder.start_cons(SEQUENCE)
      .encode(CMS_VERSION)
      .start_cons(SET)
         .encode(AlgorithmIdentifier(OIDS::lookup(hash),
                                     AlgorithmIdentifier::USE_NULL_PARAM))
      .end_cons()
   .raw_bytes(make_econtent(data, type));

   encoder.start_cons(ASN1_Tag(0), CONTEXT_SPECIFIC);
   for(size_t j = 0; j != chain.size(); j++)
      encoder.raw_bytes(chain[j].BER_encode());
   encoder.raw_bytes(cert.BER_encode()).end_cons();

   encoder.start_cons(SET)
      .start_cons(SEQUENCE)
      .encode(SI_VERSION);
      encode_si(encoder, cert, ((SI_VERSION == 3) ? true : false))
      .encode(
         AlgorithmIdentifier(OIDS::lookup(hash),
                             AlgorithmIdentifier::USE_NULL_PARAM)
         )
      .raw_bytes(signed_attr)
      .encode(sig_algo)
      .encode(signature, OCTET_STRING)
      .end_cons()
     .end_cons()
   .end_cons();

   add_layer("CMS.SignedData", encoder);
   }

/*
* Digest a message
*/
void CMS_Encoder::digest(const std::string& user_hash)
   {
   const std::string hash = choose_algo(user_hash, "SHA-1");
   if(!OIDS::have_oid(hash))
      throw Encoding_Error("CMS: No OID assigned for " + hash);

   const size_t VERSION = (type != "CMS.DataContent") ? 2 : 0;

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE)
      .encode(VERSION)
      .encode(AlgorithmIdentifier(OIDS::lookup(hash),
                                  AlgorithmIdentifier::USE_NULL_PARAM))
      .raw_bytes(make_econtent(data, type))
      .encode(hash_of(data, hash), OCTET_STRING)
   .end_cons();

   add_layer("CMS.DigestedData", encoder);
   }

/*
* MAC a message with an encrypted key
*/
void CMS_Encoder::authenticate(const X509_Certificate&,
                               const std::string& mac_algo)
   {
   const std::string mac = choose_algo(mac_algo, "HMAC(SHA-1)");
   throw Internal_Error("FIXME: unimplemented");
   }

/*
* MAC a message with a shared key
*/
void CMS_Encoder::authenticate(const SymmetricKey&,
                               const std::string& mac_algo)
   {
   const std::string mac = choose_algo(mac_algo, "HMAC(SHA-1)");
   throw Internal_Error("FIXME: unimplemented");
   }

/*
* MAC a message with a passphrase
*/
void CMS_Encoder::authenticate(const std::string&,
                               const std::string& mac_algo)
   {
   const std::string mac = choose_algo(mac_algo, "HMAC(SHA-1)");
   throw Internal_Error("FIXME: unimplemented");
   }

}
