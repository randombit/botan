/*************************************************
* CMS Encoding Operations Source File            *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/cms_enc.h>
#include <botan/der_enc.h>
#include <botan/bigint.h>
#include <botan/oids.h>
#include <botan/lookup.h>
#include <botan/look_pk.h>
#include <botan/pipe.h>
#include <botan/conf.h>

namespace Botan {

namespace {

/*************************************************
* Choose an algorithm                            *
*************************************************/
std::string choose_algo(const std::string& user_algo,
                        const std::string& default_algo)
   {
   if(user_algo == "")
      return deref_alias(default_algo);
   return deref_alias(user_algo);
   }

/*************************************************
* Encode a SignerIdentifier/RecipientIdentifier  *
*************************************************/
void encode_si(DER_Encoder& der, const X509_Certificate& cert,
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
   }

/*************************************************
* Compute the hash of some content               *
*************************************************/
SecureVector<byte> hash_of(const SecureVector<byte>& content,
                           const std::string& hash)
   {
   std::auto_ptr<HashFunction> hash_fn(get_hash(hash));
   return hash_fn->process(content);
   }

/*************************************************
* Encode Attributes containing info on content   *
*************************************************/
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

   encoder.start_cons(SET);
   encoder.encode(content_type);
   encoder.encode(message_digest);
   encoder.end_cons();

   return encoder.get_contents();
   }

}

/*************************************************
* Encrypt a message                              *
*************************************************/
void CMS_Encoder::encrypt(const X509_Certificate& to,
                          const std::string user_cipher)
   {
   const std::string cipher = choose_algo(user_cipher, "TripleDES");

   std::auto_ptr<X509_PublicKey> key(to.subject_public_key());
   const std::string algo = key->algo_name();

   Key_Constraints constraints = to.get_constraints();

   if(algo == "RSA")
      {
      if(constraints != NO_CONSTRAINTS && !(constraints & KEY_ENCIPHERMENT))
         throw Invalid_Argument("CMS: Constraints not set for encryption");

      PK_Encrypting_Key* enc_key = dynamic_cast<PK_Encrypting_Key*>(key.get());
      if(enc_key == 0)
         throw Internal_Error("CMS_Encoder::encrypt: " + algo +
                              " can't encrypt");

      encrypt_ktri(to, enc_key, cipher);
      }
   else if(algo == "DH")
      {
      if(constraints != NO_CONSTRAINTS && !(constraints & KEY_AGREEMENT))
         throw Invalid_Argument("CMS: Constraints not set for key agreement");

      encrypt_kari(to, key.get(), cipher);
      }
   else
      throw Invalid_Argument("Unknown CMS PK encryption algorithm " + algo);
   }

/*************************************************
* Encrypt a message with a key transport algo    *
*************************************************/
void CMS_Encoder::encrypt_ktri(const X509_Certificate& to,
                               PK_Encrypting_Key* pub_key,
                               const std::string& cipher)
   {
   const std::string padding = "EME-PKCS1-v1_5";
   const std::string pk_algo = pub_key->algo_name();
   std::auto_ptr<PK_Encryptor> enc(get_pk_encryptor(*pub_key, padding));

   SymmetricKey cek = setup_key(cipher);

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
   encoder.encode((u32bit)0);
     encoder.start_cons(SET);
       encoder.start_cons(SEQUENCE);
       encoder.encode((u32bit)0);
         encode_si(encoder, to);
         encoder.encode(AlgorithmIdentifier(pk_algo + "/" + padding));
         encoder.encode(enc->encrypt(cek.bits_of()), OCTET_STRING);
       encoder.end_cons();
     encoder.end_cons();
     encoder.raw_bytes(do_encrypt(cek, cipher));
   encoder.end_cons();

   add_layer("CMS.EnvelopedData", encoder);
   }

/*************************************************
* Encrypt a message with a key agreement algo    *
*************************************************/
void CMS_Encoder::encrypt_kari(const X509_Certificate&,
                               X509_PublicKey*,
                               const std::string&)
   {
   throw Exception("FIXME: unimplemented");
#if 0
   SymmetricKey cek = setup_key(cipher);

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(2);
     encoder.start_cons(SET);
       encoder.start_sequence(ASN1_Tag(1));
         encoder.encode(3);
         encode_si(encoder, to);
         encoder.encode(AlgorithmIdentifier(pk_algo + "/" + padding));
         encoder.encode(encrypted_cek, OCTET_STRING);
       encoder.end_cons(ASN1_Tag(1));
     encoder.end_cons();
     encoder.raw_bytes(do_encrypt(cek, cipher));
   encoder.end_cons();

   add_layer("CMS.EnvelopedData", encoder);
#endif
   }

/*************************************************
* Encrypt a message with a shared key            *
*************************************************/
void CMS_Encoder::encrypt(const SymmetricKey& kek,
                          const std::string& user_cipher)
   {
   throw Exception("FIXME: untested");

   const std::string cipher = choose_algo(user_cipher, "TripleDES");
   SymmetricKey cek = setup_key(cipher);

   SecureVector<byte> kek_id; // FIXME: ?

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(2);
     encoder.start_sequence(ASN1_Tag(2));
       encoder.encode(4);
       encoder.start_cons(SEQUENCE);
         encoder.encode(kek_id, OCTET_STRING);
       encoder.end_cons();
       encoder.encode(AlgorithmIdentifier("KeyWrap." + cipher, true));
       encoder.encode(wrap_key(cipher, cek, kek), OCTET_STRING);
     encoder.end_cons(ASN1_Tag(2));
     encoder.raw_bytes(do_encrypt(cek, cipher));
   encoder.end_cons();

   add_layer("CMS.EnvelopedData", encoder);
   }

/*************************************************
* Encrypt a message with a passphrase            *
*************************************************/
void CMS_Encoder::encrypt(const std::string&,
                          const std::string& user_cipher)
   {
   const std::string cipher = choose_algo(user_cipher, "TripleDES");
   throw Exception("FIXME: unimplemented");
   /*
   SymmetricKey cek = setup_key(key);

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(0);
     encoder.raw_bytes(do_encrypt(cek, cipher));
   encoder.end_cons();

   add_layer("CMS.EnvelopedData", encoder);
   */
   }

/*************************************************
* Encrypt the content with the chosen key/cipher *
*************************************************/
SecureVector<byte> CMS_Encoder::do_encrypt(const SymmetricKey& key,
                                           const std::string& cipher)
   {
   if(!have_block_cipher(cipher))
      throw Invalid_Argument("CMS: Can't encrypt with non-existent cipher " +
                             cipher);
   if(!OIDS::have_oid(cipher + "/CBC"))
      throw Encoding_Error("CMS: No OID assigned for " + cipher + "/CBC");

   InitializationVector iv(block_size_of(cipher));

   AlgorithmIdentifier content_cipher;
   content_cipher.oid = OIDS::lookup(cipher + "/CBC");
   content_cipher.parameters = encode_params(cipher, key, iv);

   Pipe pipe(get_cipher(cipher + "/CBC/PKCS7", key, iv, ENCRYPTION));
   pipe.process_msg(data);

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(OIDS::lookup(type));
     encoder.encode(content_cipher);
     encoder.encode(pipe.read_all(), OCTET_STRING, ASN1_Tag(0));
   encoder.end_cons();

   return encoder.get_contents();
   }

/*************************************************
* Sign a message                                 *
*************************************************/
void CMS_Encoder::sign(X509_Store& store, const PKCS8_PrivateKey& key)
   {
   std::vector<X509_Certificate> matching =
      X509_Store_Search::by_keyid(store, key.key_id());
   if(matching.size() == 0)
      throw Encoding_Error("CMS::sign: Cannot find cert matching given key");

   const X509_Certificate& cert = matching[0];

   std::vector<X509_Certificate> chain = store.get_cert_chain(cert);

   std::string padding, hash;
   Signature_Format format;
   Config::choose_sig_format(key.algo_name(), padding, hash, format);
   const std::string sig_algo = key.algo_name() + "/" + padding;

   SecureVector<byte> signed_attr = encode_attr(data, type, hash);
   const PK_Signing_Key& sig_key = dynamic_cast<const PK_Signing_Key&>(key);
   std::auto_ptr<PK_Signer> signer(get_pk_signer(sig_key, padding, format));
   signer->update(signed_attr);
   SecureVector<byte> signature = signer->signature();
   signed_attr[0] = 0xA0;

   const u32bit SI_VERSION = cert.has_SKID() ? 3 : 1;
   const u32bit CMS_VERSION = (type != "CMS.DataContent") ? 3 : SI_VERSION;

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(CMS_VERSION);
     encoder.start_cons(SET);
       encoder.encode(AlgorithmIdentifier(hash, true));
     encoder.end_cons();
     encoder.raw_bytes(make_econtent(data, type));

     encoder.start_set(ASN1_Tag(0));
     for(u32bit j = 0; j != chain.size(); j++)
        encoder.raw_bytes(chain[j].BER_encode());
     encoder.raw_bytes(cert.BER_encode());
     encoder.end_cons(ASN1_Tag(0));

     encoder.start_cons(SET);
       encoder.start_cons(SEQUENCE);
         encoder.encode(SI_VERSION);
         encode_si(encoder, cert, ((SI_VERSION == 3) ? true : false));
         encoder.encode(AlgorithmIdentifier(hash, true));
         encoder.raw_bytes(signed_attr);
         encoder.encode(AlgorithmIdentifier(sig_algo, true));
         encoder.encode(signature, OCTET_STRING);
       encoder.end_cons();
     encoder.end_cons();
   encoder.end_cons();

   add_layer("CMS.SignedData", encoder);
   }

/*************************************************
* Digest a message                               *
*************************************************/
void CMS_Encoder::digest(const std::string& user_hash)
   {
   const std::string hash = choose_algo(user_hash, "SHA-1");
   if(!OIDS::have_oid(hash))
      throw Encoding_Error("CMS: No OID assigned for " + hash);

   const u32bit VERSION = (type != "CMS.DataContent") ? 2 : 0;

   DER_Encoder encoder;
   encoder.start_cons(SEQUENCE);
     encoder.encode(VERSION);
     encoder.encode(AlgorithmIdentifier(hash, true));
     encoder.raw_bytes(make_econtent(data, type));
     encoder.encode(hash_of(data, hash), OCTET_STRING);
   encoder.end_cons();

   add_layer("CMS.DigestedData", encoder);
   }

/*************************************************
* MAC a message with an encrypted key            *
*************************************************/
void CMS_Encoder::authenticate(const X509_Certificate&,
                               const std::string& mac_algo)
   {
   const std::string mac = choose_algo(mac_algo, "HMAC(SHA-1)");
   throw Exception("FIXME: unimplemented");
   }

/*************************************************
* MAC a message with a shared key                *
*************************************************/
void CMS_Encoder::authenticate(const SymmetricKey&,
                               const std::string& mac_algo)
   {
   const std::string mac = choose_algo(mac_algo, "HMAC(SHA-1)");
   throw Exception("FIXME: unimplemented");
   }

/*************************************************
* MAC a message with a passphrase                *
*************************************************/
void CMS_Encoder::authenticate(const std::string&,
                               const std::string& mac_algo)
   {
   const std::string mac = choose_algo(mac_algo, "HMAC(SHA-1)");
   throw Exception("FIXME: unimplemented");
   }

}
