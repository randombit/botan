/*
* CMS Decoding Operations
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cms_dec.h>
#include <botan/x509find.h>
#include <botan/ber_dec.h>
#include <botan/oids.h>
#include <botan/hash.h>
#include <botan/look_pk.h>
#include <botan/bigint.h>
#include <botan/libstate.h>
#include <memory>

namespace Botan {

namespace {

/*
* Compute the hash of some content
*/
SecureVector<byte> hash_of(const SecureVector<byte>& content,
                           const AlgorithmIdentifier& hash_algo,
                           std::string& hash_name)
   {
   hash_name = OIDS::lookup(hash_algo.oid);

   Algorithm_Factory& af = global_state().algorithm_factory();

   std::auto_ptr<HashFunction> hash_fn(af.make_hash_function(hash_name));
   return hash_fn->process(content);
   }

/*
* Find a cert based on SignerIdentifier
*/
std::vector<X509_Certificate> get_cert(BER_Decoder& signer_info,
                                       X509_Store& store)
   {
   BER_Object id = signer_info.get_next_object();

   std::vector<X509_Certificate> found;

   if(id.type_tag == SEQUENCE && id.class_tag == CONSTRUCTED)
      {
      X509_DN issuer;
      BigInt serial;
      BER_Decoder iands(id.value);
      iands.decode(issuer);
      iands.decode(serial);

      found = store.get_certs(IandS_Match(issuer, BigInt::encode(serial)));
      }
   else if(id.type_tag == 0 && id.class_tag == CONSTRUCTED)
      found = store.get_certs(SKID_Match(id.value));
   else
      throw Decoding_Error("CMS: Unknown tag for cert identifier");

   // verify cert if found

   if(found.size() > 1)
      throw Internal_Error("CMS: Found more than one match in get_cert");
   return found;
   }

/*
* Read OriginatorInfo
*/
void read_orig_info(BER_Decoder& info, X509_Store& store)
   {
   BER_Object next = info.get_next_object();

   if(next.type_tag == 0 &&
      next.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      DataSource_Memory certs(next.value);
      while(!certs.end_of_data())
         {
         // FIXME: can be attribute certs too
         // FIXME: DoS?
         X509_Certificate cert(certs);
         store.add_cert(cert);
         }
      next = info.get_next_object();
      }
   if(next.type_tag == 1 &&
      next.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      {
      DataSource_Memory crls(next.value);
      while(!crls.end_of_data())
         {
         // FIXME: DoS?
         X509_CRL crl(crls);
         store.add_crl(crl);
         }
      next = info.get_next_object();
      }
   info.push_back(next);
   }

/*
* Decode any Attributes, and check type
*/
SecureVector<byte> decode_attributes(BER_Decoder& ber, const OID& type,
                                     bool& bad_attributes)
   {
   BER_Object obj = ber.get_next_object();
   SecureVector<byte> digest;

   bool got_digest = false;
   bool got_content_type = false;

   if(obj.type_tag == 0 &&
      obj.class_tag == ASN1_Tag(CONSTRUCTED | CONTEXT_SPECIFIC))
      ber.push_back(obj);
   else
      {
      BER_Decoder attributes(obj.value);
      while(attributes.more_items())
         {
         Attribute attr;
         attributes.decode(attr);
         BER_Decoder attr_value(attr.parameters);

         if(attr.oid == OIDS::lookup("PKCS9.MessageDigest"))
            {
            got_digest = true;
            attr_value.decode(digest, OCTET_STRING);
            }
         else if(attr.oid == OIDS::lookup("PKCS9.ContentType"))
            {
            got_content_type = true;
            OID inner_type;
            attr_value.decode(inner_type);
            if(inner_type != type)
               bad_attributes = true;
            }
         else
            throw Decoding_Error("Unknown/unhandled CMS attribute found: " +
                                 OIDS::lookup(attr.oid));
         }

      if(!got_digest || !got_content_type)
         bad_attributes = true;
      }

   return digest;
   }

}

/*
* Decode this layer of CMS encoding
*/
void CMS_Decoder::decode_layer()
   {
   try {
      if(status == FAILURE)
         throw Invalid_State("CMS: Decoder is in FAILURE state");

      status = GOOD;
      info = "";

      type = next_type;

      if(type == OIDS::lookup("CMS.DataContent"))
         return;

      BER_Decoder decoder(data);
      if(type == OIDS::lookup("CMS.CompressedData"))
         decompress(decoder);
      else if(type == OIDS::lookup("CMS.DigestedData"))
         {
         u32bit version;
         AlgorithmIdentifier hash_algo;
         SecureVector<byte> digest;

         BER_Decoder hash_info = decoder.start_cons(SEQUENCE);

         hash_info.decode(version);
         if(version != 0 && version != 2)
            throw Decoding_Error("CMS: Unknown version for DigestedData");

         hash_info.decode(hash_algo);
         read_econtent(hash_info);
         hash_info.decode(digest, OCTET_STRING);
         hash_info.end_cons();

         if(digest != hash_of(data, hash_algo, info))
            status = BAD;
         }
      else if(type == OIDS::lookup("CMS.SignedData"))
         {
#if 1
         throw Exception("FIXME: not implemented");
#else
         u32bit version;

         BER_Decoder sig_info = BER::get_subsequence(decoder);
         BER::decode(sig_info, version);
         if(version != 1 && version != 3)
            throw Decoding_Error("CMS: Unknown version for SignedData");
         BER::get_subset(sig_info); // hash algos (do something with these?)
         read_econtent(sig_info);
         read_orig_info(sig_info, store);

         BER_Decoder signer_infos = BER::get_subset(sig_info);
         while(signer_infos.more_items())
            {
            AlgorithmIdentifier sig_algo, hash_algo;
            SecureVector<byte> signature, digest;
            u32bit version;

            BER_Decoder signer_info = BER::get_subsequence(signer_infos);
            BER::decode(signer_info, version);
            if(version != 1 && version != 3)
               throw Decoding_Error("CMS: Unknown version for SignerInfo");

            std::vector<X509_Certificate> certs = get_cert(signer_info, store);
            if(certs.size() == 0) { status = NO_KEY; continue; }

            BER::decode(signer_info, hash_algo);
            bool bad_attr = false;
            digest = decode_attributes(signer_info, next_type, bad_attr);
            if(bad_attr) { status = BAD; continue; }
            BER::decode(signer_info, sig_algo);
            BER::decode(signer_info, signature, OCTET_STRING);
            // unsigned attributes
            signer_info.verify_end();

            if(digest.has_items())
               {
               std::string hash;
               if(digest != hash_of(data, hash_algo, hash))
                  {
                  status = BAD;
                  continue;
                  }
               status = check_sig(signed_attr, sig_algo, signature, certs[0]);
               }
            else
               status = check_sig(data, sig_algo, signature, certs[0]);

            if(status == BAD)
               continue;

            // fix this (gets only last signer, for one thing)
            // maybe some way for the user to get all certs that signed the
            // message? that would be useful
            info = "CN=" + cert.subject_info("CommonName") +
                   ",O="  + cert.subject_info("Organization") +
                   ",OU=" + cert.subject_info("Organizational Unit");
            }
#endif
         }
      else if(type == OIDS::lookup("CMS.EnvelopedData"))
         {
         throw Exception("FIXME: not implemented");
         }
      else if(type == OIDS::lookup("CMS.AuthenticatedData"))
         {
         throw Exception("FIXME: not implemented");
         }
      else
         throw Decoding_Error("CMS: Unknown content ID " + type.as_string());
   }
   catch(std::exception)
      {
      status = FAILURE;
      }
   }

}
