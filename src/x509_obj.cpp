/*************************************************
* X.509 SIGNED Object Source File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/x509_obj.h>
#include <botan/x509_key.h>
#include <botan/look_pk.h>
#include <botan/oids.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/pem.h>
#include <algorithm>
#include <botan/pointers.h>

namespace Botan {

/*************************************************
* Create a generic X.509 object                  *
*************************************************/
 X509_Object::X509_Object(SharedPtrConverter<DataSource> stream, const std::string& labels)
    {
    init(stream.get_shared(), labels);
    }

/*************************************************
* Createa a generic X.509 object                 *
*************************************************/
 X509_Object::X509_Object(const std::string& file, const std::string& labels)
    {
    std::tr1::shared_ptr<DataSource> stream(new DataSource_Stream(file, true));
    init(stream, labels);
    }

/*************************************************
* Read a PEM or BER X.509 object                 *
*************************************************/
void X509_Object::init(SharedPtrConverter<DataSource> in, const std::string& labels)
   {
   PEM_labels_allowed = split_on(labels, '/');
   if(PEM_labels_allowed.size() < 1)
      throw Invalid_Argument("Bad labels argument to X509_Object");

   PEM_label_pref = PEM_labels_allowed[0];
   std::sort(PEM_labels_allowed.begin(), PEM_labels_allowed.end());

   try {
      if(ASN1::maybe_BER(in.get_shared()) && !PEM_Code::matches(in.get_shared()))
         decode_info(in.get_shared());
      else
         {
         std::string got_label;
         std::tr1::shared_ptr<DataSource> ber(new DataSource_Memory (PEM_Code::decode(in.get_shared(), got_label)));

         if(!std::binary_search(PEM_labels_allowed.begin(),
                                PEM_labels_allowed.end(), got_label))
            throw Decoding_Error("Invalid PEM label: " + got_label);
         decode_info(ber);
         }
      }
   catch(Decoding_Error)
      {
      throw Decoding_Error(PEM_label_pref + " decoding failed");
      }
   }

/*************************************************
* Read a BER encoded X.509 object                *
*************************************************/
void X509_Object::decode_info(SharedPtrConverter<DataSource> source)
   {
   BER_Decoder(source.get_shared())
      .start_cons(SEQUENCE)
         .start_cons(SEQUENCE)
            .raw_bytes(tbs_bits)
         .end_cons()
         .decode(sig_algo)
         .decode(sig, BIT_STRING)
         .verify_end()
      .end_cons();
   }

/*************************************************
* Return a BER or PEM encoded X.509 object       *
*************************************************/
void X509_Object::encode(Pipe& out, X509_Encoding encoding) const
   {
   SecureVector<byte> der = DER_Encoder()
      .start_cons(SEQUENCE)
         .start_cons(SEQUENCE)
            .raw_bytes(tbs_bits)
         .end_cons()
         .encode(sig_algo)
         .encode(sig, BIT_STRING)
      .end_cons()
   .get_contents();

   if(encoding == PEM)
      out.write(PEM_Code::encode(der, PEM_label_pref));
   else
      out.write(der);
   }


/*************************************************
* Return the TBS data                            *
*************************************************/
SecureVector<byte> X509_Object::tbs_data() const
   {
   return ASN1::put_in_sequence(tbs_bits);
   }

/*************************************************
* Return the signature of this object            *
*************************************************/
SecureVector<byte> X509_Object::signature() const
   {
   return sig;
   }

/*************************************************
   * Return the signature of this object            *
*************************************************/
   SecureVector<byte> X509_Object::get_concat_sig() const
   {
   return sig;
   }


/*************************************************
* Check the signature on an object               *
*************************************************/
bool X509_Object::check_signature(Public_Key& pub_key) const
   {
   try {
      std::vector<std::string> sig_info =
         split_on(OIDS::lookup(sig_algo.oid), '/');

      if(sig_info.size() != 2 || sig_info[0] != pub_key.algo_name())
         return false;

      std::string padding = sig_info[1];
      Signature_Format format =
         (pub_key.message_parts() >= 2) ? DER_SEQUENCE : IEEE_1363;

      std::auto_ptr<PK_Verifier> verifier;

      if(dynamic_cast<PK_Verifying_with_MR_Key*>(&pub_key))
         {
         PK_Verifying_with_MR_Key& sig_key =
            dynamic_cast<PK_Verifying_with_MR_Key&>(pub_key);
         verifier.reset(get_pk_verifier(sig_key, padding, format).release());
         }
      else if(dynamic_cast<PK_Verifying_wo_MR_Key*>(&pub_key))
         {
         PK_Verifying_wo_MR_Key& sig_key =
            dynamic_cast<PK_Verifying_wo_MR_Key&>(pub_key);
         verifier.reset(get_pk_verifier(sig_key, padding, format).release());
         }
      else
         return false;

      return verifier->verify_message(tbs_data(), signature());
      }
   catch(...)
      {
      return false;
      }
   }

/*************************************************
* Apply the X.509 SIGNED macro                   *
*************************************************/
MemoryVector<byte> X509_Object::make_signed(SharedPtrConverter<PK_Signer> signer,
                                            const AlgorithmIdentifier& algo,
                                            const MemoryRegion<byte>& tbs_bits)
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .raw_bytes(tbs_bits)
         .encode(algo)
         .encode(signer.get_shared()->sign_message(tbs_bits), BIT_STRING)
      .end_cons()
   .get_contents();
   }


 }
