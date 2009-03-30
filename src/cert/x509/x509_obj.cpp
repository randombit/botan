/*
* X.509 SIGNED Object
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509_obj.h>
#include <botan/x509_key.h>
#include <botan/look_pk.h>
#include <botan/oids.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/pem.h>
#include <algorithm>
#include <memory>

namespace Botan {

/*
* Create a generic X.509 object
*/
X509_Object::X509_Object(DataSource& stream, const std::string& labels)
   {
   init(stream, labels);
   }

/*
* Createa a generic X.509 object
*/
X509_Object::X509_Object(const std::string& file, const std::string& labels)
   {
   DataSource_Stream stream(file, true);
   init(stream, labels);
   }

/*
* Read a PEM or BER X.509 object
*/
void X509_Object::init(DataSource& in, const std::string& labels)
   {
   PEM_labels_allowed = split_on(labels, '/');
   if(PEM_labels_allowed.size() < 1)
      throw Invalid_Argument("Bad labels argument to X509_Object");

   PEM_label_pref = PEM_labels_allowed[0];
   std::sort(PEM_labels_allowed.begin(), PEM_labels_allowed.end());

   try {
      if(ASN1::maybe_BER(in) && !PEM_Code::matches(in))
         decode_info(in);
      else
         {
         std::string got_label;
         DataSource_Memory ber(PEM_Code::decode(in, got_label));

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

/*
* Read a BER encoded X.509 object
*/
void X509_Object::decode_info(DataSource& source)
   {
   BER_Decoder(source)
      .start_cons(SEQUENCE)
         .start_cons(SEQUENCE)
            .raw_bytes(tbs_bits)
         .end_cons()
         .decode(sig_algo)
         .decode(sig, BIT_STRING)
         .verify_end()
      .end_cons();
   }

/*
* Return a BER or PEM encoded X.509 object
*/
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

/*
* Return a BER encoded X.509 object
*/
SecureVector<byte> X509_Object::BER_encode() const
   {
   Pipe ber;
   ber.start_msg();
   encode(ber, RAW_BER);
   ber.end_msg();
   return ber.read_all();
   }

/*
* Return a PEM encoded X.509 object
*/
std::string X509_Object::PEM_encode() const
   {
   Pipe pem;
   pem.start_msg();
   encode(pem, PEM);
   pem.end_msg();
   return pem.read_all_as_string();
   }

/*
* Return the TBS data
*/
SecureVector<byte> X509_Object::tbs_data() const
   {
   return ASN1::put_in_sequence(tbs_bits);
   }

/*
* Return the signature of this object
*/
SecureVector<byte> X509_Object::signature() const
   {
   return sig;
   }

/*
* Return the algorithm used to sign this object
*/
AlgorithmIdentifier X509_Object::signature_algorithm() const
   {
   return sig_algo;
   }

/*
* Check the signature on an object
*/
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
         verifier.reset(get_pk_verifier(sig_key, padding, format));
         }
      else if(dynamic_cast<PK_Verifying_wo_MR_Key*>(&pub_key))
         {
         PK_Verifying_wo_MR_Key& sig_key =
            dynamic_cast<PK_Verifying_wo_MR_Key&>(pub_key);
         verifier.reset(get_pk_verifier(sig_key, padding, format));
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

/*
* Apply the X.509 SIGNED macro
*/
MemoryVector<byte> X509_Object::make_signed(PK_Signer* signer,
                                            RandomNumberGenerator& rng,
                                            const AlgorithmIdentifier& algo,
                                            const MemoryRegion<byte>& tbs_bits)
   {
   return DER_Encoder()
      .start_cons(SEQUENCE)
         .raw_bytes(tbs_bits)
         .encode(algo)
         .encode(signer->sign_message(tbs_bits, rng), BIT_STRING)
      .end_cons()
   .get_contents();
   }

/*
* Try to decode the actual information
*/
void X509_Object::do_decode()
   {
   try {
      force_decode();
      }
   catch(Decoding_Error& e)
      {
      const std::string what = e.what();
      throw Decoding_Error(PEM_label_pref + " decoding failed (" +
                           what.substr(23, std::string::npos) + ")");
      }
   catch(Invalid_Argument& e)
      {
      const std::string what = e.what();
      throw Decoding_Error(PEM_label_pref + " decoding failed (" +
                           what.substr(7, std::string::npos) + ")");
      }
   }

}
