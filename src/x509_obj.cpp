/*************************************************
* X.509 SIGNED Object Source File                *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x509_obj.h>
#include <botan/parsing.h>
#include <botan/pem.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Create a generic X.509 object                  *
*************************************************/
X509_Object::X509_Object(DataSource& stream, const std::string& labels)
   {
   init(stream, labels);
   }

/*************************************************
* Createa a generic X.509 object                 *
*************************************************/
X509_Object::X509_Object(const std::string& file, const std::string& labels)
   {
   DataSource_Stream stream(file, true);
   init(stream, labels);
   }

/*************************************************
* Read a PEM or BER X.509 object                 *
*************************************************/
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

/*************************************************
* Read a BER encoded X.509 object                *
*************************************************/
void X509_Object::decode_info(DataSource& source)
   {
   BER_Decoder ber(source);
   BER_Decoder sequence = BER::get_subsequence(ber);
   tbs_bits = BER::get_subsequence(sequence).get_remaining();

   BER::decode(sequence, sig_algo);
   sequence.decode(sig, BIT_STRING);
   sequence.verify_end();
   }

/*************************************************
* Return a BER or PEM encoded X.509 object       *
*************************************************/
void X509_Object::encode(Pipe& out, X509_Encoding encoding) const
   {
   SecureVector<byte> der = 
      DER_Encoder().start_sequence()
         .add_raw_octets(tbs_data())
         .encode(sig_algo)
         .encode(sig, BIT_STRING)
      .end_sequence()
   .get_contents();

   if(encoding == PEM)
      out.write(PEM_Code::encode(der, PEM_label_pref));
   else
      out.write(der);
   }

/*************************************************
* Return a BER encoded X.509 object              *
*************************************************/
SecureVector<byte> X509_Object::BER_encode() const
   {
   Pipe ber;
   ber.start_msg();
   encode(ber, RAW_BER);
   ber.end_msg();
   return ber.read_all();
   }

/*************************************************
* Return a PEM encoded X.509 object              *
*************************************************/
std::string X509_Object::PEM_encode() const
   {
   Pipe pem;
   pem.start_msg();
   encode(pem, PEM);
   pem.end_msg();
   return pem.read_all_as_string();
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
* Return the algorithm used to sign this object  *
*************************************************/
AlgorithmIdentifier X509_Object::signature_algorithm() const
   {
   return sig_algo;
   }

/*************************************************
* Try to decode the actual information           *
*************************************************/
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
