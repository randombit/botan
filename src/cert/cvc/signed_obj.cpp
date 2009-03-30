/*
* X.509 SIGNED Object
* (C) 1999-2007 Jack Lloyd
*     2007 FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#include <botan/signed_obj.h>

namespace Botan {

/*
* Return a BER encoded X.509 object
*/
SecureVector<byte> EAC_Signed_Object::BER_encode() const
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
std::string EAC_Signed_Object::PEM_encode() const
   {
   Pipe pem;
   pem.start_msg();
   encode(pem, PEM);
   pem.end_msg();
   return pem.read_all_as_string();
   }

/*
* Return the algorithm used to sign this object
*/
AlgorithmIdentifier EAC_Signed_Object::signature_algorithm() const
   {
   return sig_algo;
   }

/*
* Try to decode the actual information
*/
void EAC_Signed_Object::do_decode()
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
