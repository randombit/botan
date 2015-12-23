/*
* EAC SIGNED Object
* (C) 2007 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EAC_SIGNED_OBJECT_H__
#define BOTAN_EAC_SIGNED_OBJECT_H__

#include <botan/asn1_obj.h>
#include <botan/x509_key.h>
#include <botan/pipe.h>
#include <vector>

namespace Botan {

/**
* This class represents abstract signed EAC object
*/
class BOTAN_DLL EAC_Signed_Object
   {
   public:
      /**
      * Get the TBS (to-be-signed) data in this object.
      * @return DER encoded TBS data of this object
      */
      virtual std::vector<byte> tbs_data() const = 0;

      /**
      * Get the signature of this object as a concatenation, i.e. if the
      * signature consists of multiple parts (like in the case of ECDSA)
      * these will be concatenated.
      * @return signature as a concatenation of its parts
      */

      /*
       NOTE: this is here only because abstract signature objects have
       not yet been introduced
      */
      virtual std::vector<byte> get_concat_sig() const = 0;

      /**
      * Get the signature algorithm identifier used to sign this object.
      * @result the signature algorithm identifier
      */
      AlgorithmIdentifier signature_algorithm() const;

      /**
      * Check the signature of this object.
      * @param key the public key associated with this signed object
      * @param sig the signature we are checking
      * @return true if the signature was created by the private key
      * associated with this public key
      */
      bool check_signature(class Public_Key& key,
                           const std::vector<byte>& sig) const;

      /**
      * Write this object DER encoded into a specified pipe.
      * @param pipe the pipe to write the encoded object to
      * @param encoding the encoding type to use
      */
      virtual void encode(Pipe& pipe,
                          X509_Encoding encoding = PEM) const = 0;

      /**
      * BER encode this object.
      * @return result containing the BER representation of this object.
      */
      std::vector<byte> BER_encode() const;

      /**
      * PEM encode this object.
      * @return result containing the PEM representation of this object.
      */
      std::string PEM_encode() const;

      virtual ~EAC_Signed_Object() {}
   protected:
      void do_decode();
      EAC_Signed_Object() {}

      AlgorithmIdentifier m_sig_algo;
      std::vector<byte> m_tbs_bits;
      std::string m_PEM_label_pref;
      std::vector<std::string> m_PEM_labels_allowed;
   private:
      virtual void force_decode() = 0;
   };

}

#endif
