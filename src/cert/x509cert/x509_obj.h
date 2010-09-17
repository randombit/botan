/*
* X.509 SIGNED Object
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_OBJECT_H__
#define BOTAN_X509_OBJECT_H__

#include <botan/asn1_obj.h>
#include <botan/pipe.h>
#include <botan/pubkey_enums.h>
#include <botan/rng.h>
#include <vector>

namespace Botan {

/**
* This class represents abstract X.509 signed objects as
* in the X.500 SIGNED macro
*/
class BOTAN_DLL X509_Object
   {
   public:

      /**
      * The underlying data that is to be or was signed
      * @return data that is or was signed
      */
      SecureVector<byte> tbs_data() const;

      /**
      * @return signature on tbs_data()
      */
      SecureVector<byte> signature() const;

      /**
      * @return signature algorithm that was used to generate signature
      */
      AlgorithmIdentifier signature_algorithm() const;

      /**
      * Create a signed X509 object.
      * @param signer the signer used to sign the object
      * @param rng the random number generator to use
      * @param alg_id the algorithm identifier of the signature scheme
      * @param tbs the tbs bits to be signed
      * @return signed X509 object
      */
      static MemoryVector<byte> make_signed(class PK_Signer* signer,
                                            RandomNumberGenerator& rng,
                                            const AlgorithmIdentifier& alg_id,
                                            const MemoryRegion<byte>& tbs);

      /**
      * Check the signature on this data
      * @param key the public key purportedly used to sign this data
      * @return true if the signature is valid, otherwise false
      */
      bool check_signature(class Public_Key& key) const;

      /**
      * Check the signature on this data
      * @param key the public key purportedly used to sign this data
      *        the pointer will be deleted after use
      * @return true if the signature is valid, otherwise false
      */
      bool check_signature(class Public_Key* key) const;

      /**
      * Encode this to a pipe
      * @deprecated use BER_encode or PEM_encode instead
      * @param out the pipe to write to
      * @param encoding the encoding to use
      */
      void encode(Pipe& out, X509_Encoding encoding = PEM) const;

      /**
      * @return BER encoding of this
      */
      SecureVector<byte> BER_encode() const;

      /**
      * @return PEM encoding of this
      */
      std::string PEM_encode() const;

      X509_Object(DataSource&, const std::string&);
      X509_Object(const std::string&, const std::string&);
      virtual ~X509_Object() {}
   protected:
      void do_decode();
      X509_Object() {}
      AlgorithmIdentifier sig_algo;
      SecureVector<byte> tbs_bits, sig;
   private:
      virtual void force_decode() = 0;
      void init(DataSource&, const std::string&);
      void decode_info(DataSource&);
      std::vector<std::string> PEM_labels_allowed;
      std::string PEM_label_pref;
   };

}

#endif
