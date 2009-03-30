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
      SecureVector<byte> tbs_data() const;
      SecureVector<byte> signature() const;
      AlgorithmIdentifier signature_algorithm() const;

      /**
      * Create a signed X509 object.
      * @param signer the signer used to sign the object
      * @param rng the random number generator to use
      * @param alg_id the algorithm identifier of the signature scheme
      * @param tbs the tbs bits to be signed
      * @return the signed X509 object
      */
      static MemoryVector<byte> make_signed(class PK_Signer* signer,
                                            RandomNumberGenerator& rng,
                                            const AlgorithmIdentifier& alg_id,
                                            const MemoryRegion<byte>& tbs);

      bool check_signature(class Public_Key&) const;

      void encode(Pipe&, X509_Encoding = PEM) const;
      SecureVector<byte> BER_encode() const;
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
