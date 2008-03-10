/*************************************************
* X.509 SIGNED Object Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_OBJECT_H__
#define BOTAN_X509_OBJECT_H__

#include <botan/asn1_obj.h>
#include <botan/pipe.h>
#include <vector>

namespace Botan {

/*************************************************
* Generic X.509 SIGNED Object                    *
*************************************************/
class X509_Object
   {
   public:
      SecureVector<byte> tbs_data() const;
      SecureVector<byte> signature() const;
      AlgorithmIdentifier signature_algorithm() const;

      static MemoryVector<byte> make_signed(class PK_Signer*,
                                            const AlgorithmIdentifier&,
                                            const MemoryRegion<byte>&);

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
