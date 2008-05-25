/*************************************************
* X.509 SIGNED Object Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_X509_OBJECT_H__
#define BOTAN_X509_OBJECT_H__

#include <botan/asn1_obj.h>
#include <botan/pipe.h>
#include <vector>
#include <botan/signed_obj.h>

namespace Botan {

/*************************************************
* Generic X.509 SIGNED Object                    *
*************************************************/
class X509_Object : public Signed_Object
   {
       public:

           SecureVector<byte> tbs_data() const;
           SecureVector<byte> signature() const;
           SecureVector<byte> get_concat_sig() const;
           static MemoryVector<byte> make_signed(SharedPtrConverter<class PK_Signer>,
                   const AlgorithmIdentifier&,
                   const MemoryRegion<byte>&);

           void encode(Pipe&, X509_Encoding = PEM) const;
           void decode_info(SharedPtrConverter<DataSource>);

           bool check_signature(class Public_Key&) const;

           X509_Object(const std::string&, const std::string&);
           X509_Object(SharedPtrConverter<DataSource>, const std::string&);

           virtual ~X509_Object() {}

       protected:
           X509_Object() {}
           SecureVector<byte> sig;
       private:
           void init(SharedPtrConverter<DataSource>, const std::string&);
   /*public:
      SecureVector<byte> tbs_data() const;
      SecureVector<byte> signature() const;
      AlgorithmIdentifier signature_algorithm() const;

      static MemoryVector<byte> make_signed(std::tr1::shared_ptr<class PK_Signer>,
                                            const AlgorithmIdentifier&,
                                            const MemoryRegion<byte>&);

      bool check_signature(class Public_Key&) const;

      void encode(Pipe&, X509_Encoding = PEM) const;
      SecureVector<byte> BER_encode() const;
      std::string PEM_encode() const;

      X509_Object(std::tr1::shared_ptr<DataSource>&, const std::string&);
      X509_Object(const std::string&, const std::string&);
      virtual ~X509_Object() {}
   protected:
      void do_decode();
      X509_Object() {}
      AlgorithmIdentifier sig_algo;
      SecureVector<byte> tbs_bits, sig;
   private:
      virtual void force_decode() = 0;
      void init(std::tr1::shared_ptr<DataSource>&, const std::string&);
      void decode_info(std::tr1::shared_ptr<DataSource>&);
      std::vector<std::string> PEM_labels_allowed;
      std::string PEM_label_pref;*/
   };

}

#endif
