/*************************************************
* PK Filters Header File                         *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_PK_FILTERS_H__
#define BOTAN_PK_FILTERS_H__

#include <botan/filter.h>
#include <botan/pubkey.h>

namespace Botan {

/*************************************************
* PK_Encryptor Filter                            *
*************************************************/
class PK_Encryptor_Filter : public Filter
   {
   public:
      void write(const byte[], u32bit);
      void end_msg();
      PK_Encryptor_Filter(SharedPtrConverter<PK_Encryptor> const& c) : cipher(c.get_shared()) {}
      ~PK_Encryptor_Filter() { }
   private:
      std::tr1::shared_ptr<PK_Encryptor> cipher;
      SecureVector<byte> buffer;
   };

/*************************************************
* PK_Decryptor Filter                            *
*************************************************/
class PK_Decryptor_Filter : public Filter
   {
   public:
      void write(const byte[], u32bit);
      void end_msg();
      PK_Decryptor_Filter(SharedPtrConverter<PK_Decryptor> const& c) : cipher(c.get_shared()) {}
      ~PK_Decryptor_Filter() { }
   private:
     std::tr1::shared_ptr<PK_Decryptor> cipher;
      SecureVector<byte> buffer;
   };

/*************************************************
* PK_Signer Filter                               *
*************************************************/
class PK_Signer_Filter : public Filter
   {
   public:
      void write(const byte[], u32bit);
      void end_msg();
      PK_Signer_Filter(SharedPtrConverter<PK_Signer> const& s) : signer(s.get_shared()) {}
      ~PK_Signer_Filter() { }
   private:
     std::tr1::shared_ptr<PK_Signer> signer;
   };

/*************************************************
* PK_Verifier Filter                             *
*************************************************/
class PK_Verifier_Filter : public Filter
   {
   public:
      void write(const byte[], u32bit);
      void end_msg();

      void set_signature(const byte[], u32bit);
      void set_signature(const MemoryRegion<byte>&);

      PK_Verifier_Filter(SharedPtrConverter<PK_Verifier> const& v) : verifier(v.get_shared()) {}
      PK_Verifier_Filter(SharedPtrConverter<PK_Verifier> const&, const byte[], u32bit);
      PK_Verifier_Filter(SharedPtrConverter<PK_Verifier> const&, const MemoryRegion<byte>&);
      ~PK_Verifier_Filter() {  }
   private:
      std::tr1::shared_ptr<PK_Verifier> verifier;
      SecureVector<byte> signature;
   };

}

#endif
