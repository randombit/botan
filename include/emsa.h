/*************************************************
* EMSA Header File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EMSA_H__
#define BOTAN_EMSA_H__

#include <botan/pk_util.h>
#include <botan/pointers.h>

namespace Botan {

/*************************************************
* EMSA1                                          *
*************************************************/
class EMSA1 : public EMSA
   {
   public:
      EMSA1(const std::string&);
      virtual ~EMSA1() {  }
   private:
      virtual void update(const byte[], u32bit);
      virtual SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit);
      virtual SecureVector<byte> raw_data();
      virtual bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();
    protected:
      std::tr1::shared_ptr<HashFunction> hash;
   };

/*************************************************
* EMSA1 BSI variant                              *
*************************************************/
class EMSA1_BSI : public EMSA1
   {
   public:
      EMSA1_BSI(const std::string&);
      ~EMSA1_BSI() {  }
   private:
      /**
      * Accepts only hash values which are less or equal than the maximum
      * key length
      */
      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit);
   };



/*************************************************
* EMSA2                                          *
*************************************************/
class EMSA2 : public EMSA
   {
   public:
      EMSA2(const std::string&);
      ~EMSA2() { }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit);
      SecureVector<byte> raw_data();
      SecureVector<byte> empty_hash;
      std::tr1::shared_ptr<HashFunction> hash;
      byte hash_id;
   };

/*************************************************
* EMSA3                                          *
*************************************************/
class EMSA3 : public EMSA
   {
   public:
      EMSA3(const std::string&);
      ~EMSA3() { }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit);
      SecureVector<byte> raw_data();
      std::tr1::shared_ptr<HashFunction> hash;
      SecureVector<byte> hash_id;
   };

/*************************************************
* EMSA4                                          *
*************************************************/
class EMSA4 : public EMSA
   {
   public:
      EMSA4(const std::string&, const std::string&);
      EMSA4(const std::string&, const std::string&, u32bit);
      ~EMSA4() {  }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit);
      SecureVector<byte> raw_data();
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();
      const u32bit SALT_SIZE;
      std::tr1::shared_ptr<HashFunction> hash;
      std::tr1::shared_ptr<MGF const> mgf;
   };

/*************************************************
* EMSA-Raw                                       *
*************************************************/
class EMSA_Raw : public EMSA
   {
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit);
      SecureVector<byte> raw_data();
      SecureVector<byte> message;
   };

}

#endif
