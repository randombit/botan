/*************************************************
* EMSA Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EMSA_H__
#define BOTAN_EMSA_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* EMSA1                                          *
*************************************************/
class BOTAN_DLL EMSA1 : public EMSA
   {
   public:
      EMSA1(const std::string&);
      ~EMSA1() { delete hash; }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      HashFunction* hash;
   };

/*************************************************
* EMSA2                                          *
*************************************************/
class BOTAN_DLL EMSA2 : public EMSA
   {
   public:
      EMSA2(const std::string&);
      ~EMSA2() { delete hash; }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      SecureVector<byte> empty_hash;
      HashFunction* hash;
      byte hash_id;
   };

/*************************************************
* EMSA3                                          *
*************************************************/
class BOTAN_DLL EMSA3 : public EMSA
   {
   public:
      EMSA3(const std::string&);
      ~EMSA3() { delete hash; }
   private:
      void update(const byte[], u32bit);

      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);

      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      HashFunction* hash;
      SecureVector<byte> hash_id;
   };

/*************************************************
* EMSA4                                          *
*************************************************/
class BOTAN_DLL EMSA4 : public EMSA
   {
   public:
      EMSA4(const std::string&, const std::string&);
      EMSA4(const std::string&, const std::string&, u32bit);
      ~EMSA4() { delete hash; delete mgf; }
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator& rng);
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      const u32bit SALT_SIZE;
      HashFunction* hash;
      const MGF* mgf;
   };

/*************************************************
* EMSA-Raw                                       *
*************************************************/
class BOTAN_DLL EMSA_Raw : public EMSA
   {
   private:
      void update(const byte[], u32bit);
      SecureVector<byte> raw_data();

      SecureVector<byte> encoding_of(const MemoryRegion<byte>&, u32bit,
                                     RandomNumberGenerator&);
      bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                  u32bit) throw();

      SecureVector<byte> message;
   };

}

#endif
