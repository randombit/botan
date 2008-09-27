/*************************************************
* KDF Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KDF_H__
#define BOTAN_KDF_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* KDF1                                           *
*************************************************/
class BOTAN_DLL KDF1 : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;

      KDF1(const std::string&);
   private:
      const std::string hash_name;
   };

/*************************************************
* KDF2                                           *
*************************************************/
class BOTAN_DLL KDF2 : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;

      KDF2(const std::string&);
   private:
      const std::string hash_name;
   };

/*************************************************
* X9.42 PRF                                      *
*************************************************/
class BOTAN_DLL X942_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;

      X942_PRF(const std::string&);
   private:
      std::string key_wrap_oid;
   };

/*************************************************
* SSL3 PRF                                       *
*************************************************/
class BOTAN_DLL SSL3_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;
   };

/*************************************************
* TLS PRF                                        *
*************************************************/
class BOTAN_DLL TLS_PRF : public KDF
   {
   public:
      SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                const byte[], u32bit) const;
   private:
      SecureVector<byte> P_hash(const std::string&, u32bit,
                                const byte[], u32bit,
                                const byte[], u32bit) const;
   };

}

#endif
