/*************************************************
* EME Header File                                *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_EME_H__
#define BOTAN_EME_H__

#include <botan/pk_util.h>

namespace Botan {

/*************************************************
* EME1                                           *
*************************************************/
class BOTAN_DLL EME1 : public EME
   {
   public:
      u32bit maximum_input_size(u32bit) const;

      EME1(const std::string&, const std::string&, const std::string& = "");
      ~EME1() { delete mgf; }
   private:
      SecureVector<byte> pad(const byte[], u32bit, u32bit,
                             RandomNumberGenerator&) const;
      SecureVector<byte> unpad(const byte[], u32bit, u32bit) const;

      const u32bit HASH_LENGTH;
      SecureVector<byte> Phash;
      MGF* mgf;
   };

/*************************************************
* EME_PKCS1v15                                   *
*************************************************/
class BOTAN_DLL EME_PKCS1v15 : public EME
   {
   public:
      u32bit maximum_input_size(u32bit) const;
   private:
      SecureVector<byte> pad(const byte[], u32bit, u32bit,
                             RandomNumberGenerator&) const;
      SecureVector<byte> unpad(const byte[], u32bit, u32bit) const;
   };

}

#endif
