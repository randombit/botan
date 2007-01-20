/*************************************************
* CBC Padding Methods Header File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_CBC_PADDING_H__
#define BOTAN_CBC_PADDING_H__

#include <botan/base.h>
#include <string>

namespace Botan {

/*************************************************
* Block Cipher Mode Padding Method               *
*************************************************/
class BlockCipherModePaddingMethod
   {
   public:
      virtual void pad(byte[], u32bit, u32bit) const = 0;
      virtual u32bit unpad(const byte[], u32bit) const = 0;
      virtual u32bit pad_bytes(u32bit, u32bit) const;
      virtual bool valid_blocksize(u32bit) const = 0;
      virtual std::string name() const = 0;
      virtual ~BlockCipherModePaddingMethod() {}
   };

/*************************************************
* PKCS#7 Padding                                 *
*************************************************/
class PKCS7_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], u32bit, u32bit) const;
      u32bit unpad(const byte[], u32bit) const;
      bool valid_blocksize(u32bit) const;
      std::string name() const { return "PKCS7"; }
   };

/*************************************************
* ANSI X9.23 Padding                             *
*************************************************/
class ANSI_X923_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], u32bit, u32bit) const;
      u32bit unpad(const byte[], u32bit) const;
      bool valid_blocksize(u32bit) const;
      std::string name() const { return "X9.23"; }
   };

/*************************************************
* One And Zeros Padding                          *
*************************************************/
class OneAndZeros_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], u32bit, u32bit) const;
      u32bit unpad(const byte[], u32bit) const;
      bool valid_blocksize(u32bit) const;
      std::string name() const { return "OneAndZeros"; }
   };

/*************************************************
* Null Padding                                   *
*************************************************/
class Null_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], u32bit, u32bit) const { return; }
      u32bit unpad(const byte[], u32bit size) const { return size; }
      u32bit pad_bytes(u32bit, u32bit) const { return 0; }
      bool valid_blocksize(u32bit) const { return true; }
      std::string name() const { return "NoPadding"; }
   };

}

#endif
