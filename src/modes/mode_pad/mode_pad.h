/**
* CBC Padding Methods
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_CBC_PADDING_H__
#define BOTAN_CBC_PADDING_H__

#include <botan/types.h>
#include <string>

namespace Botan {

/**
* Block Cipher Mode Padding Method
* This class is pretty limited, it cannot deal well with
* randomized padding methods, or any padding method that
* wants to add more than one block. For instance, it should
* be possible to define cipher text stealing mode as simply
* a padding mode for CBC, which happens to consume the last
* two block (and requires use of the block cipher).
*/
class BOTAN_DLL BlockCipherModePaddingMethod
   {
   public:
      /**
      * @param block output buffer
      * @param size of the block
      * @param current_position in the last block
      */
      virtual void pad(byte block[],
                       u32bit size,
                       u32bit current_position) const = 0;

      /**
      * @param block the last block
      * @param size the of the block
      */
      virtual u32bit unpad(const byte block[],
                           u32bit size) const = 0;

      /**
      * @param block_size of the cipher
      * @param position in the current block
      * @return number of padding bytes that will be appended
      */
      virtual u32bit pad_bytes(u32bit block_size,
                               u32bit position) const;

      /**
      * @param block_size of the cipher
      * @return valid block size for this padding mode
      */
      virtual bool valid_blocksize(u32bit block_size) const = 0;

      /**
      * @return name of the mode
      */
      virtual std::string name() const = 0;

      /**
      * virtual destructor
      */
      virtual ~BlockCipherModePaddingMethod() {}
   };

/**
* PKCS#7 Padding
*/
class BOTAN_DLL PKCS7_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], u32bit, u32bit) const;
      u32bit unpad(const byte[], u32bit) const;
      bool valid_blocksize(u32bit) const;
      std::string name() const { return "PKCS7"; }
   };

/**
* ANSI X9.23 Padding
*/
class BOTAN_DLL ANSI_X923_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], u32bit, u32bit) const;
      u32bit unpad(const byte[], u32bit) const;
      bool valid_blocksize(u32bit) const;
      std::string name() const { return "X9.23"; }
   };

/**
* One And Zeros Padding
*/
class BOTAN_DLL OneAndZeros_Padding : public BlockCipherModePaddingMethod
   {
   public:
      void pad(byte[], u32bit, u32bit) const;
      u32bit unpad(const byte[], u32bit) const;
      bool valid_blocksize(u32bit) const;
      std::string name() const { return "OneAndZeros"; }
   };

/**
* Null Padding
*/
class BOTAN_DLL Null_Padding : public BlockCipherModePaddingMethod
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
