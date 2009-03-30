/*
* EAX Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAX_H__
#define BOTAN_EAX_H__

#include <botan/basefilt.h>
#include <botan/block_cipher.h>
#include <botan/mac.h>

namespace Botan {

/*
* EAX Base Class
*/
class BOTAN_DLL EAX_Base : public Keyed_Filter
   {
   public:
      void set_key(const SymmetricKey&);
      void set_iv(const InitializationVector&);
      void set_header(const byte[], u32bit);
      std::string name() const;

      bool valid_keylength(u32bit) const;

      ~EAX_Base() { delete cipher; delete mac; }
   protected:
      EAX_Base(BlockCipher*, u32bit);
      void start_msg();
      void increment_counter();

      const u32bit TAG_SIZE, BLOCK_SIZE;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;
      SecureVector<byte> nonce_mac, header_mac, state, buffer;
      u32bit position;
   };

/*
* EAX Encryption
*/
class BOTAN_DLL EAX_Encryption : public EAX_Base
   {
   public:
      EAX_Encryption(BlockCipher* ciph, u32bit tag_size = 0) :
         EAX_Base(ciph, tag_size) {}

      EAX_Encryption(BlockCipher* ciph, const SymmetricKey& key,
                     const InitializationVector& iv,
                     u32bit tag_size) : EAX_Base(ciph, tag_size)
         {
         set_key(key);
         set_iv(iv);
         }
   private:
      void write(const byte[], u32bit);
      void end_msg();
   };

/*
* EAX Decryption
*/
class BOTAN_DLL EAX_Decryption : public EAX_Base
   {
   public:
      EAX_Decryption(BlockCipher* ciph, u32bit tag_size = 0);

      EAX_Decryption(BlockCipher* ciph, const SymmetricKey& key,
                     const InitializationVector& iv,
                     u32bit tag_size = 0);
   private:
      void write(const byte[], u32bit);
      void do_write(const byte[], u32bit);
      void end_msg();
      SecureVector<byte> queue;
      u32bit queue_start, queue_end;
   };

}

#endif
