/*************************************************
* EAX Mode Header File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EAX_H__
#define BOTAN_EAX_H__

#include <botan/basefilt.h>

namespace Botan {

/*************************************************
* EAX Base Class                                 *
*************************************************/
class EAX_Base : public Keyed_Filter
   {
   public:
      void set_key(const SymmetricKey&);
      void set_iv(const InitializationVector&);
      void set_header(const byte[], u32bit);
      std::string name() const;

      bool valid_keylength(u32bit) const;

      ~EAX_Base() { delete cipher; delete mac; }
   protected:
      EAX_Base(const std::string&, u32bit);
      void start_msg();
      void increment_counter();

      const u32bit TAG_SIZE, BLOCK_SIZE;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;
      SecureVector<byte> nonce_mac, header_mac, state, buffer;
      u32bit position;
   };

/*************************************************
* EAX Encryption                                 *
*************************************************/
class EAX_Encryption : public EAX_Base
   {
   public:
      EAX_Encryption(const std::string&, u32bit = 0);
      EAX_Encryption(const std::string&, const SymmetricKey&,
                     const InitializationVector&, u32bit = 0);
   private:
      void write(const byte[], u32bit);
      void end_msg();
   };

/*************************************************
* EAX Decryption                                 *
*************************************************/
class EAX_Decryption : public EAX_Base
   {
   public:
      EAX_Decryption(const std::string&, u32bit = 0);
      EAX_Decryption(const std::string&, const SymmetricKey&,
                     const InitializationVector&, u32bit = 0);
   private:
      void write(const byte[], u32bit);
      void do_write(const byte[], u32bit);
      void end_msg();
      SecureVector<byte> queue;
      u32bit queue_start, queue_end;
   };

}

#endif
