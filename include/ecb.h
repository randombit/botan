/*************************************************
* ECB Mode Header File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ECB_H__
#define BOTAN_ECB_H__

#include <botan/modebase.h>
#include <botan/mode_pad.h>

namespace Botan {

/*************************************************
* ECB                                            *
*************************************************/
class ECB : public BlockCipherMode
   {
   protected:
      ECB(const std::string&, const std::string&);
      std::string name() const;
      const BlockCipherModePaddingMethod* padder;
   private:
      bool valid_iv_size(u32bit) const;
   };

/*************************************************
* ECB Encryption                                 *
*************************************************/
class ECB_Encryption : public ECB
   {
   public:
      ECB_Encryption(const std::string&, const std::string&);
      ECB_Encryption(const std::string&, const std::string&,
                     const SymmetricKey&);
   private:
      void write(const byte[], u32bit);
      void end_msg();
   };

/*************************************************
* ECB Decryption                                 *
*************************************************/
class ECB_Decryption : public ECB
   {
   public:
      ECB_Decryption(const std::string&, const std::string&);
      ECB_Decryption(const std::string&, const std::string&,
                     const SymmetricKey&);
   private:
      void write(const byte[], u32bit);
      void end_msg();
   };

}

#endif
