/*************************************************
* CBC Mode Header File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_CBC_H__
#define BOTAN_CBC_H__

#include <botan/modebase.h>
#include <botan/mode_pad.h>

namespace Botan {

/*************************************************
* CBC Encryption                                 *
*************************************************/
class CBC_Encryption : public BlockCipherMode
   {
   public:
      CBC_Encryption(const std::string&, const std::string&);
      CBC_Encryption(const std::string&, const std::string&,
                     const SymmetricKey&, const InitializationVector&);
   private:
      std::string name() const;
      void write(const byte[], u32bit);
      void end_msg();
      const BlockCipherModePaddingMethod* padder;
   };

/*************************************************
* CBC Decryption                                 *
*************************************************/
class CBC_Decryption : public BlockCipherMode
   {
   public:
      CBC_Decryption(const std::string&, const std::string&);
      CBC_Decryption(const std::string&, const std::string&,
                     const SymmetricKey&, const InitializationVector&);
   private:
      std::string name() const;
      void write(const byte[], u32bit);
      void end_msg();
      const BlockCipherModePaddingMethod* padder;
      SecureVector<byte> temp;
   };

}

#endif
