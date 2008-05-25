/*************************************************
* CMAC Header File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_CMAC_H__
#define BOTAN_CMAC_H__

#include <botan/base.h>
#include <botan/pointers.h>

namespace Botan {

/*************************************************
* CMAC                                           *
*************************************************/
class CMAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const;
      AutoMACPtr clone() const;
      CMAC(const std::string&);
      ~CMAC() {  } 
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key(const byte[], u32bit);

      std::tr1::shared_ptr<BlockCipher> e;
      SecureVector<byte> buffer, state, B, P;
      u32bit position;
      byte polynomial;
   };

}

#endif
