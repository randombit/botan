/*************************************************
* ANSI X9.19 MAC Header File                     *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_ANSI_X919_MAC_H__
#define BOTAN_ANSI_X919_MAC_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* ANSI X9.19 MAC                                 *
*************************************************/
class BOTAN_DLL ANSI_X919_MAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const { return "X9.19-MAC"; }
      MessageAuthenticationCode* clone() const { return new ANSI_X919_MAC; }
      ANSI_X919_MAC();
      ~ANSI_X919_MAC();
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key(const byte[], u32bit);
      BlockCipher* e;
      BlockCipher* d;
      SecureBuffer<byte, 8> state;
      u32bit position;
   };

}

#endif
