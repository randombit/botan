/*************************************************
* CBC-MAC Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_CBC_MAC__
#define BOTAN_CBC_MAC__

#include <botan/base.h>
#include <botan/pointers.h>

namespace Botan {

/*************************************************
* CBC-MAC                                        *
*************************************************/
class CBC_MAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const;
      AutoMACPtr clone() const;      
      CBC_MAC(const std::string&);
      ~CBC_MAC() { };
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key(const byte[], u32bit);

      std::tr1::shared_ptr<BlockCipher> e;
      SecureVector<byte> state;
      u32bit position;
   };

}

#endif
