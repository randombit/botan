/*************************************************
* HMAC Header File                               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_HMAC_H__
#define BOTAN_HMAC_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* HMAC                                           *
*************************************************/
class HMAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const;
      MessageAuthenticationCode* clone() const;
      HMAC(const std::string&);
      ~HMAC() { delete hash; }
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key(const byte[], u32bit);
      HashFunction* hash;
      SecureVector<byte> i_key, o_key;
   };

}

#endif
