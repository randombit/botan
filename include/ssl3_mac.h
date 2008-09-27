/*************************************************
* SSL3-MAC Header File                           *
* (C) 1999-2004 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_SSL3_MAC_H__
#define BOTAN_SSL3_MAC_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* SSL3-MAC                                       *
*************************************************/
class SSL3_MAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const;
      MessageAuthenticationCode* clone() const;
      SSL3_MAC(const std::string&);
      ~SSL3_MAC() { delete hash; }
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key(const byte[], u32bit);
      HashFunction* hash;
      SecureVector<byte> i_key, o_key;
   };

}

#endif
