/*
* HMAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_HMAC_H__
#define BOTAN_HMAC_H__

#include <botan/mac.h>
#include <botan/hash.h>

namespace Botan {

/*
* HMAC
*/
class BOTAN_DLL HMAC : public MessageAuthenticationCode
   {
   public:
      void clear() throw();
      std::string name() const;
      MessageAuthenticationCode* clone() const;

      HMAC(HashFunction* hash);
      ~HMAC() { delete hash; }
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key_schedule(const byte[], u32bit);
      HashFunction* hash;
      SecureVector<byte> i_key, o_key;
   };

}

#endif
