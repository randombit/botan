/*
* SSL3-MAC
* (C) 1999-2004 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SSL3_MAC_H__
#define BOTAN_SSL3_MAC_H__

#include <botan/hash.h>
#include <botan/mac.h>

namespace Botan {

/**
* A MAC only used in SSLv3. Do not use elsewhere! Use HMAC instead.
*/
class BOTAN_DLL SSL3_MAC : public MessageAuthenticationCode
   {
   public:
      void clear();
      std::string name() const;
      MessageAuthenticationCode* clone() const;

      /**
      * @param hash the underlying hash to use
      */
      SSL3_MAC(HashFunction* hash);
      ~SSL3_MAC() { delete hash; }
   private:
      void add_data(const byte[], u32bit);
      void final_result(byte[]);
      void key_schedule(const byte[], u32bit);

      HashFunction* hash;
      SecureVector<byte> i_key, o_key;
   };

}

#endif
