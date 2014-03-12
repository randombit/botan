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

/**
* HMAC
*/
class BOTAN_DLL HMAC : public MessageAuthenticationCode
   {
   public:
      void clear();
      std::string name() const;
      MessageAuthenticationCode* clone() const;

      size_t output_length() const { return hash->output_length(); }

      Key_Length_Specification key_spec() const
         {
         // Absurd max length here is to support PBKDF2
         return Key_Length_Specification(0, 512);
         }

      /**
      * @param hash the hash to use for HMACing
      */
      HMAC(HashFunction* hash);
      ~HMAC() { delete hash; }
   private:
      void add_data(const byte[], size_t);
      void final_result(byte[]);
      void key_schedule(const byte[], size_t);

      HashFunction* hash;
      SecureVector<byte> i_key, o_key;
   };

}

#endif
