/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eme.h>

namespace Botan {

/*
* Encode a message
*/
secure_vector<byte> EME::encode(const byte msg[], size_t msg_len,
                               size_t key_bits,
                               RandomNumberGenerator& rng) const
   {
   return pad(msg, msg_len, key_bits, rng);
   }

/*
* Encode a message
*/
secure_vector<byte> EME::encode(const secure_vector<byte>& msg,
                               size_t key_bits,
                               RandomNumberGenerator& rng) const
   {
   return pad(msg.data(), msg.size(), key_bits, rng);
   }

/*
* Decode a message
*/
secure_vector<byte> EME::decode(const byte msg[], size_t msg_len,
                               size_t key_bits) const
   {
   return unpad(msg, msg_len, key_bits);
   }

/*
* Decode a message
*/
secure_vector<byte> EME::decode(const secure_vector<byte>& msg,
                               size_t key_bits) const
   {
   return unpad(msg.data(), msg.size(), key_bits);
   }

}
