/*
* OpenSSL RC4
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/stream_utils.h>
#include <botan/parsing.h>
#include <openssl/rc4.h>

namespace Botan {

namespace {

class OpenSSL_RC4 : public StreamCipher
   {
   public:
      void clear() { clear_mem(&m_rc4, 1); }

      std::string name() const { return "RC4"; }
      StreamCipher* clone() const { return new OpenSSL_RC4; }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(1, 32);
         }

      OpenSSL_RC4() { clear(); }
      ~OpenSSL_RC4() { clear(); }
   private:
      void cipher(const byte in[], byte out[], size_t length)
         {
         RC4(&m_rc4, length, in, out);
         }

      void key_schedule(const byte key[], size_t length)
         {
         RC4_set_key(&m_rc4, length, key);
         }

      RC4_KEY m_rc4;
   };

}

BOTAN_REGISTER_TYPE(StreamCipher, OpenSSL_RC4, "RC4", make_new_T<OpenSSL_RC4>, "openssl", 64);

}
