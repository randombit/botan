/*
* OpenSSL RC4
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stream_cipher.h>

#if defined(BOTAN_HAS_OPENSSL)

#include <botan/internal/algo_registry.h>
#include <botan/internal/openssl.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <openssl/rc4.h>

namespace Botan {

namespace {

class OpenSSL_RC4 : public StreamCipher
   {
   public:
      void clear() override { clear_mem(&m_rc4, 1); }

      std::string provider() const override { return "openssl"; }

      std::string name() const override
         {
         switch(m_skip)
            {
            case 0:
               return "RC4";
            case 256:
               return "MARK-4";
            default:
               return "RC4_skip(" + std::to_string(m_skip) + ")";
            }
         }

      StreamCipher* clone() const override { return new OpenSSL_RC4; }

      Key_Length_Specification key_spec() const override
         {
         return Key_Length_Specification(1, 32);
         }

      explicit OpenSSL_RC4(size_t skip = 0) : m_skip(skip) { clear(); }
      ~OpenSSL_RC4() { clear(); }

      void set_iv(const byte*, size_t) override
         {
         throw Exception("RC4 does not support an IV");
         }

      void seek(u64bit) override
         {
         throw Exception("RC4 does not support seeking");
         }
   private:
      void cipher(const byte in[], byte out[], size_t length) override
         {
         ::RC4(&m_rc4, length, in, out);
         }

      void key_schedule(const byte key[], size_t length) override
         {
         ::RC4_set_key(&m_rc4, length, key);
         byte d = 0;
         for(size_t i = 0; i != m_skip; ++i)
            ::RC4(&m_rc4, 1, &d, &d);
         }

      size_t m_skip;
      RC4_KEY m_rc4;
   };

}

BOTAN_REGISTER_TYPE(StreamCipher, OpenSSL_RC4, "RC4", (make_new_T_1len<OpenSSL_RC4,0>),
                    "openssl", BOTAN_OPENSSL_RC4_PRIO);

}

#endif
