/*
* OpenSSL RC4
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/stream_cipher.h>

#if defined(BOTAN_HAS_OPENSSL) && defined(BOTAN_HAS_RC4)

#include <botan/internal/openssl.h>
#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <openssl/rc4.h>

namespace Botan {

namespace {

class OpenSSL_RC4 final : public StreamCipher
   {
   public:
      void clear() override { clear_mem(&m_rc4, 1); m_key_set = false; }

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
               return "RC4(" + std::to_string(m_skip) + ")";
            }
         }

      StreamCipher* clone() const override { return new OpenSSL_RC4(m_skip); }

      Key_Length_Specification key_spec() const override
         {
         return Key_Length_Specification(1, 32);
         }

      explicit OpenSSL_RC4(size_t skip = 0) : m_skip(skip) { clear(); }
      ~OpenSSL_RC4() { clear(); }

      void set_iv(const uint8_t*, size_t len) override
         {
         if(len > 0)
            throw Invalid_IV_Length("RC4", len);
         }

      void seek(uint64_t) override
         {
         throw Not_Implemented("RC4 does not support seeking");
         }
   private:
      void cipher(const uint8_t in[], uint8_t out[], size_t length) override
         {
         verify_key_set(m_key_set);
         ::RC4(&m_rc4, length, in, out);
         }

      void key_schedule(const uint8_t key[], size_t length) override
         {
         ::RC4_set_key(&m_rc4, length, key);
         uint8_t d = 0;
         for(size_t i = 0; i != m_skip; ++i)
            ::RC4(&m_rc4, 1, &d, &d);
         m_key_set = true;
         }

      size_t m_skip;
      RC4_KEY m_rc4;
      bool m_key_set;
   };

}

std::unique_ptr<StreamCipher>
make_openssl_rc4(size_t skip)
   {
   return std::unique_ptr<StreamCipher>(new OpenSSL_RC4(skip));
   }


}

#endif
