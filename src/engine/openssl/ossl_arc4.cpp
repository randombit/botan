/*
* OpenSSL ARC4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/internal/openssl_engine.h>
#include <botan/parsing.h>
#include <openssl/opensslconf.h>
#if !defined(OPENSSL_NO_RC4)
#include <openssl/rc4.h>
#endif

namespace Botan {

#if !defined(OPENSSL_NO_RC4)
namespace {

/**
* ARC4 as implemented by OpenSSL
*/
class ARC4_OpenSSL : public StreamCipher
   {
   public:
      void clear() { std::memset(&state, 0, sizeof(state)); }
      std::string name() const;
      StreamCipher* clone() const { return new ARC4_OpenSSL(SKIP); }

      Key_Length_Specification key_spec() const
         {
         return Key_Length_Specification(1, 32);
         }


      ARC4_OpenSSL(size_t s = 0) : SKIP(s) { clear(); }
      ~ARC4_OpenSSL() { clear(); }
   private:
      void cipher(const byte[], byte[], size_t);
      void key_schedule(const byte[], size_t);

      const size_t SKIP;
      RC4_KEY state;
   };

/*
* Return the name of this type
*/
std::string ARC4_OpenSSL::name() const
   {
   if(SKIP == 0)   return "ARC4";
   if(SKIP == 256) return "MARK-4";
   else            return "RC4_skip(" + to_string(SKIP) + ")";
   }

/*
* ARC4 Key Schedule
*/
void ARC4_OpenSSL::key_schedule(const byte key[], size_t length)
   {
   RC4_set_key(&state, length, key);
   byte dummy = 0;
   for(size_t i = 0; i != SKIP; ++i)
      RC4(&state, 1, &dummy, &dummy);
   }

/*
* ARC4 Encryption
*/
void ARC4_OpenSSL::cipher(const byte in[], byte out[], size_t length)
   {
   RC4(&state, length, in, out);
   }

}
#endif

/**
* Look for an OpenSSL-supported stream cipher (ARC4)
*/
StreamCipher*
OpenSSL_Engine::find_stream_cipher(const SCAN_Name& request,
                                   Algorithm_Factory&) const
   {
#if !defined(OPENSSL_NO_RC4)
   if(request.algo_name() == "ARC4")
      return new ARC4_OpenSSL(request.arg_as_integer(0, 0));
   if(request.algo_name() == "RC4_drop")
      return new ARC4_OpenSSL(768);
#endif

   return 0;
   }

}
