/*
* OpenSSL ARC4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eng_ossl.h>
#include <botan/parsing.h>
#include <openssl/rc4.h>

namespace Botan {

namespace {

/**
* ARC4 as implemented by OpenSSL
*/
class ARC4_OpenSSL : public StreamCipher
   {
   public:
      void clear() throw() { std::memset(&state, 0, sizeof(state)); }
      std::string name() const;
      StreamCipher* clone() const { return new ARC4_OpenSSL(SKIP); }

      ARC4_OpenSSL(u32bit s = 0) : StreamCipher(1, 32), SKIP(s) { clear(); }
      ~ARC4_OpenSSL() { clear(); }
   private:
      void cipher(const byte[], byte[], u32bit);
      void key_schedule(const byte[], u32bit);

      const u32bit SKIP;
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
void ARC4_OpenSSL::key_schedule(const byte key[], u32bit length)
   {
   RC4_set_key(&state, length, key);
   byte dummy = 0;
   for(u32bit j = 0; j != SKIP; j++)
      RC4(&state, 1, &dummy, &dummy);
   }

/*
* ARC4 Encryption
*/
void ARC4_OpenSSL::cipher(const byte in[], byte out[], u32bit length)
   {
   RC4(&state, length, in, out);
   }

}

/**
* Look for an OpenSSL-suported stream cipher (ARC4)
*/
StreamCipher*
OpenSSL_Engine::find_stream_cipher(const SCAN_Name& request,
                                   Algorithm_Factory&) const
   {
   if(request.algo_name() == "ARC4")
      return new ARC4_OpenSSL(request.arg_as_u32bit(0, 0));
   if(request.algo_name() == "RC4_drop")
      return new ARC4_OpenSSL(768);

   return 0;
   }

}
