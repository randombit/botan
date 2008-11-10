/**
* OpenSSL's ARC4
*/

#ifndef BOTAN_ARC4_OPENSSL_H__
#define BOTAN_ARC4_OPENSSL_H__

#include <botan/stream_cipher.h>
#include <openssl/rc4.h>

namespace Botan {

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

}

#endif
