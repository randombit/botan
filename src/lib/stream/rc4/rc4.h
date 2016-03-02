/*
* RC4
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_RC4_H__
#define BOTAN_RC4_H__

#include <botan/stream_cipher.h>
#include <botan/types.h>

namespace Botan {

/**
* RC4 stream cipher
*/
class BOTAN_DLL RC4 final : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], size_t length) override;

      void clear() override;
      std::string name() const override;

      StreamCipher* clone() const override { return new RC4(m_SKIP); }

      Key_Length_Specification key_spec() const override
         {
         return Key_Length_Specification(1, 256);
         }

      static RC4* make(const Spec& spec);

      /**
      * @param skip skip this many initial bytes in the keystream
      */
      explicit RC4(size_t skip = 0);

      ~RC4() { clear(); }
   private:
      void key_schedule(const byte[], size_t) override;
      void generate();

      const size_t m_SKIP;
      byte m_X = 0;
      byte m_Y = 0;
      secure_vector<byte> m_state;
      secure_vector<byte> m_buffer;
      size_t m_position = 0;
   };

}

#endif
