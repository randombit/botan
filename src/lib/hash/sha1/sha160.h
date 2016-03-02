/*
* SHA-160
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_SHA_160_H__
#define BOTAN_SHA_160_H__

#include <botan/mdx_hash.h>

namespace Botan {

/**
* NIST's SHA-160
*/
class BOTAN_DLL SHA_160 : public MDx_HashFunction
   {
   public:
      std::string name() const override { return "SHA-160"; }
      size_t output_length() const override { return 20; }
      HashFunction* clone() const override { return new SHA_160; }

      void clear() override;

      SHA_160() : MDx_HashFunction(64, true, true), m_digest(5), m_W(80)
         {
         clear();
         }
   protected:
      /**
      * Set a custom size for the W array. Normally 80, but some
      * subclasses need slightly more for best performance/internal
      * constraints
      * @param W_size how big to make W
      */
      explicit SHA_160(size_t W_size) :
         MDx_HashFunction(64, true, true), m_digest(5), m_W(W_size)
         {
         clear();
         }

      void compress_n(const byte[], size_t blocks) override;
      void copy_out(byte[]) override;

      /**
      * The digest value, exposed for use by subclasses (asm, SSE2)
      */
      secure_vector<u32bit> m_digest;

      /**
      * The message buffer, exposed for use by subclasses (asm, SSE2)
      */
      secure_vector<u32bit> m_W;
   };

}

#endif
