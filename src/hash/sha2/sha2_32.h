/*************************************************
* SHA-{224,256} Header File                      *
* (C) 1999-2008 Jack Lloyd                       *
*     2007 FlexSecure GmbH                       *
*************************************************/

#ifndef BOTAN_SHA_256_H__
#define BOTAN_SHA_256_H__

#include <botan/mdx_hash.h>

namespace Botan {

/*************************************************
* SHA-{224,256} Base                             *
*************************************************/
class BOTAN_DLL SHA_224256_BASE : public MDx_HashFunction
   {
   protected:
      void clear() throw();
      SHA_224256_BASE(u32bit out) :
         MDx_HashFunction(out, 64, true, true) { clear(); }

      SecureBuffer<u32bit, 64> W;
      SecureBuffer<u32bit, 8> digest;
   private:
      void hash(const byte[]);
      void copy_out(byte[]);
   };

/*************************************************
* SHA-224                                        *
*************************************************/
class BOTAN_DLL SHA_224 : public SHA_224256_BASE
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-224"; }
      HashFunction* clone() const { return new SHA_224; }
      SHA_224() : SHA_224256_BASE(28) { clear(); }
   };

/*************************************************
* SHA-256                                        *
*************************************************/
class BOTAN_DLL SHA_256 : public SHA_224256_BASE
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-256"; }
      HashFunction* clone() const { return new SHA_256; }
      SHA_256() : SHA_224256_BASE(32) { clear (); }
   };

}

#endif
