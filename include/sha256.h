/*************************************************
* SHA-256 Header File                            *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_SHA_256_H__
#define BOTAN_SHA_256_H__

#include <botan/mdx_hash.h>

namespace Botan {


/*************************************************
* SHA-{224,256} Base                             *
*************************************************/
class SHA_224256_BASE : public MDx_HashFunction
   {
   protected:
      void clear() throw();
      SHA_224256_BASE(u32bit out) : MDx_HashFunction(out, 64, true, true) { clear(); }
      SecureBuffer<u32bit, 64> W;
      SecureBuffer<u32bit, 8> digest;
   private:
      void hash(const byte[]);
      void copy_out(byte[]);
   };

/*************************************************
* SHA-256                                        *
*************************************************/
class SHA_256 : public SHA_224256_BASE
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-256"; }
      AutoHashFunctionPtr clone() const { return AutoHashFunctionPtr(new SHA_256); }
      SHA_256() : SHA_224256_BASE(32) { clear ();}
   };


/*************************************************
* SHA-224                                        *
*************************************************/
class SHA_224 : public SHA_224256_BASE
   {
   public:
      void clear() throw();
      std::string name() const { return "SHA-224"; }
      AutoHashFunctionPtr clone() const { return AutoHashFunctionPtr(new SHA_224); }
      SHA_224() : SHA_224256_BASE(28) { clear();}
   };
}


#endif
