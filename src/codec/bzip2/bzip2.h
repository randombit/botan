/*
* Bzip Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_BZIP2_H__
#define BOTAN_BZIP2_H__

#include <botan/filter.h>

namespace Botan {

/*
* Bzip Compression Filter
*/
class BOTAN_DLL Bzip_Compression : public Filter
   {
   public:
      void write(const byte input[], u32bit length);
      void start_msg();
      void end_msg();

      void flush();

      Bzip_Compression(u32bit = 9);
      ~Bzip_Compression() { clear(); }
   private:
      void clear();

      const u32bit level;
      SecureVector<byte> buffer;
      class Bzip_Stream* bz;
   };

/*
* Bzip Decompression Filter
*/
class BOTAN_DLL Bzip_Decompression : public Filter
   {
   public:
      void write(const byte input[], u32bit length);
      void start_msg();
      void end_msg();

      Bzip_Decompression(bool = false);
      ~Bzip_Decompression() { clear(); }
   private:
      void clear();

      const bool small_mem;
      SecureVector<byte> buffer;
      class Bzip_Stream* bz;
      bool no_writes;
   };

}

#endif
