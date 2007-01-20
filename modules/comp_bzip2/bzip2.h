/*************************************************
* Bzip Compressor Header File                    *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_BZIP2_H__
#define BOTAN_EXT_BZIP2_H__

#include <botan/filter.h>

namespace Botan {

/*************************************************
* Bzip Compression Filter                        *
*************************************************/
class Bzip_Compression : public Filter
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

/*************************************************
* Bzip Decompression Filter                      *
*************************************************/
class Bzip_Decompression : public Filter
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
