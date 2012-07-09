/*
* Lzma Compressor
* (C) 2001 Peter J Jones
*     2001-2007 Jack Lloyd
*     2012 Vojtech Kral
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_LZMA_H__
#define BOTAN_LZMA_H__

#include <botan/filter.h>

namespace Botan {

/**
* Lzma Compression Filter
*/
class BOTAN_DLL Lzma_Compression : public Filter
   {
   public:
      std::string name() const { return "Lzma_Compression"; }

      void write(const byte input[], size_t length);
      void start_msg();
      void end_msg();

      /**
      * Flush the compressor
      */
      void flush();

      /**
      * @param level how much effort to use on compressing (0 to 9);
      *        higher levels are slower but tend to give better
      *        compression
      */
      Lzma_Compression(size_t level = 6);

      ~Lzma_Compression() { clear(); }
   private:
      void clear();
      const size_t level;

      secure_vector<byte> buffer;
      class Lzma_Stream* lzma;
   };

/**
* Lzma Decompression Filter
*/
class BOTAN_DLL Lzma_Decompression : public Filter
   {
   public:
      std::string name() const { return "Lzma_Decompression"; }

      void write(const byte input[], size_t length);
      void start_msg();
      void end_msg();

      Lzma_Decompression();
      ~Lzma_Decompression() { clear(); }
   private:
      void clear();

      secure_vector<byte> buffer;
      class Lzma_Stream* lzma;
      bool no_writes;
   };

}

#endif
