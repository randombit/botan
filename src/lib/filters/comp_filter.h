/*
* Filter interface for compression
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_COMPRESSION_FILTER_H__
#define BOTAN_COMPRESSION_FILTER_H__

#include <botan/filter.h>
#include <botan/compression.h>

namespace Botan {

/**
* Filter interface for compression/decompression
*/
class BOTAN_DLL Compression_Decompression_Filter : public Filter
   {
   public:
      void start_msg() override;
      void write(const byte input[], size_t input_length) override;
      void end_msg() override;

      std::string name() const override;

   protected:
      Compression_Decompression_Filter(Compressor_Transformation* t);

      void flush();
   private:
      std::unique_ptr<Compressor_Transformation> m_transform;
      secure_vector<byte> m_buffer;
   };

class BOTAN_DLL Compression_Filter : public Compression_Decompression_Filter
   {
   public:
      Compression_Filter(const std::string& type, size_t level); // compression

      using Compression_Decompression_Filter::flush;
   };

class Decompression_Filter : public Compression_Decompression_Filter
   {
   public:
      Decompression_Filter(const std::string& type);
   };

}

#endif
