/*
* Filter interface for compression
* (C) 2014,2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_COMPRESSION_FILTER_H__
#define BOTAN_COMPRESSION_FILTER_H__

#include <botan/filter.h>

namespace Botan {

class Compression_Algorithm;
class Decompression_Algorithm;

/**
* Filter interface for compression
*/
class BOTAN_DLL Compression_Filter : public Filter
   {
   public:
      void start_msg() override;
      void write(const byte input[], size_t input_length) override;
      void end_msg() override;

      void flush();

      std::string name() const override;

      Compression_Filter(const std::string& type,
                         size_t compression_level,
                         size_t buffer_size = 4096);
   private:
      std::unique_ptr<Compression_Algorithm> m_comp;
      size_t m_buffersize, m_level;
      secure_vector<byte> m_buffer;
   };

/**
* Filter interface for decompression
*/
class BOTAN_DLL Decompression_Filter : public Filter
   {
   public:
      void start_msg() override;
      void write(const byte input[], size_t input_length) override;
      void end_msg() override;

      std::string name() const override;

      Decompression_Filter(const std::string& type,
                           size_t buffer_size = 4096);
   private:
      std::unique_ptr<Decompression_Algorithm> m_comp;
      std::size_t m_buffersize;
      secure_vector<byte> m_buffer;
   };

}

#endif
