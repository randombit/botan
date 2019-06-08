/*
* Filter interface for compression
* (C) 2014,2015,2016 Jack Lloyd
* (C) 2015 Matej Kenda
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>
#include <botan/exceptn.h>

#if defined(BOTAN_HAS_COMPRESSION)
  #include <botan/compression.h>
#endif

namespace Botan {

#if defined(BOTAN_HAS_COMPRESSION)

Compression_Filter::Compression_Filter(const std::string& type, size_t level, size_t bs) :
   m_comp(make_compressor(type)),
   m_buffersize(std::max<size_t>(bs, 256)),
   m_level(level)
   {
   if(!m_comp)
      {
      throw Invalid_Argument("Compression type '" + type + "' not found");
      }
   }

Compression_Filter::~Compression_Filter() { /* for unique_ptr */ }

std::string Compression_Filter::name() const
   {
   return m_comp->name();
   }

void Compression_Filter::start_msg()
   {
   m_comp->start(m_level);
   }

void Compression_Filter::write(const uint8_t input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min(m_buffersize, input_length);
      BOTAN_ASSERT(take > 0, "Consumed something");

      m_buffer.assign(input, input + take);
      m_comp->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Compression_Filter::flush()
   {
   m_buffer.clear();
   m_comp->update(m_buffer, 0, true);
   send(m_buffer);
   }

void Compression_Filter::end_msg()
   {
   m_buffer.clear();
   m_comp->finish(m_buffer);
   send(m_buffer);
   }

Decompression_Filter::Decompression_Filter(const std::string& type, size_t bs) :
   m_comp(make_decompressor(type)),
   m_buffersize(std::max<size_t>(bs, 256))
   {
   if(!m_comp)
      {
      throw Invalid_Argument("Compression type '" + type + "' not found");
      }
   }

Decompression_Filter::~Decompression_Filter() { /* for unique_ptr */ }

std::string Decompression_Filter::name() const
   {
   return m_comp->name();
   }

void Decompression_Filter::start_msg()
   {
   m_comp->start();
   }

void Decompression_Filter::write(const uint8_t input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min(m_buffersize, input_length);
      BOTAN_ASSERT(take > 0, "Consumed something");

      m_buffer.assign(input, input + take);
      m_comp->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Decompression_Filter::end_msg()
   {
   m_buffer.clear();
   m_comp->finish(m_buffer);
   send(m_buffer);
   }

#endif

}
