/*
* Filter interface for compression
* (C) 2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/comp_filter.h>
#include <botan/compression.h>

namespace Botan {

Compression_Filter::Compression_Filter(const std::string& type, size_t level) :
   Compression_Decompression_Filter(make_compressor(type, level))
   {
   }

Decompression_Filter::Decompression_Filter(const std::string& type) :
   Compression_Decompression_Filter(make_decompressor(type))
   {
   }

Compression_Decompression_Filter::Compression_Decompression_Filter(Transform* transform)
   {
   m_transform.reset(dynamic_cast<Compressor_Transform*>(transform));
   if(!m_transform)
      throw std::invalid_argument("Transform " + transform->name() + " is not a compressor");
   }

std::string Compression_Decompression_Filter::name() const
   {
   return m_transform->name();
   }

void Compression_Decompression_Filter::start_msg()
   {
   send(m_transform->start());
   }

void Compression_Decompression_Filter::write(const byte input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min<size_t>({4096, m_buffer.capacity(), input_length});

      m_buffer.assign(input, input + take);
      m_transform->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Compression_Decompression_Filter::flush()
   {
   m_buffer.clear();
   m_transform->flush(m_buffer);
   send(m_buffer);
   }

void Compression_Decompression_Filter::end_msg()
   {
   m_buffer.clear();
   m_transform->finish(m_buffer);
   send(m_buffer);
   }

}
