/*
* Filter interface for Transformations
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/transform_filter.h>

namespace Botan {

Transformation_Filter::Transformation_Filter(Transformation* transform) :
   Buffered_Filter(transform->update_granularity(),
                   transform->minimum_final_size()),
   m_nonce(transform->default_nonce_length() == 0),
   m_transform(transform),
   m_buffer(m_transform->update_granularity())
   {
   }

std::string Transformation_Filter::name() const
   {
   return "";
   //return m_transform->name();
   }

void Transformation_Filter::Nonce_State::update(const InitializationVector& iv)
   {
   m_nonce = unlock(iv.bits_of());
   m_fresh_nonce = true;
   }

std::vector<byte> Transformation_Filter::Nonce_State::get()
   {
   BOTAN_ASSERT(m_fresh_nonce, "The nonce is fresh for this message");

   if(!m_nonce.empty())
      m_fresh_nonce = false;
   return m_nonce;
   }

void Transformation_Filter::set_iv(const InitializationVector& iv)
   {
   m_nonce.update(iv);
   }

void Transformation_Filter::set_key(const SymmetricKey& key)
   {
   m_transform->set_key(key);
   }

Key_Length_Specification Transformation_Filter::key_spec() const
   {
   return m_transform->key_spec();
   }

bool Transformation_Filter::valid_iv_length(size_t length) const
   {
   return m_transform->valid_nonce_length(length);
   }

void Transformation_Filter::write(const byte input[], size_t input_length)
   {
   Buffered_Filter::write(input, input_length);
   }

void Transformation_Filter::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void Transformation_Filter::start_msg()
   {
   send(m_transform->start_vec(m_nonce.get()));
   }

void Transformation_Filter::buffered_block(const byte input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min(m_transform->update_granularity(), input_length);

      m_buffer.assign(input, input + take);
      m_transform->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Transformation_Filter::buffered_final(const byte input[], size_t input_length)
   {
   secure_vector<byte> buf(input, input + input_length);
   m_transform->finish(buf);
   send(buf);
   }

}
