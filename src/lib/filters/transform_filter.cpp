/*
* Filter interface for Transforms
* (C) 2013,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/transform_filter.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

size_t choose_update_size(size_t update_granularity)
   {
   const size_t target_size = 1024;

   if(update_granularity >= target_size)
      return update_granularity;

   return round_up(target_size, update_granularity);
   }

}

Transform_Filter::Transform_Filter(Transform* transform) :
   Buffered_Filter(choose_update_size(transform->update_granularity()),
                   transform->minimum_final_size()),
   m_nonce(transform->default_nonce_length() == 0),
   m_transform(transform),
   m_buffer(m_transform->update_granularity())
   {
   }

std::string Transform_Filter::name() const
   {
   return m_transform->name();
   }

void Transform_Filter::Nonce_State::update(const InitializationVector& iv)
   {
   m_nonce = unlock(iv.bits_of());
   m_fresh_nonce = true;
   }

std::vector<byte> Transform_Filter::Nonce_State::get()
   {
   BOTAN_ASSERT(m_fresh_nonce, "The nonce is fresh for this message");

   if(!m_nonce.empty())
      m_fresh_nonce = false;
   return m_nonce;
   }

void Transform_Filter::set_iv(const InitializationVector& iv)
   {
   m_nonce.update(iv);
   }

void Transform_Filter::set_key(const SymmetricKey& key)
   {
   if(Keyed_Transform* keyed = dynamic_cast<Keyed_Transform*>(m_transform.get()))
      keyed->set_key(key);
   else if(key.length() != 0)
      throw std::runtime_error("Transform " + name() + " does not accept keys");
   }

Key_Length_Specification Transform_Filter::key_spec() const
   {
   if(Keyed_Transform* keyed = dynamic_cast<Keyed_Transform*>(m_transform.get()))
      return keyed->key_spec();
   return Key_Length_Specification(0);
   }

bool Transform_Filter::valid_iv_length(size_t length) const
   {
   return m_transform->valid_nonce_length(length);
   }

void Transform_Filter::write(const byte input[], size_t input_length)
   {
   Buffered_Filter::write(input, input_length);
   }

void Transform_Filter::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void Transform_Filter::start_msg()
   {
   send(m_transform->start(m_nonce.get()));
   }

void Transform_Filter::buffered_block(const byte input[], size_t input_length)
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

void Transform_Filter::buffered_final(const byte input[], size_t input_length)
   {
   secure_vector<byte> buf(input, input + input_length);
   m_transform->finish(buf);
   send(buf);
   }

}
