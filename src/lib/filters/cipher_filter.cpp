/*
* Filter interface for Cipher_Modes
* (C) 2013,2014,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>
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

Cipher_Mode_Filter::Cipher_Mode_Filter(Cipher_Mode* mode) :
   Buffered_Filter(choose_update_size(mode->update_granularity()),
                   mode->minimum_final_size()),
   m_mode(mode),
   m_nonce(mode->default_nonce_length()),
   m_buffer(m_mode->update_granularity())
   {
   }

std::string Cipher_Mode_Filter::name() const
   {
   return m_mode->name();
   }

void Cipher_Mode_Filter::set_iv(const InitializationVector& iv)
   {
   m_nonce = unlock(iv.bits_of());
   }

void Cipher_Mode_Filter::set_key(const SymmetricKey& key)
   {
   m_mode->set_key(key);
   }

Key_Length_Specification Cipher_Mode_Filter::key_spec() const
   {
   return m_mode->key_spec();
   }

bool Cipher_Mode_Filter::valid_iv_length(size_t length) const
   {
   return m_mode->valid_nonce_length(length);
   }

void Cipher_Mode_Filter::write(const uint8_t input[], size_t input_length)
   {
   Buffered_Filter::write(input, input_length);
   }

void Cipher_Mode_Filter::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void Cipher_Mode_Filter::start_msg()
   {
   if(m_nonce.empty() && !m_mode->valid_nonce_length(0))
      throw Invalid_State("Cipher " + m_mode->name() + " requires a fresh nonce for each message");

   m_mode->start(m_nonce);
   m_nonce.clear();
   }

void Cipher_Mode_Filter::buffered_block(const uint8_t input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min(m_mode->update_granularity(), input_length);

      m_buffer.assign(input, input + take);
      m_mode->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Cipher_Mode_Filter::buffered_final(const uint8_t input[], size_t input_length)
   {
   secure_vector<uint8_t> buf(input, input + input_length);
   m_mode->finish(buf);
   send(buf);
   }

}
