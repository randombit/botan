/*
* Filter interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/aead_filt.h>

namespace Botan {

AEAD_Filter::AEAD_Filter(AEAD_Mode* aead) :
   Buffered_Filter(aead->update_granularity(),
                   aead->minimum_final_size()),
   m_aead(aead)
   {
   }

std::string AEAD_Filter::name() const
   {
   return m_aead->name();
   }

void AEAD_Filter::Nonce_State::update(const InitializationVector& iv)
   {
   m_nonce = unlock(iv.bits_of());
   m_fresh_nonce = true;
   }

std::vector<byte> AEAD_Filter::Nonce_State::get()
   {
   BOTAN_ASSERT(m_fresh_nonce, "The nonce is fresh for this message");

   m_fresh_nonce = false;
   return m_nonce;
   }

void AEAD_Filter::set_associated_data(const byte ad[], size_t ad_len)
   {
   m_aead->set_associated_data(ad, ad_len);
   }

void AEAD_Filter::set_iv(const InitializationVector& iv)
   {
   m_nonce.update(iv);
   }

void AEAD_Filter::set_key(const SymmetricKey& key)
   {
   m_aead->set_key(key);
   }

Key_Length_Specification AEAD_Filter::key_spec() const
   {
   return m_aead->key_spec();
   }

bool AEAD_Filter::valid_iv_length(size_t length) const
   {
   return m_aead->valid_nonce_length(length);
   }

void AEAD_Filter::write(const byte input[], size_t input_length)
   {
   Buffered_Filter::write(input, input_length);
   }

void AEAD_Filter::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void AEAD_Filter::start_msg()
   {
   send(m_aead->start_vec(m_nonce.get()));
   }

void AEAD_Filter::buffered_block(const byte input[], size_t input_length)
   {
   secure_vector<byte> buf;

   while(input_length)
      {
      const size_t take = std::min(m_aead->update_granularity(), input_length);

      buf.resize(take);
      copy_mem(&buf[0], input, take);

      m_aead->update(buf);

      send(buf);

      input += take;
      input_length -= take;
      }
   }

void AEAD_Filter::buffered_final(const byte input[], size_t input_length)
   {
   secure_vector<byte> buf(input, input + input_length);
   m_aead->finish(buf);
   send(buf);
   }

}
