/*
* CFB Mode
* (C) 1999-2007,2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cfb.h>

namespace Botan {

CFB_Mode::CFB_Mode(BlockCipher* cipher, size_t feedback_bits) :
   m_cipher(cipher),
   m_block_size(m_cipher->block_size()),
   m_feedback_bytes(feedback_bits ? feedback_bits / 8 : m_block_size)
   {
   if(feedback_bits % 8 || feedback() > cipher->block_size())
      throw Invalid_Argument(name() + ": feedback bits " +
                                  std::to_string(feedback_bits) + " not supported");
   }

void CFB_Mode::clear()
   {
   m_cipher->clear();
   m_keystream.clear();
   reset();
   }

void CFB_Mode::reset()
   {
   m_state.clear();
   zeroise(m_keystream);
   }

std::string CFB_Mode::name() const
   {
   if(feedback() == cipher().block_size())
      return cipher().name() + "/CFB";
   else
      return cipher().name() + "/CFB(" + std::to_string(feedback()*8) + ")";
   }

size_t CFB_Mode::output_length(size_t input_length) const
   {
   return input_length;
   }

size_t CFB_Mode::update_granularity() const
   {
   return feedback();
   }

size_t CFB_Mode::minimum_final_size() const
   {
   return 0;
   }

Key_Length_Specification CFB_Mode::key_spec() const
   {
   return cipher().key_spec();
   }

size_t CFB_Mode::default_nonce_length() const
   {
   return block_size();
   }

bool CFB_Mode::valid_nonce_length(size_t n) const
   {
   return (n == 0 || n == block_size());
   }

void CFB_Mode::key_schedule(const uint8_t key[], size_t length)
   {
   m_cipher->set_key(key, length);
   m_keystream.resize(m_cipher->block_size());
   }

void CFB_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   verify_key_set(!m_keystream.empty());

   if(nonce_len == 0)
      {
      if(m_state.empty())
         {
         throw Invalid_State("CFB requires a non-empty initial nonce");
         }
      // No reason to encrypt state->keystream_buf, because no change
      }
   else
      {
      m_state.assign(nonce, nonce + nonce_len);
      cipher().encrypt(m_state, m_keystream);
      m_keystream_pos = 0;
      }
   }

void CFB_Mode::shift_register()
   {
   const size_t shift = feedback();
   const size_t carryover = block_size() - shift;

   if(carryover > 0)
      {
      copy_mem(m_state.data(), &m_state[shift], carryover);
      }
   copy_mem(&m_state[carryover], m_keystream.data(), shift);
   cipher().encrypt(m_state, m_keystream);
   m_keystream_pos = 0;
   }

size_t CFB_Encryption::process(uint8_t buf[], size_t sz)
   {
   verify_key_set(!m_keystream.empty());
   BOTAN_STATE_CHECK(m_state.empty() == false);

   const size_t shift = feedback();

   size_t left = sz;

   if(m_keystream_pos != 0)
      {
      const size_t take = std::min<size_t>(left, shift - m_keystream_pos);

      xor_buf(m_keystream.data() + m_keystream_pos, buf, take);
      copy_mem(buf, m_keystream.data() + m_keystream_pos, take);

      m_keystream_pos += take;
      left -= take;
      buf += take;

      if(m_keystream_pos == shift)
         {
         shift_register();
         }
      }

   while(left >= shift)
      {
      xor_buf(m_keystream.data(), buf, shift);
      copy_mem(buf, m_keystream.data(), shift);

      left -= shift;
      buf += shift;
      shift_register();
      }

   if(left > 0)
      {
      xor_buf(m_keystream.data(), buf, left);
      copy_mem(buf, m_keystream.data(), left);
      m_keystream_pos += left;
      }

   return sz;
   }

void CFB_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   update(buffer, offset);
   }

namespace {

inline void xor_copy(uint8_t buf[], uint8_t key_buf[], size_t len)
   {
   for(size_t i = 0; i != len; ++i)
      {
      uint8_t k = key_buf[i];
      key_buf[i] = buf[i];
      buf[i] ^= k;
      }
   }

}

size_t CFB_Decryption::process(uint8_t buf[], size_t sz)
   {
   verify_key_set(!m_keystream.empty());
   BOTAN_STATE_CHECK(m_state.empty() == false);

   const size_t shift = feedback();

   size_t left = sz;

   if(m_keystream_pos != 0)
      {
      const size_t take = std::min<size_t>(left, shift - m_keystream_pos);

      xor_copy(buf, m_keystream.data() + m_keystream_pos, take);

      m_keystream_pos += take;
      left -= take;
      buf += take;

      if(m_keystream_pos == shift)
         {
         shift_register();
         }
      }

   while(left >= shift)
      {
      xor_copy(buf, m_keystream.data(), shift);
      left -= shift;
      buf += shift;
      shift_register();
      }

   if(left > 0)
      {
      xor_copy(buf, m_keystream.data(), left);
      m_keystream_pos += left;
      }

   return sz;
   }

void CFB_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   update(buffer, offset);
   }

}
