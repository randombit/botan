/*
* CFB Mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/mode_utils.h>
#include <botan/cfb.h>
#include <botan/parsing.h>

namespace Botan {

CFB_Mode::CFB_Mode(BlockCipher* cipher, size_t feedback_bits) :
   m_cipher(cipher),
   m_feedback_bytes(feedback_bits ? feedback_bits / 8 : cipher->block_size())
   {
   if(feedback_bits % 8 || feedback() > cipher->block_size())
      throw Invalid_Argument(name() + ": feedback bits " +
                                  std::to_string(feedback_bits) + " not supported");
   }

void CFB_Mode::clear()
   {
   m_cipher->clear();
   m_shift_register.clear();
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
   return cipher().block_size();
   }

bool CFB_Mode::valid_nonce_length(size_t n) const
   {
   return (n == cipher().block_size());
   }

void CFB_Mode::key_schedule(const byte key[], size_t length)
   {
   m_cipher->set_key(key, length);
   }

void CFB_Mode::start_msg(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_shift_register.assign(nonce, nonce + nonce_len);
   m_keystream_buf.resize(m_shift_register.size());
   cipher().encrypt(m_shift_register, m_keystream_buf);
   }

size_t CFB_Encryption::process(uint8_t buf[], size_t sz)
   {
   const size_t BS = cipher().block_size();

   secure_vector<byte>& state = shift_register();
   const size_t shift = feedback();
   size_t left = sz;

   while(left)
      {
      const size_t took = std::min(shift, left);
      xor_buf(buf, &keystream_buf()[0], took);

      // Assumes feedback-sized block except for last input
      if (BS - shift > 0)
         {
         copy_mem(state.data(), &state[shift], BS - shift);
         }
      copy_mem(&state[BS-shift], buf, took);
      cipher().encrypt(state, keystream_buf());

      buf += took;
      left -= took;
      }
   return sz;
   }

void CFB_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);
   }

size_t CFB_Decryption::process(uint8_t buf[], size_t sz)
   {
   const size_t BS = cipher().block_size();

   secure_vector<byte>& state = shift_register();
   const size_t shift = feedback();
   size_t left = sz;

   while(left)
      {
      const size_t took = std::min(shift, left);

      // first update shift register with ciphertext
      if (BS - shift > 0)
         {
         copy_mem(state.data(), &state[shift], BS - shift);
         }
      copy_mem(&state[BS-shift], buf, took);

      // then decrypt
      xor_buf(buf, &keystream_buf()[0], took);

      // then update keystream
      cipher().encrypt(state, keystream_buf());

      buf += took;
      left -= took;
      }
   return sz;
   }

void CFB_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   update(buffer, offset);
   }

}
