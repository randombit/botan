/*
* CBC Mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cbc.h>
#include <botan/loadstor.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/rounding.h>

namespace Botan {

CBC_Mode::CBC_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
   m_cipher(cipher),
   m_padding(padding),
   m_state(m_cipher->block_size())
   {
   if(!m_padding->valid_blocksize(cipher->block_size()))
      throw std::invalid_argument("Padding " + m_padding->name() +
                                  " cannot be used with " +
                                  cipher->name() + "/CBC");
   }

void CBC_Mode::clear()
   {
   m_cipher->clear();
   m_state.clear();
   }

std::string CBC_Mode::name() const
   {
   return cipher().name() + "/CBC/" + padding().name();
   }

size_t CBC_Mode::update_granularity() const
   {
   return cipher().parallel_bytes();
   }

Key_Length_Specification CBC_Mode::key_spec() const
   {
   return cipher().key_spec();
   }

size_t CBC_Mode::default_nonce_size() const
   {
   return cipher().block_size();
   }

bool CBC_Mode::valid_nonce_length(size_t n) const
   {
   return (n == 0 || n == cipher().block_size());
   }

void CBC_Mode::key_schedule(const byte key[], size_t length)
   {
   m_cipher->set_key(key, length);
   }

secure_vector<byte> CBC_Mode::start(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   /*
   * A nonce of zero length means carry the last ciphertext value over
   * as the new IV, as unfortunately some protocols require this. If
   * this is the first message then we use an IV of all zeros.
   */
   if(nonce_len)
      m_state.assign(nonce, nonce + nonce_len);

   return secure_vector<byte>();
   }

size_t CBC_Encryption::minimum_final_size() const
   {
   return 0;
   }

size_t CBC_Encryption::output_length(size_t input_length) const
   {
   return round_up(input_length, cipher().block_size());
   }

void CBC_Encryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   const size_t BS = cipher().block_size();

   BOTAN_ASSERT(sz % BS == 0, "CBC input is full blocks");
   const size_t blocks = sz / BS;

   if(blocks)
      {
      xor_buf(&buf[0], &state()[0], BS);
      cipher().encrypt(&buf[0]);

      for(size_t i = 1; i != blocks; ++i)
         {
         xor_buf(&buf[BS*i], &buf[BS*(i-1)], BS);
         cipher().encrypt(&buf[BS*i]);
         }

      state().assign(&buf[BS*(blocks-1)], &buf[BS*blocks]);
      }
   }

void CBC_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   //byte* buf = &buffer[offset];

   const size_t BS = cipher().block_size();

   const size_t bytes_in_final_block = sz % BS;

   const size_t pad_bytes = padding().pad_bytes(BS, bytes_in_final_block);

   if((pad_bytes + bytes_in_final_block) % BS)
      throw std::runtime_error("Did not pad to full block size in " + name());

#if 0
   const size_t pad_offset = buffer.size();
   //buffer.resize(checked_add(buffer.size() + pad_bytes));
   buffer.resize(buffer.size() + pad_bytes);

   padder().pad(&buffer[pad_offset], BS, bytes_in_final_block);
#else
   std::vector<byte> pad(BS);
   padding().pad(&pad[0], BS, bytes_in_final_block);

   buffer.insert(buffer.end(), pad.begin(), pad.begin() + pad_bytes);
#endif

   update(buffer, offset);
   }

size_t CBC_Decryption::output_length(size_t input_length) const
   {
   return input_length;
   }

size_t CBC_Decryption::minimum_final_size() const
   {
   return cipher().block_size();
   }

void CBC_Decryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   const size_t BS = cipher().block_size();

   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;

   while(blocks)
      {
      const size_t to_proc = std::min(sz, m_tempbuf.size());

      cipher().decrypt_n(buf, &m_tempbuf[0], to_proc / BS);

      xor_buf(&m_tempbuf[0], state_ptr(), BS);
      xor_buf(&m_tempbuf[BS], buf, to_proc - BS);
      copy_mem(state_ptr(), buf + (to_proc - BS), BS);

      copy_mem(buf, &m_tempbuf[0], to_proc);

      buf += to_proc;
      blocks -= to_proc / BS;
      }
   }

void CBC_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;

   const size_t BS = cipher().block_size();

   if(sz == 0 || sz % BS)
      throw Decoding_Error(name() + ": Ciphertext not a multiple of block size");

   update(buffer, offset);

   const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.size()-BS], BS);
   buffer.resize(buffer.size() - pad_bytes); // remove padding
   }

}
