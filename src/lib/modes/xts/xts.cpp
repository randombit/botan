/*
* XTS Mode
* (C) 2009,2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/xts.h>
#include <botan/internal/poly_dbl.h>

namespace Botan {

XTS_Mode::XTS_Mode(BlockCipher* cipher) :
   m_cipher(cipher),
   m_cipher_block_size(m_cipher->block_size()),
   m_cipher_parallelism(m_cipher->parallel_bytes())
   {
   if(poly_double_supported_size(m_cipher_block_size) == false)
      {
      throw Invalid_Argument("Cannot use " + cipher->name() + " with XTS");
      }

   m_tweak_cipher.reset(m_cipher->clone());
   }

void XTS_Mode::clear()
   {
   m_cipher->clear();
   m_tweak_cipher->clear();
   reset();
   }

void XTS_Mode::reset()
   {
   m_tweak.clear();
   }

std::string XTS_Mode::name() const
   {
   return cipher().name() + "/XTS";
   }

size_t XTS_Mode::minimum_final_size() const
   {
   return cipher_block_size();
   }

Key_Length_Specification XTS_Mode::key_spec() const
   {
   return cipher().key_spec().multiple(2);
   }

size_t XTS_Mode::default_nonce_length() const
   {
   return cipher_block_size();
   }

bool XTS_Mode::valid_nonce_length(size_t n) const
   {
   return cipher_block_size() == n;
   }

void XTS_Mode::key_schedule(const uint8_t key[], size_t length)
   {
   const size_t key_half = length / 2;

   if(length % 2 == 1 || !m_cipher->valid_keylength(key_half))
      throw Invalid_Key_Length(name(), length);

   m_cipher->set_key(key, key_half);
   m_tweak_cipher->set_key(&key[key_half], key_half);
   }

void XTS_Mode::start_msg(const uint8_t nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   m_tweak.resize(update_granularity());
   copy_mem(m_tweak.data(), nonce, nonce_len);
   m_tweak_cipher->encrypt(m_tweak.data());

   update_tweak(0);
   }

void XTS_Mode::update_tweak(size_t which)
   {
   const size_t BS = m_tweak_cipher->block_size();

   if(which > 0)
      poly_double_n_le(m_tweak.data(), &m_tweak[(which-1)*BS], BS);

   const size_t blocks_in_tweak = update_granularity() / BS;

   for(size_t i = 1; i < blocks_in_tweak; ++i)
      poly_double_n_le(&m_tweak[i*BS], &m_tweak[(i-1)*BS], BS);
   }

size_t XTS_Encryption::output_length(size_t input_length) const
   {
   return input_length;
   }

size_t XTS_Encryption::process(uint8_t buf[], size_t sz)
   {
   BOTAN_STATE_CHECK(tweak_set());
   const size_t BS = cipher_block_size();

   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;

   const size_t blocks_in_tweak = update_granularity() / BS;

   while(blocks)
      {
      const size_t to_proc = std::min(blocks, blocks_in_tweak);

      cipher().encrypt_n_xex(buf, tweak(), to_proc);

      buf += to_proc * BS;
      blocks -= to_proc;

      update_tweak(to_proc);
      }

   return sz;
   }

void XTS_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ASSERT(sz >= minimum_final_size(), "Have sufficient final input in XTS encrypt");

   const size_t BS = cipher_block_size();

   if(sz % BS == 0)
      {
      update(buffer, offset);
      }
   else
      {
      // steal ciphertext
      const size_t full_blocks = ((sz / BS) - 1) * BS;
      const size_t final_bytes = sz - full_blocks;
      BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");

      secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      xor_buf(last, tweak(), BS);
      cipher().encrypt(last);
      xor_buf(last, tweak(), BS);

      for(size_t i = 0; i != final_bytes - BS; ++i)
         {
         last[i] ^= last[i + BS];
         last[i + BS] ^= last[i];
         last[i] ^= last[i + BS];
         }

      xor_buf(last, tweak() + BS, BS);
      cipher().encrypt(last);
      xor_buf(last, tweak() + BS, BS);

      buffer += last;
      }
   }

size_t XTS_Decryption::output_length(size_t input_length) const
   {
   return input_length;
   }

size_t XTS_Decryption::process(uint8_t buf[], size_t sz)
   {
   BOTAN_STATE_CHECK(tweak_set());
   const size_t BS = cipher_block_size();

   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;

   const size_t blocks_in_tweak = update_granularity() / BS;

   while(blocks)
      {
      const size_t to_proc = std::min(blocks, blocks_in_tweak);

      cipher().decrypt_n_xex(buf, tweak(), to_proc);

      buf += to_proc * BS;
      blocks -= to_proc;

      update_tweak(to_proc);
      }

   return sz;
   }

void XTS_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   BOTAN_ASSERT(sz >= minimum_final_size(), "Have sufficient final input in XTS decrypt");

   const size_t BS = cipher_block_size();

   if(sz % BS == 0)
      {
      update(buffer, offset);
      }
   else
      {
      // steal ciphertext
      const size_t full_blocks = ((sz / BS) - 1) * BS;
      const size_t final_bytes = sz - full_blocks;
      BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");

      secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      xor_buf(last, tweak() + BS, BS);
      cipher().decrypt(last);
      xor_buf(last, tweak() + BS, BS);

      for(size_t i = 0; i != final_bytes - BS; ++i)
         {
         last[i] ^= last[i + BS];
         last[i + BS] ^= last[i];
         last[i] ^= last[i + BS];
         }

      xor_buf(last, tweak(), BS);
      cipher().decrypt(last);
      xor_buf(last, tweak(), BS);

      buffer += last;
      }
   }

}
