/*
* XTS Mode
* (C) 2009,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/xts.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

void poly_double(byte tweak[], size_t size)
   {
   // Use u64bits here?
   const byte polynomial = (size == 16) ? 0x87 : 0x1B;

   byte carry = 0;
   for(size_t i = 0; i != size; ++i)
      {
      byte carry2 = (tweak[i] >> 7);
      tweak[i] = (tweak[i] << 1) | carry;
      carry = carry2;
      }

   if(carry)
      tweak[0] ^= polynomial;
   }

}

XTS_Mode::XTS_Mode(BlockCipher* cipher) : m_cipher(cipher)
   {
   if(m_cipher->block_size() != 8 && m_cipher->block_size() != 16)
      throw std::invalid_argument("Bad cipher for XTS: " + cipher->name());

   m_tweak_cipher.reset(m_cipher->clone());
   m_tweak.resize(update_granularity());
   }

void XTS_Mode::clear()
   {
   m_cipher->clear();
   m_tweak_cipher->clear();
   zeroise(m_tweak);
   }

std::string XTS_Mode::name() const
   {
   return cipher().name() + "/XTS";
   }

size_t XTS_Mode::update_granularity() const
   {
   /* XTS needs to process at least 2 blocks in parallel
      because block_size+1 bytes are needed at the end
   */
   return std::max<size_t>(cipher().parallel_bytes(), 2 * cipher().block_size());
   }

size_t XTS_Mode::minimum_final_size() const
   {
   return cipher().block_size() + 1;
   }

Key_Length_Specification XTS_Mode::key_spec() const
   {
   const Key_Length_Specification spec = cipher().key_spec();

   return Key_Length_Specification(2*spec.minimum_keylength(),
                                   2*spec.maximum_keylength(),
                                   2*spec.keylength_multiple());
   }

size_t XTS_Mode::default_nonce_size() const
   {
   return cipher().block_size();
   }

bool XTS_Mode::valid_nonce_length(size_t n) const
   {
   return cipher().block_size() == n;
   }

void XTS_Mode::key_schedule(const byte key[], size_t length)
   {
   const size_t key_half = length / 2;

   if(length % 2 == 1 || !m_cipher->valid_keylength(key_half))
      throw Invalid_Key_Length(name(), length);

   m_cipher->set_key(&key[0], key_half);
   m_tweak_cipher->set_key(&key[key_half], key_half);
   }

secure_vector<byte> XTS_Mode::start(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   const size_t BS = m_tweak_cipher->block_size();
   const size_t blocks_in_tweak = update_granularity() / BS;

   copy_mem(&m_tweak[0], nonce, nonce_len);
   m_tweak_cipher->encrypt(&m_tweak[0]);

   //update_tweak(0);

   for(size_t i = 1; i < blocks_in_tweak; ++i)
      {
      copy_mem(&m_tweak[i*BS], &m_tweak[(i-1)*BS], BS);
      poly_double(&m_tweak[i*BS], BS);
      }

   return secure_vector<byte>();
   }

void XTS_Mode::update_tweak(size_t which)
   {
   const size_t BS = m_tweak_cipher->block_size();

   //if(which > 0)
   copy_mem(&m_tweak[0], &m_tweak[(which-1)*BS], BS);
   poly_double(&m_tweak[0], BS);

   const size_t blocks_in_tweak = update_granularity() / BS;

   for(size_t i = 1; i < blocks_in_tweak; ++i)
      {
      copy_mem(&m_tweak[i*BS], &m_tweak[(i-1)*BS], BS);
      poly_double(&m_tweak[i*BS], BS);
      }
   }

size_t XTS_Encryption::output_length(size_t input_length) const
   {
   return round_up(input_length, cipher().block_size());
   }

void XTS_Encryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   const size_t BS = cipher().block_size();

   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;

   const size_t blocks_in_tweak = update_granularity() / BS;

   while(blocks)
      {
      const size_t to_proc = std::min(blocks, blocks_in_tweak);
      const size_t to_proc_bytes = to_proc * BS;

      xor_buf(buf, tweak(), to_proc_bytes);
      cipher().encrypt_n(buf, buf, to_proc);
      xor_buf(buf, tweak(), to_proc_bytes);

      buf += to_proc * BS;
      blocks -= to_proc;

      update_tweak(to_proc);
      }
   }

void XTS_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   BOTAN_ASSERT(sz >= minimum_final_size(), "Have sufficient final input");

   const size_t BS = cipher().block_size();

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

      secure_vector<byte> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      xor_buf(last, tweak(), BS);
      cipher().encrypt(last);
      xor_buf(last, tweak(), BS);

      for(size_t i = 0; i != final_bytes - BS; ++i)
         std::swap(last[i], last[i + BS]);

      xor_buf(last, tweak() + BS, BS);
      cipher().encrypt(last);
      xor_buf(last, tweak() + BS, BS);

      buffer += last;
      }
   }

size_t XTS_Decryption::output_length(size_t input_length) const
   {
   // might be less
   return input_length;
   }

void XTS_Decryption::update(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   const size_t BS = cipher().block_size();

   BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
   size_t blocks = sz / BS;

   const size_t blocks_in_tweak = update_granularity() / BS;

   while(blocks)
      {
      const size_t to_proc = std::min(blocks, blocks_in_tweak);
      const size_t to_proc_bytes = to_proc * BS;

      xor_buf(buf, tweak(), to_proc_bytes);
      cipher().decrypt_n(buf, buf, to_proc);
      xor_buf(buf, tweak(), to_proc_bytes);

      buf += to_proc * BS;
      blocks -= to_proc;

      update_tweak(to_proc);
      }
   }

void XTS_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = &buffer[offset];

   BOTAN_ASSERT(sz >= minimum_final_size(), "Have sufficient final input");

   const size_t BS = cipher().block_size();

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

      secure_vector<byte> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      xor_buf(last, tweak() + BS, BS);
      cipher().decrypt(last);
      xor_buf(last, tweak() + BS, BS);

      for(size_t i = 0; i != final_bytes - BS; ++i)
         std::swap(last[i], last[i + BS]);

      xor_buf(last, tweak(), BS);
      cipher().decrypt(last);
      xor_buf(last, tweak(), BS);

      buffer += last;
      }
   }

/*
void XTS_Decryption::buffered_final(const byte input[], size_t length)
   {
      size_t leftover_blocks =
         ((length / BS) - 1) * BS;

      buffered_block(input, leftover_blocks);

      input += leftover_blocks;
      length -= leftover_blocks;

      secure_vector<byte> temp(input, input + length);
      secure_vector<byte> tweak_copy(&tweak[0], &tweak[BS]);

      poly_double(&tweak_copy[0], BS);

      xor_buf(temp, tweak_copy, BS);
      cipher->decrypt(temp);
      xor_buf(temp, tweak_copy, BS);

      for(size_t i = 0; i != length - BS; ++i)
         std::swap(temp[i], temp[i + BS]);

      xor_buf(temp, tweak, BS);
      cipher->decrypt(temp);
      xor_buf(temp, tweak, BS);

      send(temp, length);
      }

   buffer_reset();
   }
*/

}
