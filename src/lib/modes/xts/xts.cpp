/*
* XTS Mode
* (C) 2009,2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/xts.h>
#include <botan/loadstor.h>

namespace Botan {

namespace {

void poly_double_128(byte out[], const byte in[])
   {
   u64bit X0 = load_le<u64bit>(in, 0);
   u64bit X1 = load_le<u64bit>(in, 1);

   const bool carry = static_cast<bool>((X1 >> 63) != 0);

   X1 = (X1 << 1) | (X0 >> 63);
   X0 = (X0 << 1);

   if(carry)
      X0 ^= 0x87;

   store_le(out, X0, X1);
   }

void poly_double_64(byte out[], const byte in[])
   {
   u64bit X = load_le<u64bit>(in, 0);
   const bool carry = static_cast<bool>((X >> 63) != 0);
   X <<= 1;
   if(carry)
      X ^= 0x1B;
   store_le(X, out);
   }

inline void poly_double(byte out[], const byte in[], size_t size)
   {
   if(size == 8)
      poly_double_64(out, in);
   else
      poly_double_128(out, in);
   }

}

XTS_Mode::XTS_Mode(BlockCipher* cipher) : m_cipher(cipher)
   {
   if(m_cipher->block_size() != 8 && m_cipher->block_size() != 16)
      throw Invalid_Argument("Bad cipher for XTS: " + cipher->name());

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
   return cipher().parallel_bytes();
   }

size_t XTS_Mode::minimum_final_size() const
   {
   return cipher().block_size() + 1;
   }

Key_Length_Specification XTS_Mode::key_spec() const
   {
   return cipher().key_spec().multiple(2);
   }

size_t XTS_Mode::default_nonce_length() const
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

   m_cipher->set_key(key, key_half);
   m_tweak_cipher->set_key(&key[key_half], key_half);
   }

void XTS_Mode::start_msg(const byte nonce[], size_t nonce_len)
   {
   if(!valid_nonce_length(nonce_len))
      throw Invalid_IV_Length(name(), nonce_len);

   copy_mem(m_tweak.data(), nonce, nonce_len);
   m_tweak_cipher->encrypt(m_tweak.data());

   update_tweak(0);
   }

void XTS_Mode::update_tweak(size_t which)
   {
   const size_t BS = m_tweak_cipher->block_size();

   if(which > 0)
      poly_double(m_tweak.data(), &m_tweak[(which-1)*BS], BS);

   const size_t blocks_in_tweak = update_granularity() / BS;

   for(size_t i = 1; i < blocks_in_tweak; ++i)
      poly_double(&m_tweak[i*BS], &m_tweak[(i-1)*BS], BS);
   }

size_t XTS_Encryption::output_length(size_t input_length) const
   {
   return input_length;
   }

size_t XTS_Encryption::process(uint8_t buf[], size_t sz)
   {
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

   return sz;
   }

void XTS_Encryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

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

   return sz;
   }

void XTS_Decryption::finish(secure_vector<byte>& buffer, size_t offset)
   {
   BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
   const size_t sz = buffer.size() - offset;
   byte* buf = buffer.data() + offset;

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
