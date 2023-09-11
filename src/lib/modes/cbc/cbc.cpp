/*
* CBC Mode
* (C) 1999-2007,2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cbc.h>

#include <botan/internal/fmt.h>
#include <botan/internal/mode_pad.h>
#include <botan/internal/rounding.h>

namespace Botan {

CBC_Mode::CBC_Mode(std::unique_ptr<BlockCipher> cipher, std::unique_ptr<BlockCipherModePaddingMethod> padding) :
      m_cipher(std::move(cipher)), m_padding(std::move(padding)), m_block_size(m_cipher->block_size()) {
   if(m_padding && !m_padding->valid_blocksize(m_block_size)) {
      throw Invalid_Argument(fmt("Padding {} cannot be used with {} in CBC mode", m_padding->name(), m_cipher->name()));
   }
}

void CBC_Mode::clear() {
   m_cipher->clear();
   reset();
}

void CBC_Mode::reset() {
   m_state.clear();
}

std::string CBC_Mode::name() const {
   if(m_padding) {
      return fmt("{}/CBC/{}", cipher().name(), padding().name());
   } else {
      return fmt("{}/CBC/CTS", cipher().name());
   }
}

size_t CBC_Mode::update_granularity() const {
   return cipher().block_size();
}

size_t CBC_Mode::ideal_granularity() const {
   return cipher().parallel_bytes();
}

Key_Length_Specification CBC_Mode::key_spec() const {
   return cipher().key_spec();
}

size_t CBC_Mode::default_nonce_length() const {
   return block_size();
}

bool CBC_Mode::valid_nonce_length(size_t n) const {
   return (n == 0 || n == block_size());
}

bool CBC_Mode::has_keying_material() const {
   return m_cipher->has_keying_material();
}

void CBC_Mode::key_schedule(std::span<const uint8_t> key) {
   m_cipher->set_key(key);
   m_state.clear();
}

void CBC_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   /*
   * A nonce of zero length means carry the last ciphertext value over
   * as the new IV, as unfortunately some protocols require this. If
   * this is the first message then we use an IV of all zeros.
   */
   if(nonce_len) {
      m_state.assign(nonce, nonce + nonce_len);
   } else if(m_state.empty()) {
      m_state.resize(m_cipher->block_size());
   }
   // else leave the state alone
}

size_t CBC_Encryption::minimum_final_size() const {
   return 0;
}

size_t CBC_Encryption::output_length(size_t input_length) const {
   if(input_length == 0) {
      return block_size();
   } else {
      return round_up(input_length, block_size());
   }
}

size_t CBC_Encryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(state().empty() == false);
   const size_t BS = block_size();

   BOTAN_ARG_CHECK(sz % BS == 0, "CBC input is not full blocks");
   const size_t blocks = sz / BS;

   if(blocks > 0) {
      xor_buf(&buf[0], state_ptr(), BS);
      cipher().encrypt(&buf[0]);

      for(size_t i = 1; i != blocks; ++i) {
         xor_buf(&buf[BS * i], &buf[BS * (i - 1)], BS);
         cipher().encrypt(&buf[BS * i]);
      }

      state().assign(&buf[BS * (blocks - 1)], &buf[BS * blocks]);
   }

   return sz;
}

void CBC_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_STATE_CHECK(state().empty() == false);
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");

   const size_t BS = block_size();

   const size_t bytes_in_final_block = (buffer.size() - offset) % BS;

   padding().add_padding(buffer, bytes_in_final_block, BS);

   BOTAN_ASSERT_EQUAL(buffer.size() % BS, offset % BS, "Padded to block boundary");

   update(buffer, offset);
}

bool CTS_Encryption::valid_nonce_length(size_t n) const {
   return (n == block_size());
}

size_t CTS_Encryption::minimum_final_size() const {
   return block_size() + 1;
}

size_t CTS_Encryption::output_length(size_t input_length) const {
   return input_length;  // no ciphertext expansion in CTS
}

void CTS_Encryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_STATE_CHECK(state().empty() == false);
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");
   uint8_t* buf = buffer.data() + offset;
   const size_t sz = buffer.size() - offset;

   const size_t BS = block_size();

   if(sz < BS + 1) {
      throw Encoding_Error(name() + ": insufficient data to encrypt");
   }

   if(sz % BS == 0) {
      update(buffer, offset);

      // swap last two blocks
      for(size_t i = 0; i != BS; ++i) {
         std::swap(buffer[buffer.size() - BS + i], buffer[buffer.size() - 2 * BS + i]);
      }
   } else {
      const size_t full_blocks = ((sz / BS) - 1) * BS;
      const size_t final_bytes = sz - full_blocks;
      BOTAN_ASSERT(final_bytes > BS && final_bytes < 2 * BS, "Left over size in expected range");

      secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      xor_buf(last.data(), state_ptr(), BS);
      cipher().encrypt(last.data());

      for(size_t i = 0; i != final_bytes - BS; ++i) {
         last[i] ^= last[i + BS];
         last[i + BS] ^= last[i];
      }

      cipher().encrypt(last.data());

      buffer += last;
   }
}

size_t CBC_Decryption::output_length(size_t input_length) const {
   return input_length;  // precise for CTS, worst case otherwise
}

size_t CBC_Decryption::minimum_final_size() const {
   return block_size();
}

size_t CBC_Decryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(state().empty() == false);

   const size_t BS = block_size();

   BOTAN_ARG_CHECK(sz % BS == 0, "Input is not full blocks");
   size_t blocks = sz / BS;

   while(blocks) {
      const size_t to_proc = std::min(BS * blocks, m_tempbuf.size());

      cipher().decrypt_n(buf, m_tempbuf.data(), to_proc / BS);

      xor_buf(m_tempbuf.data(), state_ptr(), BS);
      xor_buf(&m_tempbuf[BS], buf, to_proc - BS);
      copy_mem(state_ptr(), buf + (to_proc - BS), BS);

      copy_mem(buf, m_tempbuf.data(), to_proc);

      buf += to_proc;
      blocks -= to_proc / BS;
   }

   return sz;
}

void CBC_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_STATE_CHECK(state().empty() == false);
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");
   const size_t sz = buffer.size() - offset;

   const size_t BS = block_size();

   if(sz == 0 || sz % BS) {
      throw Decoding_Error(name() + ": Ciphertext not a multiple of block size");
   }

   update(buffer, offset);

   const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.size() - BS], BS);
   buffer.resize(buffer.size() - pad_bytes);  // remove padding
   if(pad_bytes == 0 && padding().name() != "NoPadding") {
      throw Decoding_Error("Invalid CBC padding");
   }
}

void CBC_Decryption::reset() {
   CBC_Mode::reset();
   zeroise(m_tempbuf);
}

bool CTS_Decryption::valid_nonce_length(size_t n) const {
   return (n == block_size());
}

size_t CTS_Decryption::minimum_final_size() const {
   return block_size() + 1;
}

void CTS_Decryption::finish_msg(secure_vector<uint8_t>& buffer, size_t offset) {
   BOTAN_STATE_CHECK(state().empty() == false);
   BOTAN_ARG_CHECK(buffer.size() >= offset, "Offset is out of range");
   const size_t sz = buffer.size() - offset;
   uint8_t* buf = buffer.data() + offset;

   const size_t BS = block_size();

   if(sz < BS + 1) {
      throw Encoding_Error(name() + ": insufficient data to decrypt");
   }

   if(sz % BS == 0) {
      // swap last two blocks

      for(size_t i = 0; i != BS; ++i) {
         std::swap(buffer[buffer.size() - BS + i], buffer[buffer.size() - 2 * BS + i]);
      }

      update(buffer, offset);
   } else {
      const size_t full_blocks = ((sz / BS) - 1) * BS;
      const size_t final_bytes = sz - full_blocks;
      BOTAN_ASSERT(final_bytes > BS && final_bytes < 2 * BS, "Left over size in expected range");

      secure_vector<uint8_t> last(buf + full_blocks, buf + full_blocks + final_bytes);
      buffer.resize(full_blocks + offset);
      update(buffer, offset);

      cipher().decrypt(last.data());

      xor_buf(last.data(), &last[BS], final_bytes - BS);

      for(size_t i = 0; i != final_bytes - BS; ++i) {
         std::swap(last[i], last[i + BS]);
      }

      cipher().decrypt(last.data());
      xor_buf(last.data(), state_ptr(), BS);

      buffer += last;
   }
}

}  // namespace Botan
