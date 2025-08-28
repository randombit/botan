/*
* CBC Mode
* (C) 1999-2007,2013,2017 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cbc.h>

#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/mode_pad.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace {

constexpr void swap_bytes(std::span<uint8_t> a, std::span<uint8_t> b) {
   BOTAN_DEBUG_ASSERT(a.size() == b.size());
   for(size_t i = 0; i != a.size(); ++i) {
      std::swap(a[i], b[i]);
   }
}

}  // namespace

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
   if(nonce_len > 0) {
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
   return padding().output_length(input_length, block_size());
}

size_t CBC_Encryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(!state().empty());
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

size_t CBC_Encryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   BOTAN_STATE_CHECK(!state().empty());
   BOTAN_DEBUG_ASSERT(buffer.size() == bytes_needed_for_finalization(input_bytes));

   const size_t BS = block_size();

   const size_t bytes_in_final_block = input_bytes % BS;
   padding().add_padding(buffer, bytes_in_final_block, BS);
   process(buffer);

   return buffer.size();
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

size_t CTS_Encryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   BOTAN_STATE_CHECK(!state().empty());
   BOTAN_ASSERT_NOMSG(buffer.size() == input_bytes);

   const size_t BS = block_size();

   if(input_bytes < BS + 1) {
      throw Encoding_Error(Botan::fmt("{}: insufficient data to encrypt", name()));
   }

   if(input_bytes % BS == 0) {
      process(buffer);
      const auto last_block = buffer.last(BS);
      const auto second_last_block = buffer.last(BS * 2).first(BS);
      swap_bytes(last_block, second_last_block);
   } else {
      const size_t full_blocks = ((buffer.size() / BS) - 1) * BS;
      const auto tail = buffer.subspan(full_blocks);
      BOTAN_ASSERT(tail.size() > BS && tail.size() < 2 * BS, "Left over size in expected range");

      const auto final_ordinary_blocks = buffer.first(full_blocks);
      const auto first_block_of_tail = tail.first(BS);
      const auto final_bytes_of_tail = tail.subspan(BS);
      const auto first_bytes_of_tail = tail.first(final_bytes_of_tail.size());

      process(final_ordinary_blocks);
      xor_buf(first_block_of_tail, state());
      cipher().encrypt(first_block_of_tail);
      swap_bytes(first_bytes_of_tail, final_bytes_of_tail);
      xor_buf(first_bytes_of_tail, final_bytes_of_tail);
      cipher().encrypt(first_block_of_tail);
   }

   return buffer.size();
}

size_t CBC_Decryption::output_length(size_t input_length) const {
   return input_length;  // precise for CTS, worst case otherwise
}

size_t CBC_Decryption::minimum_final_size() const {
   return block_size();
}

size_t CBC_Decryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(!state().empty());

   const size_t BS = block_size();

   BOTAN_ARG_CHECK(sz % BS == 0, "Input is not full blocks");
   size_t blocks = sz / BS;

   while(blocks > 0) {
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

size_t CBC_Decryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   BOTAN_STATE_CHECK(!state().empty());
   BOTAN_ASSERT_NOMSG(buffer.size() == input_bytes);

   const size_t BS = block_size();

   if(buffer.empty() || buffer.size() % BS != 0) {
      throw Decoding_Error(Botan::fmt("{}: Ciphertext not a multiple of block size", name()));
   }

   process(buffer);

   const size_t pad_bytes = BS - padding().unpad(std::span{buffer}.last(BS));
   if(pad_bytes == 0 && padding().name() != "NoPadding") {
      throw Decoding_Error("Invalid CBC padding");
   }

   return buffer.size() - pad_bytes;
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

size_t CTS_Decryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   BOTAN_STATE_CHECK(!state().empty());
   BOTAN_ASSERT_NOMSG(buffer.size() == input_bytes);

   const size_t BS = block_size();

   if(buffer.size() < BS + 1) {
      throw Encoding_Error(Botan::fmt("{}: insufficient data to decrypt", name()));
   }

   if(buffer.size() % BS == 0) {
      const auto last_block = buffer.last(BS);
      const auto second_last_block = buffer.last(BS * 2).first(BS);
      swap_bytes(last_block, second_last_block);
      process(buffer);
   } else {
      const size_t full_blocks = ((buffer.size() / BS) - 1) * BS;
      const auto tail = buffer.subspan(full_blocks);
      BOTAN_ASSERT(tail.size() > BS && tail.size() < 2 * BS, "Left over size in expected range");

      const auto final_ordinary_blocks = buffer.first(full_blocks);
      const auto first_block_of_tail = tail.first(BS);
      const auto final_bytes_of_tail = tail.subspan(BS);
      const auto first_bytes_of_tail = tail.first(final_bytes_of_tail.size());

      process(final_ordinary_blocks);
      cipher().decrypt(first_block_of_tail);
      xor_buf(first_bytes_of_tail, final_bytes_of_tail);
      swap_bytes(first_bytes_of_tail, final_bytes_of_tail);
      cipher().decrypt(first_block_of_tail);
      xor_buf(first_block_of_tail, state());
   }

   return buffer.size();
}

}  // namespace Botan
