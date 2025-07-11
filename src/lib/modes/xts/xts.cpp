/*
* XTS Mode
* (C) 2009,2013 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/xts.h>

#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/poly_dbl.h>

namespace Botan {

namespace {

constexpr void swap_bytes_via_xor(std::span<uint8_t> a, std::span<uint8_t> b) {
   BOTAN_DEBUG_ASSERT(a.size() == b.size());

   // TODO: use std::views::zip once we shed some older compilers, like:
   //       for(auto& [front, back] : std::views::zip(a, b))
   for(auto front = a.begin(), back = b.begin(); front != a.end() && back != b.end(); ++front, ++back) {
      *front ^= *back;
      *back ^= *front;
      *front ^= *back;
   }
}

}  // namespace

XTS_Mode::XTS_Mode(std::unique_ptr<BlockCipher> cipher) :
      m_cipher(std::move(cipher)),
      m_cipher_block_size(m_cipher->block_size()),
      m_cipher_parallelism(m_cipher->parallel_bytes()),
      m_tweak_blocks(m_cipher_parallelism / m_cipher_block_size) {
   if(poly_double_supported_size(m_cipher_block_size) == false) {
      throw Invalid_Argument(fmt("Cannot use {} with XTS", m_cipher->name()));
   }

   m_tweak_cipher = m_cipher->new_object();
}

void XTS_Mode::clear() {
   m_cipher->clear();
   m_tweak_cipher->clear();
   reset();
}

size_t XTS_Mode::update_granularity() const {
   return m_cipher_block_size;
}

size_t XTS_Mode::ideal_granularity() const {
   return m_cipher_parallelism;
}

void XTS_Mode::reset() {
   m_tweak.clear();
}

std::string XTS_Mode::name() const {
   return cipher().name() + "/XTS";
}

size_t XTS_Mode::minimum_final_size() const {
   return cipher_block_size();
}

Key_Length_Specification XTS_Mode::key_spec() const {
   return cipher().key_spec().multiple(2);
}

size_t XTS_Mode::output_length(size_t input_length) const {
   return input_length;
}

size_t XTS_Mode::bytes_needed_for_finalization(size_t final_input_length) const {
   BOTAN_ARG_CHECK(final_input_length >= minimum_final_size(), "Sufficient input");
   return final_input_length;
}

size_t XTS_Mode::default_nonce_length() const {
   return cipher_block_size();
}

bool XTS_Mode::valid_nonce_length(size_t n) const {
   return n <= cipher_block_size();
}

bool XTS_Mode::has_keying_material() const {
   return m_cipher->has_keying_material() && m_tweak_cipher->has_keying_material();
}

void XTS_Mode::key_schedule(std::span<const uint8_t> key) {
   const size_t key_half = key.size() / 2;

   if(key.size() % 2 == 1 || !m_cipher->valid_keylength(key_half)) {
      throw Invalid_Key_Length(name(), key.size());
   }

   m_cipher->set_key(key.first(key_half));
   m_tweak_cipher->set_key(key.last(key_half));
}

void XTS_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   m_tweak.resize(m_cipher_parallelism);
   clear_mem(m_tweak.data(), m_tweak.size());
   copy_mem(m_tweak.data(), nonce, nonce_len);
   m_tweak_cipher->encrypt(m_tweak.data());

   update_tweak(0);
}

void XTS_Mode::update_tweak(size_t which) {
   const size_t BS = m_tweak_cipher->block_size();

   if(which > 0) {
      poly_double_n_le(m_tweak.data(), &m_tweak[(which - 1) * BS], BS);
   }

   const size_t blocks_in_tweak = tweak_blocks();

   xts_update_tweak_block(m_tweak.data(), BS, blocks_in_tweak);
}

size_t XTS_Encryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(tweak_set());
   const size_t BS = cipher_block_size();

   BOTAN_ARG_CHECK(sz % BS == 0, "Input is not full blocks");
   size_t blocks = sz / BS;

   const size_t blocks_in_tweak = tweak_blocks();

   while(blocks > 0) {
      const size_t to_proc = std::min(blocks, blocks_in_tweak);
      const size_t proc_bytes = to_proc * BS;

      xor_buf(buf, tweak(), proc_bytes);
      cipher().encrypt_n(buf, buf, to_proc);
      xor_buf(buf, tweak(), proc_bytes);

      buf += proc_bytes;
      blocks -= to_proc;

      update_tweak(to_proc);
   }

   return sz;
}

size_t XTS_Encryption::finish_msg(std::span<uint8_t> buffer, [[maybe_unused]] size_t final_input) {
   BOTAN_ASSERT_NOMSG(buffer.size() >= minimum_final_size());
   BOTAN_DEBUG_ASSERT(buffer.size() == bytes_needed_for_finalization(final_input));

   const size_t BS = cipher_block_size();

   if(buffer.size() % BS == 0) {
      process(buffer);
   } else {
      // steal ciphertext
      const auto full_blocks = buffer.first(((buffer.size() / BS) - 1) * BS);
      const auto tail = buffer.subspan(full_blocks.size());
      BOTAN_ASSERT(tail.size() > BS && tail.size() < 2 * BS, "Left over size in expected range");

      const auto full_tweak = std::span{tweak(), tweak_blocks() * BS};
      const auto first_block_of_tail = tail.first(BS);
      const auto final_bytes_of_tail = tail.subspan(BS);
      const auto first_bytes_of_tail = tail.first(final_bytes_of_tail.size());

      process(full_blocks);

      xor_buf(first_block_of_tail, full_tweak.first(BS));
      cipher().encrypt(first_block_of_tail);
      xor_buf(first_block_of_tail, full_tweak.first(BS));

      swap_bytes_via_xor(first_bytes_of_tail, final_bytes_of_tail);

      xor_buf(first_block_of_tail, full_tweak.subspan(BS, BS));
      cipher().encrypt(first_block_of_tail);
      xor_buf(first_block_of_tail, full_tweak.subspan(BS, BS));
   }

   return buffer.size();
}

size_t XTS_Decryption::process_msg(uint8_t buf[], size_t sz) {
   BOTAN_STATE_CHECK(tweak_set());
   const size_t BS = cipher_block_size();

   BOTAN_ARG_CHECK(sz % BS == 0, "Input is not full blocks");
   size_t blocks = sz / BS;

   const size_t blocks_in_tweak = tweak_blocks();

   while(blocks > 0) {
      const size_t to_proc = std::min(blocks, blocks_in_tweak);
      const size_t proc_bytes = to_proc * BS;

      xor_buf(buf, tweak(), proc_bytes);
      cipher().decrypt_n(buf, buf, to_proc);
      xor_buf(buf, tweak(), proc_bytes);

      buf += proc_bytes;
      blocks -= to_proc;

      update_tweak(to_proc);
   }

   return sz;
}

size_t XTS_Decryption::finish_msg(std::span<uint8_t> buffer, [[maybe_unused]] size_t final_input) {
   BOTAN_ASSERT_NOMSG(buffer.size() >= minimum_final_size());
   BOTAN_DEBUG_ASSERT(buffer.size() == bytes_needed_for_finalization(final_input));

   const size_t BS = cipher_block_size();

   if(buffer.size() % BS == 0) {
      process(buffer);
   } else {
      // steal ciphertext
      const auto full_blocks = buffer.first(((buffer.size() / BS) - 1) * BS);
      const auto tail = buffer.subspan(full_blocks.size());
      BOTAN_ASSERT(tail.size() > BS && tail.size() < 2 * BS, "Left over size in expected range");

      const auto full_tweak = std::span{tweak(), tweak_blocks() * BS};
      const auto first_block_of_tail = tail.first(BS);
      const auto final_bytes_of_tail = tail.subspan(BS);
      const auto first_bytes_of_tail = tail.first(final_bytes_of_tail.size());

      process(full_blocks);

      xor_buf(first_block_of_tail, full_tweak.subspan(BS, BS));
      cipher().decrypt(first_block_of_tail);
      xor_buf(first_block_of_tail, full_tweak.subspan(BS, BS));

      swap_bytes_via_xor(final_bytes_of_tail, first_bytes_of_tail);

      xor_buf(first_block_of_tail, full_tweak.first(BS));
      cipher().decrypt(first_block_of_tail);
      xor_buf(first_block_of_tail, full_tweak.first(BS));
   }

   return buffer.size();
}

}  // namespace Botan
