/*
 * SHAKE-128 and SHAKE-256
 * (C) 2016 Jack Lloyd
 *     2022 René Meusel, Michael Boric - Rohde & Schwarz Cybersecurity
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 */

#include <botan/internal/shake_cipher.h>

#include <botan/exceptn.h>
#include <botan/mem_ops.h>

namespace Botan {

SHAKE_Cipher::SHAKE_Cipher(size_t keccak_capacity) :
      m_keccak(keccak_capacity, 0xF, 4),
      m_has_keying_material(false),
      m_keystream_buffer(buffer_size()),
      m_bytes_generated(0) {}

void SHAKE_Cipher::set_iv_bytes(const uint8_t /*iv*/[], size_t length) {
   /*
   * This could be supported in some way (say, by treating iv as
   * a prefix or suffix of the key).
   */
   if(length != 0) {
      throw Invalid_IV_Length(name(), length);
   }
}

void SHAKE_Cipher::seek(uint64_t /*offset*/) {
   throw Not_Implemented("SHAKE_Cipher::seek");
}

void SHAKE_Cipher::clear() {
   m_keccak.clear();
   m_has_keying_material = false;
   zeroise(m_keystream_buffer);
   m_bytes_generated = 0;
}

void SHAKE_Cipher::cipher_bytes(const uint8_t in[], uint8_t out[], size_t length) {
   assert_key_material_set();

   const auto block_size = m_keystream_buffer.size();

   auto cipher_some = [&](size_t bytes) {
      if(bytes > 0) {
         BOTAN_ASSERT_NOMSG(bytes <= block_size);
         BOTAN_ASSERT_NOMSG(bytes <= length);
         generate_keystream_internal(std::span(m_keystream_buffer).first(bytes));
         xor_buf(out, m_keystream_buffer.data(), in, bytes);
         out += bytes;
         in += bytes;
         length -= bytes;
      }
   };

   // Bring us back into alignment with the XOF's underlying blocks
   if(length > block_size) {
      const auto bytes_to_alignment = block_size - m_bytes_generated % block_size;
      cipher_some(bytes_to_alignment);
   }

   // Consume the XOF's output stream block-wise as long as we can
   while(length >= block_size) {
      cipher_some(block_size);
   }

   // Process remaining data, potentially causing misalignment
   cipher_some(length);
}

void SHAKE_Cipher::generate_keystream(uint8_t out[], size_t length) {
   assert_key_material_set();
   generate_keystream_internal({out, length});
}

void SHAKE_Cipher::generate_keystream_internal(std::span<uint8_t> out) {
   m_keccak.squeeze(out);
   m_bytes_generated += out.size();
}

void SHAKE_Cipher::key_schedule(std::span<const uint8_t> key) {
   clear();
   m_keccak.absorb(key);
   m_keccak.finish();
   m_has_keying_material = true;
}

Key_Length_Specification SHAKE_Cipher::key_spec() const {
   return Key_Length_Specification(1, 160);
}

SHAKE_128_Cipher::SHAKE_128_Cipher() : SHAKE_Cipher(256) {}

SHAKE_256_Cipher::SHAKE_256_Cipher() : SHAKE_Cipher(512) {}

}  // namespace Botan
