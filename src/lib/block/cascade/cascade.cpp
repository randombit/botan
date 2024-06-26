/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/cascade.h>

#include <botan/internal/fmt.h>
#include <botan/internal/stl_util.h>
#include <numeric>

namespace Botan {

void Cascade_Cipher::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   size_t c1_blocks = blocks * (block_size() / m_cipher1->block_size());
   size_t c2_blocks = blocks * (block_size() / m_cipher2->block_size());

   m_cipher1->encrypt_n(in, out, c1_blocks);
   m_cipher2->encrypt_n(out, out, c2_blocks);
}

void Cascade_Cipher::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   size_t c1_blocks = blocks * (block_size() / m_cipher1->block_size());
   size_t c2_blocks = blocks * (block_size() / m_cipher2->block_size());

   m_cipher2->decrypt_n(in, out, c2_blocks);
   m_cipher1->decrypt_n(out, out, c1_blocks);
}

void Cascade_Cipher::key_schedule(std::span<const uint8_t> key) {
   BufferSlicer keys(key);

   m_cipher1->set_key(keys.take(m_cipher1->maximum_keylength()));
   m_cipher2->set_key(keys.take(m_cipher2->maximum_keylength()));
}

void Cascade_Cipher::clear() {
   m_cipher1->clear();
   m_cipher2->clear();
}

std::string Cascade_Cipher::name() const {
   return fmt("Cascade({},{})", m_cipher1->name(), m_cipher2->name());
}

bool Cascade_Cipher::has_keying_material() const {
   return m_cipher1->has_keying_material() && m_cipher2->has_keying_material();
}

std::unique_ptr<BlockCipher> Cascade_Cipher::new_object() const {
   return std::make_unique<Cascade_Cipher>(m_cipher1->new_object(), m_cipher2->new_object());
}

Cascade_Cipher::Cascade_Cipher(std::unique_ptr<BlockCipher> cipher1, std::unique_ptr<BlockCipher> cipher2) :
      m_cipher1(std::move(cipher1)),
      m_cipher2(std::move(cipher2)),
      m_block_size(std::lcm(m_cipher1->block_size(), m_cipher2->block_size())) {
   BOTAN_ASSERT(m_block_size % m_cipher1->block_size() == 0 && m_block_size % m_cipher2->block_size() == 0,
                "Combined block size is a multiple of each ciphers block");
}

}  // namespace Botan
