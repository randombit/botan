/*
* Lion
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/lion.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>

namespace Botan {

/*
* Lion Encryption
*/
void Lion::encrypt_blocks(std::span<const uint8_t> in, std::span<uint8_t> out, size_t blocks) const {
   assert_key_material_set();

   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<uint8_t> buffer(LEFT_SIZE);

   for(size_t i = 0; i != blocks; ++i) {
      const auto in_left = in.first(LEFT_SIZE);
      const auto in_right = in.subspan(LEFT_SIZE, RIGHT_SIZE);
      const auto out_left = out.first(LEFT_SIZE);
      const auto out_right = out.subspan(LEFT_SIZE, RIGHT_SIZE);

      xor_buf(buffer, in_left, m_key1);
      m_cipher->set_key(buffer);
      m_cipher->cipher(in_right, out_right);

      m_hash->update(out_right);
      m_hash->final(buffer);
      xor_buf(out_left, in_left, buffer);

      xor_buf(buffer, out_left, m_key2);
      m_cipher->set_key(buffer);
      m_cipher->cipher1(out_right);

      in = in.subspan(m_block_size);
      out = out.subspan(m_block_size);
   }
}

/*
* Lion Decryption
*/
void Lion::decrypt_blocks(std::span<const uint8_t> in, std::span<uint8_t> out, size_t blocks) const {
   assert_key_material_set();

   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<uint8_t> buffer(LEFT_SIZE);

   for(size_t i = 0; i != blocks; ++i) {
      const auto in_left = in.first(LEFT_SIZE);
      const auto in_right = in.subspan(LEFT_SIZE, RIGHT_SIZE);
      const auto out_left = out.first(LEFT_SIZE);
      const auto out_right = out.subspan(LEFT_SIZE, RIGHT_SIZE);

      xor_buf(buffer, in_left, m_key2);
      m_cipher->set_key(buffer);
      m_cipher->cipher(in_right, out_right);

      m_hash->update(out_right);
      m_hash->final(buffer);
      xor_buf(out_left, in_left, buffer);

      xor_buf(buffer, out_left, m_key1);
      m_cipher->set_key(buffer);
      m_cipher->cipher1(out_right);

      in = in.subspan(m_block_size);
      out = out.subspan(m_block_size);
   }
}

bool Lion::has_keying_material() const {
   return !m_key1.empty() && !m_key2.empty();
}

/*
* Lion Key Schedule
*/
void Lion::key_schedule(std::span<const uint8_t> key) {
   clear();

   const size_t half = key.size() / 2;

   m_key1.resize(left_size());
   m_key2.resize(left_size());
   clear_mem(m_key1);
   clear_mem(m_key2);
   copy_mem(std::span(m_key1).first(half), key.first(half));
   copy_mem(std::span(m_key2).first(half), key.subspan(half, half));
}

/*
* Return the name of this type
*/
std::string Lion::name() const {
   return fmt("Lion({},{},{})", m_hash->name(), m_cipher->name(), block_size());
}

std::unique_ptr<BlockCipher> Lion::new_object() const {
   return std::make_unique<Lion>(m_hash->new_object(), m_cipher->new_object(), block_size());
}

/*
* Clear memory of sensitive data
*/
void Lion::clear() {
   zap(m_key1);
   zap(m_key2);
   m_hash->clear();
   m_cipher->clear();
}

/*
* Lion Constructor
*/
Lion::Lion(std::unique_ptr<HashFunction> hash, std::unique_ptr<StreamCipher> cipher, size_t bs) :
      m_block_size(std::max<size_t>(2 * hash->output_length() + 1, bs)),
      m_hash(std::move(hash)),
      m_cipher(std::move(cipher)) {
   if(2 * left_size() + 1 > m_block_size) {
      throw Invalid_Argument(fmt("Block size {} is too small for {}", m_block_size, name()));
   }

   if(!m_cipher->valid_keylength(left_size())) {
      throw Invalid_Argument(fmt("Lion does not support combining {} and {}", m_cipher->name(), m_hash->name()));
   }
}

}  // namespace Botan
