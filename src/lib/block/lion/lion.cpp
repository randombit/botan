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
void Lion::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<uint8_t> buffer_vec(LEFT_SIZE);
   uint8_t* buffer = buffer_vec.data();

   for(size_t i = 0; i != blocks; ++i) {
      xor_buf(buffer, in, m_key1.data(), LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher(in + LEFT_SIZE, out + LEFT_SIZE, RIGHT_SIZE);

      m_hash->update(out + LEFT_SIZE, RIGHT_SIZE);
      m_hash->final(buffer);
      xor_buf(out, in, buffer, LEFT_SIZE);

      xor_buf(buffer, out, m_key2.data(), LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher1(out + LEFT_SIZE, RIGHT_SIZE);

      in += m_block_size;
      out += m_block_size;
   }
}

/*
* Lion Decryption
*/
void Lion::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<uint8_t> buffer_vec(LEFT_SIZE);
   uint8_t* buffer = buffer_vec.data();

   for(size_t i = 0; i != blocks; ++i) {
      xor_buf(buffer, in, m_key2.data(), LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher(in + LEFT_SIZE, out + LEFT_SIZE, RIGHT_SIZE);

      m_hash->update(out + LEFT_SIZE, RIGHT_SIZE);
      m_hash->final(buffer);
      xor_buf(out, in, buffer, LEFT_SIZE);

      xor_buf(buffer, out, m_key1.data(), LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher1(out + LEFT_SIZE, RIGHT_SIZE);

      in += m_block_size;
      out += m_block_size;
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
   clear_mem(m_key1.data(), m_key1.size());
   clear_mem(m_key2.data(), m_key2.size());
   copy_mem(m_key1.data(), key.data(), half);
   copy_mem(m_key2.data(), key.subspan(half, half).data(), half);
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
