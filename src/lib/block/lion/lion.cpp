/*
* Lion
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/lion.h>
#include <botan/exceptn.h>

namespace Botan {

/*
* Lion Encryption
*/
void Lion::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_key1.empty() == false);

   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<uint8_t> buffer_vec(LEFT_SIZE);
   uint8_t* buffer = buffer_vec.data();

   for(size_t i = 0; i != blocks; ++i)
      {
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
void Lion::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_key1.empty() == false);

   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<uint8_t> buffer_vec(LEFT_SIZE);
   uint8_t* buffer = buffer_vec.data();

   for(size_t i = 0; i != blocks; ++i)
      {
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

/*
* Lion Key Schedule
*/
void Lion::key_schedule(const uint8_t key[], size_t length)
   {
   clear();

   const size_t half = length / 2;

   m_key1.resize(left_size());
   m_key2.resize(left_size());
   clear_mem(m_key1.data(), m_key1.size());
   clear_mem(m_key2.data(), m_key2.size());
   copy_mem(m_key1.data(), key, half);
   copy_mem(m_key2.data(), key + half, half);
   }

/*
* Return the name of this type
*/
std::string Lion::name() const
   {
   return "Lion(" + m_hash->name() + "," +
                    m_cipher->name() + "," +
                    std::to_string(block_size()) + ")";
   }

/*
* Return a clone of this object
*/
BlockCipher* Lion::clone() const
   {
   return new Lion(m_hash->clone(), m_cipher->clone(), block_size());
   }

/*
* Clear memory of sensitive data
*/
void Lion::clear()
   {
   zap(m_key1);
   zap(m_key2);
   m_hash->clear();
   m_cipher->clear();
   }

/*
* Lion Constructor
*/
Lion::Lion(HashFunction* hash, StreamCipher* cipher, size_t bs) :
   m_block_size(std::max<size_t>(2*hash->output_length() + 1, bs)),
   m_hash(hash),
   m_cipher(cipher)
   {
   if(2*left_size() + 1 > m_block_size)
      throw Invalid_Argument(name() + ": Chosen block size is too small");

   if(!m_cipher->valid_keylength(left_size()))
      throw Invalid_Argument(name() + ": This stream/hash combo is invalid");
   }

}
