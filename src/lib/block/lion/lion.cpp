/*
* Lion
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/block_utils.h>
#include <botan/lion.h>
#include <botan/parsing.h>

namespace Botan {

namespace {

Lion* make_lion(const BlockCipher::Spec& spec)
   {
   if(spec.arg_count_between(2, 3))
      {
      std::unique_ptr<HashFunction> hash(Algo_Registry<HashFunction>::global_registry().make(spec.arg(0)));
      std::unique_ptr<StreamCipher> stream(Algo_Registry<StreamCipher>::global_registry().make(spec.arg(1)));

      if(hash && stream)
         {
         const size_t block_size = spec.arg_as_integer(2, 1024);
         return new Lion(hash.release(), stream.release(), block_size);
         }
      }
   return nullptr;
   }

}

BOTAN_REGISTER_NAMED_T(BlockCipher, "Lion", Lion, make_lion);

/*
* Lion Encryption
*/
void Lion::encrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<byte> buffer_vec(LEFT_SIZE);
   byte* buffer = &buffer_vec[0];

   for(size_t i = 0; i != blocks; ++i)
      {
      xor_buf(buffer, in, &m_key1[0], LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher(in + LEFT_SIZE, out + LEFT_SIZE, RIGHT_SIZE);

      m_hash->update(out + LEFT_SIZE, RIGHT_SIZE);
      m_hash->final(buffer);
      xor_buf(out, in, buffer, LEFT_SIZE);

      xor_buf(buffer, out, &m_key2[0], LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher1(out + LEFT_SIZE, RIGHT_SIZE);

      in += m_block_size;
      out += m_block_size;
      }
   }

/*
* Lion Decryption
*/
void Lion::decrypt_n(const byte in[], byte out[], size_t blocks) const
   {
   const size_t LEFT_SIZE = left_size();
   const size_t RIGHT_SIZE = right_size();

   secure_vector<byte> buffer_vec(LEFT_SIZE);
   byte* buffer = &buffer_vec[0];

   for(size_t i = 0; i != blocks; ++i)
      {
      xor_buf(buffer, in, &m_key2[0], LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher(in + LEFT_SIZE, out + LEFT_SIZE, RIGHT_SIZE);

      m_hash->update(out + LEFT_SIZE, RIGHT_SIZE);
      m_hash->final(buffer);
      xor_buf(out, in, buffer, LEFT_SIZE);

      xor_buf(buffer, out, &m_key1[0], LEFT_SIZE);
      m_cipher->set_key(buffer, LEFT_SIZE);
      m_cipher->cipher1(out + LEFT_SIZE, RIGHT_SIZE);

      in += m_block_size;
      out += m_block_size;
      }
   }

/*
* Lion Key Schedule
*/
void Lion::key_schedule(const byte key[], size_t length)
   {
   clear();

   const size_t half = length / 2;
   copy_mem(&m_key1[0], key, half);
   copy_mem(&m_key2[0], key + half, half);
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
   zeroise(m_key1);
   zeroise(m_key2);
   m_hash->clear();
   m_cipher->clear();
   }

/*
* Lion Constructor
*/
Lion::Lion(HashFunction* hash, StreamCipher* cipher, size_t block_size) :
   m_block_size(std::max<size_t>(2*hash->output_length() + 1, block_size)),
   m_hash(hash),
   m_cipher(cipher)
   {
   if(2*left_size() + 1 > m_block_size)
      throw Invalid_Argument(name() + ": Chosen block size is too small");

   if(!m_cipher->valid_keylength(left_size()))
      throw Invalid_Argument(name() + ": This stream/hash combo is invalid");

   m_key1.resize(left_size());
   m_key2.resize(left_size());
   }

}
