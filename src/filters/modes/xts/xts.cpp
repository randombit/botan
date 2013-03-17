/*
* XTS Mode
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/xts.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>
#include <stdexcept>

namespace Botan {

namespace {

void poly_double(byte tweak[], size_t size)
   {
   const byte polynomial = (size == 16) ? 0x87 : 0x1B;

   byte carry = 0;
   for(size_t i = 0; i != size; ++i)
      {
      byte carry2 = (tweak[i] >> 7);
      tweak[i] = (tweak[i] << 1) | carry;
      carry = carry2;
      }

   if(carry)
      tweak[0] ^= polynomial;
   }

/* XTS needs to process at least 2 blocks in parallel
   because block_size+1 bytes are needed at the end
*/
size_t xts_parallelism(BlockCipher* cipher)
   {
   return std::max<size_t>(cipher->parallel_bytes(),
                           2 * cipher->block_size());
   }

Key_Length_Specification xts_key_spec(const BlockCipher& cipher)
   {
   const Key_Length_Specification& spec = cipher.key_spec();

   return Key_Length_Specification(2*spec.minimum_keylength(),
                                   2*spec.maximum_keylength(),
                                   2*spec.keylength_multiple());
   }

}

/*
* XTS_Encryption constructor
*/
XTS_Encryption::XTS_Encryption(BlockCipher* ciph) :
   Buffered_Filter(xts_parallelism(ciph), ciph->block_size() + 1),
   cipher(ciph)
   {
   if(cipher->block_size() != 8 && cipher->block_size() != 16)
      throw std::invalid_argument("Bad cipher for XTS: " + cipher->name());

   cipher2 = cipher->clone();
   tweak.resize(buffered_block_size());
   }

/*
* XTS_Encryption constructor
*/
XTS_Encryption::XTS_Encryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   Buffered_Filter(xts_parallelism(ciph), ciph->block_size() + 1),
   cipher(ciph)
   {
   if(cipher->block_size() != 8 && cipher->block_size() != 16)
       throw std::invalid_argument("Bad cipher for XTS: " + cipher->name());

   cipher2 = cipher->clone();
   tweak.resize(buffered_block_size());

   set_key(key);
   set_iv(iv);
   }

/*
* Return the name
*/
std::string XTS_Encryption::name() const
   {
   return (cipher->name() + "/XTS");
   }

Key_Length_Specification XTS_Encryption::key_spec() const
   {
   return xts_key_spec(*cipher);
   }

/*
* Set new tweak
*/
void XTS_Encryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   const size_t blocks_in_tweak = tweak.size() / cipher->block_size();

   tweak.assign(iv.begin(), iv.end());
   cipher2->encrypt(tweak);

   for(size_t i = 1; i < blocks_in_tweak; ++i)
      {
      buffer_insert(tweak, i*cipher->block_size(),
                    &tweak[(i-1)*cipher->block_size()],
                    cipher->block_size());

      poly_double(&tweak[i*cipher->block_size()], cipher->block_size());
      }
   }

void XTS_Encryption::set_key(const SymmetricKey& key)
   {
   size_t key_half = key.length() / 2;

   if(key.length() % 2 == 1 || !cipher->valid_keylength(key_half))
      throw Invalid_Key_Length(name(), key.length());

   cipher->set_key(key.begin(), key_half);
   cipher2->set_key(key.begin() + key_half, key_half);
   }

/*
* Encrypt in XTS mode
*/
void XTS_Encryption::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }
/*
* Finish encrypting in XTS mode
*/
void XTS_Encryption::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void XTS_Encryption::buffered_block(const byte input[], size_t length)
   {
   const size_t blocks_in_tweak = tweak.size() / cipher->block_size();
   size_t blocks = length / cipher->block_size();

   secure_vector<byte> temp(tweak.size());

   while(blocks)
      {
      size_t to_proc = std::min(blocks, blocks_in_tweak);
      size_t to_proc_bytes = to_proc * cipher->block_size();

      xor_buf(temp, input, tweak, to_proc_bytes);

      cipher->encrypt_n(&temp[0], &temp[0], to_proc);

      xor_buf(temp, tweak, to_proc_bytes);

      send(temp, to_proc_bytes);

      copy_mem(&tweak[0],
               &tweak[(to_proc-1)*cipher->block_size()],
               cipher->block_size());

      poly_double(&tweak[0], cipher->block_size());

      for(size_t i = 1; i < blocks_in_tweak; ++i)
         {
         buffer_insert(tweak, i*cipher->block_size(),
                    &tweak[(i-1)*cipher->block_size()],
                    cipher->block_size());

         poly_double(&tweak[i*cipher->block_size()], cipher->block_size());
         }

      input += to_proc * cipher->block_size();
      blocks -= to_proc;
      }
   }

/*
* Finish encrypting in XTS mode
*/
void XTS_Encryption::buffered_final(const byte input[], size_t length)
   {
   if(length <= cipher->block_size())
      throw Encoding_Error("XTS_Encryption: insufficient data to encrypt");

   if(length % cipher->block_size() == 0)
      {
      buffered_block(input, length);
      }
   else
      { // steal ciphertext

      size_t leftover_blocks =
         ((length / cipher->block_size()) - 1) * cipher->block_size();

      buffered_block(input, leftover_blocks);

      input += leftover_blocks;
      length -= leftover_blocks;

      secure_vector<byte> temp(input, input + length);

      xor_buf(temp, tweak, cipher->block_size());
      cipher->encrypt(temp);
      xor_buf(temp, tweak, cipher->block_size());

      poly_double(&tweak[0], cipher->block_size());

      for(size_t i = 0; i != length - cipher->block_size(); ++i)
         std::swap(temp[i], temp[i + cipher->block_size()]);

      xor_buf(temp, tweak, cipher->block_size());
      cipher->encrypt(temp);
      xor_buf(temp, tweak, cipher->block_size());

      send(temp, temp.size());
      }

   buffer_reset();
   }

/*
* XTS_Decryption constructor
*/
XTS_Decryption::XTS_Decryption(BlockCipher* ciph) :
   Buffered_Filter(xts_parallelism(ciph), ciph->block_size() + 1),
   cipher(ciph)
   {
   if(cipher->block_size() != 8 && cipher->block_size() != 16)
       throw std::invalid_argument("Bad cipher for XTS: " + cipher->name());

   cipher2 = ciph->clone();
   tweak.resize(buffered_block_size());
   }

/*
* XTS_Decryption constructor
*/
XTS_Decryption::XTS_Decryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv) :
   Buffered_Filter(xts_parallelism(ciph), ciph->block_size() + 1),
   cipher(ciph)
   {
   if(cipher->block_size() != 8 && cipher->block_size() != 16)
       throw std::invalid_argument("Bad cipher for XTS: " + cipher->name());

   cipher2 = ciph->clone();
   tweak.resize(buffered_block_size());

   set_key(key);
   set_iv(iv);
   }

/*
* Return the name
*/
std::string XTS_Decryption::name() const
   {
   return (cipher->name() + "/XTS");
   }

Key_Length_Specification XTS_Decryption::key_spec() const
   {
   return xts_key_spec(*cipher);
   }

/*
* Set new tweak
*/
void XTS_Decryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   const size_t blocks_in_tweak = tweak.size() / cipher->block_size();

   tweak.assign(iv.begin(), iv.end());
   cipher2->encrypt(tweak);

   for(size_t i = 1; i < blocks_in_tweak; ++i)
      {
      buffer_insert(tweak, i*cipher->block_size(),
                 &tweak[(i-1)*cipher->block_size()],
                 cipher->block_size());

      poly_double(&tweak[i*cipher->block_size()], cipher->block_size());
      }
   }

void XTS_Decryption::set_key(const SymmetricKey& key)
   {
   size_t key_half = key.length() / 2;

   if(key.length() % 2 == 1 || !cipher->valid_keylength(key_half))
      throw Invalid_Key_Length(name(), key.length());

   cipher->set_key(key.begin(), key_half);
   cipher2->set_key(key.begin() + key_half, key_half);
   }

/*
* Decrypt in XTS mode
*/
void XTS_Decryption::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }

/*
* Finish decrypting in XTS mode
*/
void XTS_Decryption::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void XTS_Decryption::buffered_block(const byte input[], size_t input_length)
   {
   const size_t blocks_in_tweak = tweak.size() / cipher->block_size();
   size_t blocks = input_length / cipher->block_size();

   secure_vector<byte> temp(tweak.size());

   while(blocks)
      {
      size_t to_proc = std::min(blocks, blocks_in_tweak);
      size_t to_proc_bytes = to_proc * cipher->block_size();

      xor_buf(temp, input, tweak, to_proc_bytes);

      cipher->decrypt_n(&temp[0], &temp[0], to_proc);

      xor_buf(temp, tweak, to_proc_bytes);

      send(temp, to_proc_bytes);

      copy_mem(&tweak[0],
               &tweak[(to_proc-1)*cipher->block_size()],
               cipher->block_size());

      poly_double(&tweak[0], cipher->block_size());

      for(size_t i = 1; i < blocks_in_tweak; ++i)
         {
         buffer_insert(tweak, i*cipher->block_size(),
                       &tweak[(i-1)*cipher->block_size()],
                       cipher->block_size());

         poly_double(&tweak[i*cipher->block_size()], cipher->block_size());
         }

      input += to_proc * cipher->block_size();
      blocks -= to_proc;
      }
   }

void XTS_Decryption::buffered_final(const byte input[], size_t length)
   {
   if(length <= cipher->block_size())
      throw Decoding_Error("XTS_Decryption: insufficient data to decrypt");

   if(length % cipher->block_size() == 0)
      {
      buffered_block(input, length);
      }
   else
      {
      size_t leftover_blocks =
         ((length / cipher->block_size()) - 1) * cipher->block_size();

      buffered_block(input, leftover_blocks);

      input += leftover_blocks;
      length -= leftover_blocks;

      secure_vector<byte> temp(input, input + length);
      secure_vector<byte> tweak_copy(&tweak[0], &tweak[cipher->block_size()]);

      poly_double(&tweak_copy[0], cipher->block_size());

      xor_buf(temp, tweak_copy, cipher->block_size());
      cipher->decrypt(temp);
      xor_buf(temp, tweak_copy, cipher->block_size());

      for(size_t i = 0; i != length - cipher->block_size(); ++i)
         std::swap(temp[i], temp[i + cipher->block_size()]);

      xor_buf(temp, tweak, cipher->block_size());
      cipher->decrypt(temp);
      xor_buf(temp, tweak, cipher->block_size());

      send(temp, length);
      }

   buffer_reset();
   }

}
