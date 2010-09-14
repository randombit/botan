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

void poly_double(byte tweak[], u32bit size)
   {
   const byte polynomial = (size == 16) ? 0x87 : 0x1B;

   byte carry = 0;
   for(u32bit i = 0; i != size; ++i)
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
u32bit xts_parallelism(BlockCipher* cipher)
   {
   return std::max<u32bit>(cipher->parallel_bytes(),
                           2 * cipher->BLOCK_SIZE);
   }

}

/*
* XTS_Encryption constructor
*/
XTS_Encryption::XTS_Encryption(BlockCipher* ciph) :
   Buffered_Filter(xts_parallelism(ciph), ciph->BLOCK_SIZE + 1),
   cipher(ciph)
   {
   if(cipher->BLOCK_SIZE != 8 && cipher->BLOCK_SIZE != 16)
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
   Buffered_Filter(xts_parallelism(ciph), ciph->BLOCK_SIZE + 1),
   cipher(ciph)
   {
   if(cipher->BLOCK_SIZE != 8 && cipher->BLOCK_SIZE != 16)
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

/*
* Set new tweak
*/
void XTS_Encryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   const u32bit blocks_in_tweak = tweak.size() / cipher->BLOCK_SIZE;

   tweak.copy(iv.begin(), iv.length());
   cipher2->encrypt(tweak);

   for(u32bit i = 1; i < blocks_in_tweak; ++i)
      {
      tweak.copy(i*cipher->BLOCK_SIZE,
                 &tweak[(i-1)*cipher->BLOCK_SIZE],
                 cipher->BLOCK_SIZE);

      poly_double(&tweak[i*cipher->BLOCK_SIZE], cipher->BLOCK_SIZE);
      }
   }

void XTS_Encryption::set_key(const SymmetricKey& key)
   {
   u32bit key_half = key.length() / 2;

   if(key.length() % 2 == 1 || !cipher->valid_keylength(key_half))
      throw Invalid_Key_Length(name(), key.length());

   cipher->set_key(key.begin(), key_half);
   cipher2->set_key(key.begin() + key_half, key_half);
   }

/*
* Encrypt in XTS mode
*/
void XTS_Encryption::write(const byte input[], u32bit length)
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

void XTS_Encryption::buffered_block(const byte input[], u32bit length)
   {
   const u32bit blocks_in_tweak = tweak.size() / cipher->BLOCK_SIZE;
   u32bit blocks = length / cipher->BLOCK_SIZE;

   SecureVector<byte> temp(tweak.size());

   while(blocks)
      {
      u32bit to_proc = std::min(blocks, blocks_in_tweak);
      u32bit to_proc_bytes = to_proc * cipher->BLOCK_SIZE;

      xor_buf(temp, input, tweak, to_proc_bytes);

      cipher->encrypt_n(&temp[0], &temp[0], to_proc);

      xor_buf(temp, tweak, to_proc_bytes);

      send(temp, to_proc_bytes);

      tweak.copy(&tweak[(to_proc-1)*cipher->BLOCK_SIZE],
                 cipher->BLOCK_SIZE);
      poly_double(&tweak[0], cipher->BLOCK_SIZE);

      for(u32bit i = 1; i < blocks_in_tweak; ++i)
         {
         tweak.copy(i*cipher->BLOCK_SIZE,
                    &tweak[(i-1)*cipher->BLOCK_SIZE],
                    cipher->BLOCK_SIZE);

         poly_double(&tweak[i*cipher->BLOCK_SIZE], cipher->BLOCK_SIZE);
         }

      input += to_proc * cipher->BLOCK_SIZE;
      blocks -= to_proc;
      }
   }

/*
* Finish encrypting in XTS mode
*/
void XTS_Encryption::buffered_final(const byte input[], u32bit length)
   {
   if(length <= cipher->BLOCK_SIZE)
      throw Encoding_Error("XTS_Encryption: insufficient data to encrypt");

   if(length % cipher->BLOCK_SIZE == 0)
      {
      buffered_block(input, length);
      }
   else
      { // steal ciphertext

      u32bit leftover_blocks =
         ((length / cipher->BLOCK_SIZE) - 1) * cipher->BLOCK_SIZE;

      buffered_block(input, leftover_blocks);

      input += leftover_blocks;
      length -= leftover_blocks;

      SecureVector<byte> temp(input, length);

      xor_buf(temp, tweak, cipher->BLOCK_SIZE);
      cipher->encrypt(temp);
      xor_buf(temp, tweak, cipher->BLOCK_SIZE);

      poly_double(&tweak[0], cipher->BLOCK_SIZE);

      for(u32bit i = 0; i != length - cipher->BLOCK_SIZE; ++i)
         std::swap(temp[i], temp[i + cipher->BLOCK_SIZE]);

      xor_buf(temp, tweak, cipher->BLOCK_SIZE);
      cipher->encrypt(temp);
      xor_buf(temp, tweak, cipher->BLOCK_SIZE);

      send(temp, temp.size());
      }

   buffer_reset();
   }

/*
* XTS_Decryption constructor
*/
XTS_Decryption::XTS_Decryption(BlockCipher* ciph) :
   Buffered_Filter(xts_parallelism(ciph), ciph->BLOCK_SIZE + 1),
   cipher(ciph)
   {
   if(cipher->BLOCK_SIZE != 8 && cipher->BLOCK_SIZE != 16)
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
   Buffered_Filter(xts_parallelism(ciph), ciph->BLOCK_SIZE + 1),
   cipher(ciph)
   {
   if(cipher->BLOCK_SIZE != 8 && cipher->BLOCK_SIZE != 16)
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

/*
* Set new tweak
*/
void XTS_Decryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   const u32bit blocks_in_tweak = tweak.size() / cipher->BLOCK_SIZE;

   tweak.copy(iv.begin(), iv.length());
   cipher2->encrypt(tweak);

   for(u32bit i = 1; i < blocks_in_tweak; ++i)
      {
      tweak.copy(i*cipher->BLOCK_SIZE,
                 &tweak[(i-1)*cipher->BLOCK_SIZE],
                 cipher->BLOCK_SIZE);

      poly_double(&tweak[i*cipher->BLOCK_SIZE], cipher->BLOCK_SIZE);
      }
   }

void XTS_Decryption::set_key(const SymmetricKey& key)
   {
   u32bit key_half = key.length() / 2;

   if(key.length() % 2 == 1 || !cipher->valid_keylength(key_half))
      throw Invalid_Key_Length(name(), key.length());

   cipher->set_key(key.begin(), key_half);
   cipher2->set_key(key.begin() + key_half, key_half);
   }

/*
* Decrypt in XTS mode
*/
void XTS_Decryption::write(const byte input[], u32bit length)
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

void XTS_Decryption::buffered_block(const byte input[], u32bit input_length)
   {
   const u32bit blocks_in_tweak = tweak.size() / cipher->BLOCK_SIZE;
   u32bit blocks = input_length / cipher->BLOCK_SIZE;

   SecureVector<byte> temp(tweak.size());

   while(blocks)
      {
      u32bit to_proc = std::min(blocks, blocks_in_tweak);
      u32bit to_proc_bytes = to_proc * cipher->BLOCK_SIZE;

      xor_buf(temp, input, tweak, to_proc_bytes);

      cipher->decrypt_n(&temp[0], &temp[0], to_proc);

      xor_buf(temp, tweak, to_proc_bytes);

      send(temp, to_proc_bytes);

      tweak.copy(&tweak[(to_proc-1)*cipher->BLOCK_SIZE],
                 cipher->BLOCK_SIZE);
      poly_double(&tweak[0], cipher->BLOCK_SIZE);

      for(u32bit i = 1; i < blocks_in_tweak; ++i)
         {
         tweak.copy(i*cipher->BLOCK_SIZE,
                    &tweak[(i-1)*cipher->BLOCK_SIZE],
                    cipher->BLOCK_SIZE);

         poly_double(&tweak[i*cipher->BLOCK_SIZE], cipher->BLOCK_SIZE);
         }

      input += to_proc * cipher->BLOCK_SIZE;
      blocks -= to_proc;
      }
   }

void XTS_Decryption::buffered_final(const byte input[], u32bit length)
   {
   if(length <= cipher->BLOCK_SIZE)
      throw Decoding_Error("XTS_Decryption: insufficient data to decrypt");

   if(length % cipher->BLOCK_SIZE == 0)
      {
      buffered_block(input, length);
      }
   else
      {
      u32bit leftover_blocks =
         ((length / cipher->BLOCK_SIZE) - 1) * cipher->BLOCK_SIZE;

      buffered_block(input, leftover_blocks);

      input += leftover_blocks;
      length -= leftover_blocks;

      SecureVector<byte> temp(input, length);
      SecureVector<byte> tweak_copy(&tweak[0], cipher->BLOCK_SIZE);

      poly_double(&tweak_copy[0], cipher->BLOCK_SIZE);

      xor_buf(temp, tweak_copy, cipher->BLOCK_SIZE);
      cipher->decrypt(temp);
      xor_buf(temp, tweak_copy, cipher->BLOCK_SIZE);

      for(u32bit i = 0; i != length - cipher->BLOCK_SIZE; ++i)
         std::swap(temp[i], temp[i + cipher->BLOCK_SIZE]);

      xor_buf(temp, tweak, cipher->BLOCK_SIZE);
      cipher->decrypt(temp);
      xor_buf(temp, tweak, cipher->BLOCK_SIZE);

      send(temp, length);
      }

   buffer_reset();
   }

}
