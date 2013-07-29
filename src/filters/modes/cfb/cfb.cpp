/*
* CFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cfb.h>
#include <botan/parsing.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

/*
* CFB Encryption Constructor
*/
CFB_Encryption::CFB_Encryption(BlockCipher* ciph, size_t fback_bits)
   {
   cipher = ciph;
   feedback = fback_bits ? fback_bits / 8: cipher->block_size();

   buffer.resize(cipher->block_size());
   state.resize(cipher->block_size());
   position = 0;

   if(feedback == 0 || fback_bits % 8 != 0 || feedback > cipher->block_size())
      throw Invalid_Argument("CFB_Encryption: Invalid feedback size " +
                             to_string(fback_bits));
   }

/*
* CFB Encryption Constructor
*/
CFB_Encryption::CFB_Encryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               size_t fback_bits)
   {
   cipher = ciph;
   feedback = fback_bits ? fback_bits / 8: cipher->block_size();

   buffer.resize(cipher->block_size());
   state.resize(cipher->block_size());
   position = 0;

   if(feedback == 0 || fback_bits % 8 != 0 || feedback > cipher->block_size())
      throw Invalid_Argument("CFB_Encryption: Invalid feedback size " +
                             to_string(fback_bits));

   set_key(key);
   set_iv(iv);
   }

void CFB_Encryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   zeroise(buffer);
   position = 0;

   cipher->encrypt(&state[0], &buffer[0]);
   }

/*
* Encrypt data in CFB mode
*/
void CFB_Encryption::write(const byte input[], size_t length)
   {
   while(length)
      {
      size_t xored = std::min(feedback - position, length);
      xor_buf(&buffer[position], input, xored);
      send(&buffer[position], xored);
      input += xored;
      length -= xored;
      position += xored;

      if(position == feedback)
         {
         for(size_t j = 0; j != cipher->block_size() - feedback; ++j)
            state[j] = state[j + feedback];

         buffer_insert(state, cipher->block_size() - feedback,
                       &buffer[0], feedback);

         cipher->encrypt(state, buffer);
         position = 0;
         }
      }
   }

/*
* CFB Decryption Constructor
*/
CFB_Decryption::CFB_Decryption(BlockCipher* ciph, size_t fback_bits)
   {
   cipher = ciph;
   feedback = fback_bits ? fback_bits / 8: cipher->block_size();

   buffer.resize(cipher->block_size());
   state.resize(cipher->block_size());
   position = 0;

   if(feedback == 0 || fback_bits % 8 != 0 || feedback > cipher->block_size())
      throw Invalid_Argument("CFB_Decryption: Invalid feedback size " +
                             to_string(fback_bits));
   }

/*
* CFB Decryption Constructor
*/
CFB_Decryption::CFB_Decryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               size_t fback_bits)
   {
   cipher = ciph;
   feedback = fback_bits ? fback_bits / 8: cipher->block_size();

   buffer.resize(cipher->block_size());
   state.resize(cipher->block_size());
   position = 0;

   if(feedback == 0 || fback_bits % 8 != 0 || feedback > cipher->block_size())
      throw Invalid_Argument("CFB_Decryption: Invalid feedback size " +
                             to_string(fback_bits));

   set_key(key);
   set_iv(iv);
   }

void CFB_Decryption::set_iv(const InitializationVector& iv)
   {
   if(!valid_iv_length(iv.length()))
      throw Invalid_IV_Length(name(), iv.length());

   state = iv.bits_of();
   zeroise(buffer);
   position = 0;

   cipher->encrypt(state, buffer);
   }

/*
* Decrypt data in CFB mode
*/
void CFB_Decryption::write(const byte input[], size_t length)
   {
   while(length)
      {
      size_t xored = std::min(feedback - position, length);
      xor_buf(&buffer[position], input, xored);
      send(&buffer[position], xored);
      buffer_insert(buffer, position, input, xored);
      input += xored;
      length -= xored;
      position += xored;
      if(position == feedback)
         {
         for(size_t j = 0; j != cipher->block_size() - feedback; ++j)
            state[j] = state[j + feedback];

         buffer_insert(state, cipher->block_size() - feedback,
                       &buffer[0], feedback);

         cipher->encrypt(state, buffer);
         position = 0;
         }
      }
   }

}
