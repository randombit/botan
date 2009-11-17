/*
* CFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cfb.h>
#include <botan/parsing.h>
#include <botan/xor_buf.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* Check the feedback size
*/
void check_feedback(u32bit BLOCK_SIZE, u32bit FEEDBACK_SIZE, u32bit bits,
                    const std::string& name)
   {
   if(FEEDBACK_SIZE == 0 || FEEDBACK_SIZE > BLOCK_SIZE || bits % 8 != 0)
      throw Invalid_Argument(name + ": Invalid feedback size " +
                             to_string(bits));
   }

}

/*
* CFB Encryption Constructor
*/
CFB_Encryption::CFB_Encryption(BlockCipher* ciph,
                               u32bit fback_bits) :
   BlockCipherMode(ciph, "CFB", ciph->BLOCK_SIZE, 1),
   FEEDBACK_SIZE(fback_bits ? fback_bits / 8: BLOCK_SIZE)
   {
   check_feedback(BLOCK_SIZE, FEEDBACK_SIZE, fback_bits, name());
   }

/*
* CFB Encryption Constructor
*/
CFB_Encryption::CFB_Encryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               u32bit fback_bits) :
   BlockCipherMode(ciph, "CFB", ciph->BLOCK_SIZE, 1),
   FEEDBACK_SIZE(fback_bits ? fback_bits / 8: BLOCK_SIZE)
   {
   check_feedback(BLOCK_SIZE, FEEDBACK_SIZE, fback_bits, name());
   set_key(key);
   set_iv(iv);
   }

/*
* Encrypt data in CFB mode
*/
void CFB_Encryption::write(const byte input[], u32bit length)
   {
   while(length)
      {
      u32bit xored = std::min(FEEDBACK_SIZE - position, length);
      xor_buf(buffer + position, input, xored);
      send(buffer + position, xored);
      input += xored;
      length -= xored;
      position += xored;
      if(position == FEEDBACK_SIZE)
         feedback();
      }
   }

/*
* Do the feedback
*/
void CFB_Encryption::feedback()
   {
   for(u32bit j = 0; j != BLOCK_SIZE - FEEDBACK_SIZE; ++j)
      state[j] = state[j + FEEDBACK_SIZE];
   state.copy(BLOCK_SIZE - FEEDBACK_SIZE, buffer, FEEDBACK_SIZE);
   cipher->encrypt(state, buffer);
   position = 0;
   }

/*
* CFB Decryption Constructor
*/
CFB_Decryption::CFB_Decryption(BlockCipher* ciph,
                               u32bit fback_bits) :
   BlockCipherMode(ciph, "CFB", ciph->BLOCK_SIZE, 1),
   FEEDBACK_SIZE(fback_bits ? fback_bits / 8 : BLOCK_SIZE)
   {
   check_feedback(BLOCK_SIZE, FEEDBACK_SIZE, fback_bits, name());
   }

/*
* CFB Decryption Constructor
*/
CFB_Decryption::CFB_Decryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               u32bit fback_bits) :
   BlockCipherMode(ciph, "CFB", ciph->BLOCK_SIZE, 1),
   FEEDBACK_SIZE(fback_bits ? fback_bits / 8 : BLOCK_SIZE)
   {
   check_feedback(BLOCK_SIZE, FEEDBACK_SIZE, fback_bits, name());
   set_key(key);
   set_iv(iv);
   }

/*
* Decrypt data in CFB mode
*/
void CFB_Decryption::write(const byte input[], u32bit length)
   {
   while(length)
      {
      u32bit xored = std::min(FEEDBACK_SIZE - position, length);
      xor_buf(buffer + position, input, xored);
      send(buffer + position, xored);
      buffer.copy(position, input, xored);
      input += xored;
      length -= xored;
      position += xored;
      if(position == FEEDBACK_SIZE)
         feedback();
      }
   }

/*
* Do the feedback
*/
void CFB_Decryption::feedback()
   {
   for(u32bit j = 0; j != BLOCK_SIZE - FEEDBACK_SIZE; ++j)
      state[j] = state[j + FEEDBACK_SIZE];
   state.copy(BLOCK_SIZE - FEEDBACK_SIZE, buffer, FEEDBACK_SIZE);
   cipher->encrypt(state, buffer);
   position = 0;
   }

}
