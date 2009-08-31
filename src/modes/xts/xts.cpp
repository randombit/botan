/*
* XTS Mode
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/xts.h>
#include <botan/xor_buf.h>
#include <algorithm>
#include <stdexcept>

namespace Botan {

namespace {

void poly_double(byte tweak[], u32bit size)
   {
   const byte polynomial = 0x87; // for 128 bit ciphers

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

}

/*
* XTS_Encryption constructor
*/
XTS_Encryption::XTS_Encryption(BlockCipher* ciph) : cipher(ciph)
   {
   if(cipher->BLOCK_SIZE != 16)
      throw std::invalid_argument("Bad cipher for XTS: " + cipher->name());

   cipher2 = cipher->clone();
   tweak.create(cipher->BLOCK_SIZE);
   buffer.create(2 * cipher->BLOCK_SIZE);
   position = 0;
   }

/*
* XTS_Encryption constructor
*/
XTS_Encryption::XTS_Encryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv) : cipher(ciph)
   {
   if(cipher->BLOCK_SIZE != 16)
      throw std::invalid_argument("Bad cipher for XTS: " + cipher->name());

   cipher2 = cipher->clone();
   tweak.create(cipher->BLOCK_SIZE);
   buffer.create(2 * cipher->BLOCK_SIZE);
   position = 0;

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
   if(iv.length() != tweak.size())
      throw Invalid_IV_Length(name(), iv.length());

   tweak = iv.bits_of();
   cipher2->encrypt(tweak);
   }

void XTS_Encryption::set_key(const SymmetricKey& key)
   {
   u32bit key_half = key.length() / 2;

   if(key.length() % 2 == 1 || !cipher->valid_keylength(key_half))
      throw Invalid_Key_Length(name(), key.length());

   cipher->set_key(key.begin(), key_half);
   cipher2->set_key(key.begin() + key_half, key_half);
   }

void XTS_Encryption::encrypt(const byte block[])
   {
   /*
   * We can always use the first 16 bytes of buffer as temp space,
   * since either the input block is buffer (in which case this is
   * just buffer ^= tweak) or it not, in which case we already read
   * and used the data there and are processing new input. Kind of
   * subtle/nasty, but saves allocating a distinct temp buf.
   */

   xor_buf(buffer, block, tweak, cipher->BLOCK_SIZE);
   cipher->encrypt(buffer);
   xor_buf(buffer, tweak, cipher->BLOCK_SIZE);

   poly_double(tweak, cipher->BLOCK_SIZE);

   send(buffer, cipher->BLOCK_SIZE);
   }

/*
* Encrypt in XTS mode
*/
void XTS_Encryption::write(const byte input[], u32bit length)
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   u32bit copied = std::min(buffer.size() - position, length);
   buffer.copy(position, input, copied);
   length -= copied;
   input += copied;
   position += copied;

   if(length == 0) return;

   encrypt(buffer);
   if(length > BLOCK_SIZE)
      {
      encrypt(buffer + BLOCK_SIZE);
      while(length > buffer.size())
         {
         encrypt(input);
         length -= BLOCK_SIZE;
         input += BLOCK_SIZE;
         }
      position = 0;
      }
   else
      {
      copy_mem(buffer.begin(), buffer + BLOCK_SIZE, BLOCK_SIZE);
      position = BLOCK_SIZE;
      }
   buffer.copy(position, input, length);
   position += length;
   }

/*
* Finish encrypting in XTS mode
*/
void XTS_Encryption::end_msg()
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   if(position < BLOCK_SIZE)
      throw Exception("XTS_Encryption: insufficient data to encrypt");
   else if(position == BLOCK_SIZE)
      {
      encrypt(buffer);
      }
   else if(position == 2*BLOCK_SIZE)
      {
      encrypt(buffer);
      encrypt(buffer + BLOCK_SIZE);
      }
   else
      { // steal ciphertext
      xor_buf(buffer, tweak, cipher->BLOCK_SIZE);
      cipher->encrypt(buffer);
      xor_buf(buffer, tweak, cipher->BLOCK_SIZE);

      poly_double(tweak, cipher->BLOCK_SIZE);

      for(u32bit i = 0; i != position - cipher->BLOCK_SIZE; ++i)
         std::swap(buffer[i], buffer[i + cipher->BLOCK_SIZE]);

      xor_buf(buffer, tweak, cipher->BLOCK_SIZE);
      cipher->encrypt(buffer);
      xor_buf(buffer, tweak, cipher->BLOCK_SIZE);

      send(buffer, position);
      }

   position = 0;
   }

/*
* XTS_Decryption constructor
*/
XTS_Decryption::XTS_Decryption(BlockCipher* ciph)
   {
   cipher = ciph;
   cipher2 = ciph->clone();
   tweak.create(cipher->BLOCK_SIZE);
   buffer.create(2 * cipher->BLOCK_SIZE);
   position = 0;
   }

/*
* XTS_Decryption constructor
*/
XTS_Decryption::XTS_Decryption(BlockCipher* ciph,
                               const SymmetricKey& key,
                               const InitializationVector& iv)
   {
   cipher = ciph;
   cipher2 = ciph->clone();
   tweak.create(cipher->BLOCK_SIZE);
   buffer.create(2 * cipher->BLOCK_SIZE);
   position = 0;

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
   if(iv.length() != tweak.size())
      throw Invalid_IV_Length(name(), iv.length());

   tweak = iv.bits_of();
   cipher2->encrypt(tweak);
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
* Decrypt a block
*/
void XTS_Decryption::decrypt(const byte block[])
   {
   xor_buf(buffer, block, tweak, cipher->BLOCK_SIZE);
   cipher->decrypt(buffer);
   xor_buf(buffer, tweak, cipher->BLOCK_SIZE);

   poly_double(tweak, cipher->BLOCK_SIZE);

   send(buffer, cipher->BLOCK_SIZE);
   }

/*
* Decrypt in XTS mode
*/
void XTS_Decryption::write(const byte input[], u32bit length)
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   u32bit copied = std::min(buffer.size() - position, length);
   buffer.copy(position, input, copied);
   length -= copied;
   input += copied;
   position += copied;

   if(length == 0) return;

   decrypt(buffer);
   if(length > BLOCK_SIZE)
      {
      decrypt(buffer + BLOCK_SIZE);
      while(length > 2*BLOCK_SIZE)
         {
         decrypt(input);
         length -= BLOCK_SIZE;
         input += BLOCK_SIZE;
         }
      position = 0;
      }
   else
      {
      copy_mem(buffer.begin(), buffer + BLOCK_SIZE, BLOCK_SIZE);
      position = BLOCK_SIZE;
      }
   buffer.copy(position, input, length);
   position += length;
   }

/*
* Finish decrypting in XTS mode
*/
void XTS_Decryption::end_msg()
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   if(position < BLOCK_SIZE)
      throw Exception("XTS_Decryption: insufficient data to decrypt");
   else if(position == BLOCK_SIZE)
      {
      decrypt(buffer);
      }
   else if(position == 2*BLOCK_SIZE)
      {
      decrypt(buffer);
      decrypt(buffer + BLOCK_SIZE);
      }
   else
      {
      SecureVector<byte> tweak2 = tweak;

      poly_double(tweak2, cipher->BLOCK_SIZE);

      xor_buf(buffer, tweak2, cipher->BLOCK_SIZE);
      cipher->decrypt(buffer);
      xor_buf(buffer, tweak2, cipher->BLOCK_SIZE);

      for(u32bit i = 0; i != position - cipher->BLOCK_SIZE; ++i)
         std::swap(buffer[i], buffer[i + cipher->BLOCK_SIZE]);

      xor_buf(buffer, tweak, cipher->BLOCK_SIZE);
      cipher->decrypt(buffer);
      xor_buf(buffer, tweak, cipher->BLOCK_SIZE);

      send(buffer, position);
      }

   position = 0;
   }

}
