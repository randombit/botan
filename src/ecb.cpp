/*************************************************
* ECB Mode Source File                           *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/ecb.h>
#include <botan/lookup.h>

namespace Botan {

/*************************************************
* ECB Constructor                                *
*************************************************/
ECB::ECB(const std::string& cipher_name, const std::string& padding_name) :
   BlockCipherMode(cipher_name, "ECB", 0), padder(get_bc_pad(padding_name))
   {
   }

/*************************************************
* Verify the IV is not set                       *
*************************************************/
bool ECB::valid_iv_size(u32bit iv_size) const
   {
   if(iv_size == 0)
      return true;
   return false;
   }

/*************************************************
* Return an ECB mode name                        *
*************************************************/
std::string ECB::name() const
   {
   return (cipher->name() + "/" + mode_name + "/" + padder->name());
   }

/*************************************************
* ECB Encryption Constructor                     *
*************************************************/
ECB_Encryption::ECB_Encryption(const std::string& cipher_name,
                               const std::string& padding_name) :
   ECB(cipher_name, padding_name)
   {
   }

/*************************************************
* ECB Encryption Constructor                     *
*************************************************/
ECB_Encryption::ECB_Encryption(const std::string& cipher_name,
                               const std::string& padding_name,
                               const SymmetricKey& key) :
   ECB(cipher_name, padding_name)
   {
   set_key(key);
   }

/*************************************************
* Encrypt in ECB mode                            *
*************************************************/
void ECB_Encryption::write(const byte input[], u32bit length)
   {
   buffer.copy(position, input, length);
   if(position + length >= BLOCK_SIZE)
      {
      cipher->encrypt(buffer);
      send(buffer, BLOCK_SIZE);
      input += (BLOCK_SIZE - position);
      length -= (BLOCK_SIZE - position);
      while(length >= BLOCK_SIZE)
         {
         cipher->encrypt(input, buffer);
         send(buffer, BLOCK_SIZE);
         input += BLOCK_SIZE;
         length -= BLOCK_SIZE;
         }
      buffer.copy(input, length);
      position = 0;
      }
   position += length;
   }

/*************************************************
* Finish encrypting in ECB mode                  *
*************************************************/
void ECB_Encryption::end_msg()
   {
   SecureVector<byte> padding(BLOCK_SIZE);
   padder->pad(padding, padding.size(), position);
   write(padding, padder->pad_bytes(BLOCK_SIZE, position));
   if(position != 0)
      throw Encoding_Error(name() + ": Did not pad to full blocksize");
   }

/*************************************************
* ECB Decryption Constructor                     *
*************************************************/
ECB_Decryption::ECB_Decryption(const std::string& cipher_name,
                               const std::string& padding_name) :
   ECB(cipher_name, padding_name)
   {
   }

/*************************************************
* ECB Decryption Constructor                     *
*************************************************/
ECB_Decryption::ECB_Decryption(const std::string& cipher_name,
                               const std::string& padding_name,
                               const SymmetricKey& key) :
   ECB(cipher_name, padding_name)
   {
   set_key(key);
   }

/*************************************************
* Decrypt in ECB mode                            *
*************************************************/
void ECB_Decryption::write(const byte input[], u32bit length)
   {
   buffer.copy(position, input, length);
   if(position + length > BLOCK_SIZE)
      {
      cipher->decrypt(buffer);
      send(buffer, BLOCK_SIZE);
      input += (BLOCK_SIZE - position);
      length -= (BLOCK_SIZE - position);
      while(length > BLOCK_SIZE)
         {
         cipher->decrypt(input, buffer);
         send(buffer, BLOCK_SIZE);
         input += BLOCK_SIZE;
         length -= BLOCK_SIZE;
         }
      buffer.copy(input, length);
      position = 0;
      }
   position += length;
   }

/*************************************************
* Finish decrypting in ECB mode                  *
*************************************************/
void ECB_Decryption::end_msg()
   {
   if(position != BLOCK_SIZE)
      throw Decoding_Error(name());
   cipher->decrypt(buffer);
   send(buffer, padder->unpad(buffer, BLOCK_SIZE));
   state = buffer;
   position = 0;
   }

}
