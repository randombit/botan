/*
* ECB Mode
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecb.h>

namespace Botan {

/*
* ECB_Encryption Constructor
*/
ECB_Encryption::ECB_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad) :
   Buffered_Filter(ciph->parallel_bytes(), 0)
   {
   cipher = ciph;
   padder = pad;

   temp.resize(buffered_block_size());
   }

/*
* ECB_Encryption Constructor
*/
ECB_Encryption::ECB_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key) :
   Buffered_Filter(ciph->parallel_bytes(), 0)
   {
   cipher = ciph;
   padder = pad;

   temp.resize(buffered_block_size());

   cipher->set_key(key);
   }

/*
* ECB_Encryption Destructor
*/
ECB_Encryption::~ECB_Encryption()
   {
   delete cipher;
   delete padder;
   }

/*
* Return an ECB mode name
*/
std::string ECB_Encryption::name() const
   {
   return (cipher->name() + "/ECB/" + padder->name());
   }

/*
* Encrypt in ECB mode
*/
void ECB_Encryption::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }

/*
* Finish encrypting in ECB mode
*/
void ECB_Encryption::end_msg()
   {
   size_t last_block = current_position() % cipher->block_size();

   SecureVector<byte> padding(cipher->block_size());
   padder->pad(padding, padding.size(), last_block);

   size_t pad_bytes = padder->pad_bytes(cipher->block_size(), last_block);

   if(pad_bytes)
      Buffered_Filter::write(padding, pad_bytes);
   Buffered_Filter::end_msg();
   }

void ECB_Encryption::buffered_block(const byte input[], size_t input_length)
   {
   const size_t blocks_in_temp = temp.size() / cipher->block_size();
   size_t blocks = input_length / cipher->block_size();

   while(blocks)
      {
      size_t to_proc = std::min(blocks, blocks_in_temp);

      cipher->encrypt_n(input, &temp[0], to_proc);

      send(temp, to_proc * cipher->block_size());

      input += to_proc * cipher->block_size();
      blocks -= to_proc;
      }
   }

void ECB_Encryption::buffered_final(const byte input[], size_t input_length)
   {
   if(input_length % cipher->block_size() == 0)
      buffered_block(input, input_length);
   else if(input_length != 0)
      throw Encoding_Error(name() + ": Did not pad to full blocksize");
   }

/*
* ECB_Decryption Constructor
*/
ECB_Decryption::ECB_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad) :
   Buffered_Filter(ciph->parallel_bytes(), 1)
   {
   cipher = ciph;
   padder = pad;

   temp.resize(buffered_block_size());
   }

/*
* ECB_Decryption Constructor
*/
ECB_Decryption::ECB_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key) :
   Buffered_Filter(ciph->parallel_bytes(), 1)
   {
   cipher = ciph;
   padder = pad;

   temp.resize(buffered_block_size());

   cipher->set_key(key);
   }

/*
* ECB_Decryption Destructor
*/
ECB_Decryption::~ECB_Decryption()
   {
   delete cipher;
   delete padder;
   }

/*
* Return an ECB mode name
*/
std::string ECB_Decryption::name() const
   {
   return (cipher->name() + "/ECB/" + padder->name());
   }

/*
* Decrypt in ECB mode
*/
void ECB_Decryption::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }

/*
* Finish decrypting in ECB mode
*/
void ECB_Decryption::end_msg()
   {
   Buffered_Filter::end_msg();
   }

/*
* Decrypt in ECB mode
*/
void ECB_Decryption::buffered_block(const byte input[], size_t length)
   {
   const size_t blocks_in_temp = temp.size() / cipher->block_size();
   size_t blocks = length / cipher->block_size();

   while(blocks)
      {
      size_t to_proc = std::min(blocks, blocks_in_temp);

      cipher->decrypt_n(input, &temp[0], to_proc);

      send(temp, to_proc * cipher->block_size());

      input += to_proc * cipher->block_size();
      blocks -= to_proc;
      }
   }

/*
* Finish encrypting in ECB mode
*/
void ECB_Decryption::buffered_final(const byte input[], size_t length)
   {
   if(length == 0 || length % cipher->block_size() != 0)
      throw Decoding_Error(name() + ": Ciphertext not multiple of block size");

   size_t extra_blocks = (length - 1) / cipher->block_size();

   buffered_block(input, extra_blocks * cipher->block_size());

   input += extra_blocks * cipher->block_size();

   cipher->decrypt(input, temp);
   send(temp, padder->unpad(temp, cipher->block_size()));
   }

}
