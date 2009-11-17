/*
* ECB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ecb.h>

namespace Botan {

namespace {

const u32bit PARALLEL_BLOCKS = BOTAN_PARALLEL_BLOCKS_ECB;

}

/*
* ECB_Encryption Constructor
*/
ECB_Encryption::ECB_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad)
   {
   cipher = ciph;
   padder = pad;

   plaintext.resize(cipher->BLOCK_SIZE);
   ciphertext.resize(cipher->BLOCK_SIZE * PARALLEL_BLOCKS);

   position = 0;
   }

/*
* ECB_Encryption Constructor
*/
ECB_Encryption::ECB_Encryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key)
   {
   cipher = ciph;
   padder = pad;

   plaintext.resize(cipher->BLOCK_SIZE);
   ciphertext.resize(cipher->BLOCK_SIZE * PARALLEL_BLOCKS);

   position = 0;

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
void ECB_Encryption::write(const byte input[], u32bit length)
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   if(position)
      {
      plaintext.copy(position, input, length);

      if(position + length >= BLOCK_SIZE)
         {
         cipher->encrypt(plaintext, ciphertext);
         send(ciphertext, BLOCK_SIZE);
         input += (BLOCK_SIZE - position);
         length -= (BLOCK_SIZE - position);
         position = 0;
         }
      }

   while(length >= BLOCK_SIZE)
      {
      const u32bit to_proc =
         std::min<u32bit>(length, ciphertext.size()) / BLOCK_SIZE;

      cipher->encrypt_n(input, ciphertext, to_proc);
      send(ciphertext, to_proc * BLOCK_SIZE);
      input += to_proc * BLOCK_SIZE;
      length -= to_proc * BLOCK_SIZE;
      }

   plaintext.copy(position, input, length);
   position += length;
   }

/*
* Finish encrypting in ECB mode
*/
void ECB_Encryption::end_msg()
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   SecureVector<byte> padding(BLOCK_SIZE);
   padder->pad(padding, padding.size(), position);
   write(padding, padder->pad_bytes(BLOCK_SIZE, position));
   if(position != 0)
      throw Encoding_Error(name() + ": Did not pad to full blocksize");
   }

/*
* ECB_Decryption Constructor
*/
ECB_Decryption::ECB_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad)
   {
   cipher = ciph;
   padder = pad;

   ciphertext.resize(cipher->BLOCK_SIZE);
   plaintext.resize(cipher->BLOCK_SIZE * PARALLEL_BLOCKS);

   position = 0;
   }

/*
* ECB_Decryption Constructor
*/
ECB_Decryption::ECB_Decryption(BlockCipher* ciph,
                               BlockCipherModePaddingMethod* pad,
                               const SymmetricKey& key)
   {
   cipher = ciph;
   padder = pad;

   ciphertext.resize(cipher->BLOCK_SIZE);
   plaintext.resize(cipher->BLOCK_SIZE * PARALLEL_BLOCKS);

   position = 0;

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
void ECB_Decryption::write(const byte input[], u32bit length)
   {
   const u32bit BLOCK_SIZE = cipher->BLOCK_SIZE;

   if(position)
      {
      ciphertext.copy(position, input, length);

      if(position + length > BLOCK_SIZE)
         {
         cipher->decrypt(ciphertext, plaintext);
         send(plaintext, BLOCK_SIZE);
         input += (BLOCK_SIZE - position);
         length -= (BLOCK_SIZE - position);
         position = 0;
         }
      }

   while(length > BLOCK_SIZE)
      {
      /* Always leave at least 1 byte left over, to ensure that (as long
         as the input message actually is a multiple of the block size)
         we will have the full final block left over in end_msg so as
         to remove the padding
      */
      const u32bit to_proc =
         std::min<u32bit>(length - 1, plaintext.size()) / BLOCK_SIZE;

      cipher->decrypt_n(input, plaintext, to_proc);
      send(plaintext, to_proc * BLOCK_SIZE);
      input += to_proc * BLOCK_SIZE;
      length -= to_proc * BLOCK_SIZE;
      }

   ciphertext.copy(position, input, length);
   position += length;
   }

/*
* Finish decrypting in ECB mode
*/
void ECB_Decryption::end_msg()
   {
   if(position != cipher->BLOCK_SIZE)
      throw Decoding_Error(name());

   cipher->decrypt(ciphertext);
   send(ciphertext, padder->unpad(ciphertext, cipher->BLOCK_SIZE));
   position = 0;
   }

}
