/*
* EAX Mode Encryption
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eax.h>
#include <botan/cmac.h>
#include <botan/ctr.h>
#include <botan/parsing.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* EAX MAC-based PRF
*/
secure_vector<byte> eax_prf(byte tag, size_t BLOCK_SIZE,
                           MessageAuthenticationCode& mac,
                           const byte in[], size_t length)
   {
   for(size_t i = 0; i != BLOCK_SIZE - 1; ++i)
      mac.update(0);
   mac.update(tag);
   mac.update(in, length);
   return mac.final();
   }

size_t eax_tag_size(size_t tag_size, const BlockCipher& cipher)
   {
   if(tag_size == 0)
      return cipher.block_size();
   return (tag_size / 8);
   }

}

/*
* EAX_Mode Constructor
*/
EAX_Mode::EAX_Mode(BlockCipher* cipher, size_t tag_size, bool decrypting) :
   Buffered_Filter(cipher->parallel_bytes(),
                   decrypting ? eax_tag_size(tag_size, *cipher) : 0),
   BLOCK_SIZE(cipher->block_size()),
   TAG_SIZE(eax_tag_size(tag_size, *cipher)),
   cipher_name(cipher->name()),
   ctr_buf(DEFAULT_BUFFERSIZE)
   {
   cmac.reset(new CMAC(cipher->clone()));
   ctr.reset(new CTR_BE(cipher)); // CTR_BE takes ownership of cipher

   if(tag_size % 8 != 0 || TAG_SIZE == 0 || TAG_SIZE > cmac->output_length())
      throw Invalid_Argument(name() + ": Bad tag size " + std::to_string(tag_size));
   }

/*
* Set the EAX key
*/
void EAX_Mode::set_key(const SymmetricKey& key)
   {
   /*
   * These could share the key schedule, which is one nice part of EAX,
   * but it's much easier to ignore that here...
   */
   ctr->set_key(key);
   cmac->set_key(key);

   ad_mac = eax_prf(1, BLOCK_SIZE, *cmac, nullptr, 0);
   }

/*
* Do setup at the start of each message
*/
void EAX_Mode::start_msg()
   {
   for(size_t i = 0; i != BLOCK_SIZE - 1; ++i)
      cmac->update(0);
   cmac->update(2);
   }

/*
* Set the EAX nonce
*/
void EAX_Mode::set_nonce(const byte nonce[], size_t nonce_len)
   {
   nonce_mac = eax_prf(0, BLOCK_SIZE, *cmac, nonce, nonce_len);
   ctr->set_iv(&nonce_mac[0], nonce_mac.size());
   }

/*
* Set the EAX associated data
*/
void EAX_Mode::set_associated_data(const byte ad[], size_t length)
   {
   ad_mac = eax_prf(1, BLOCK_SIZE, *cmac, ad, length);
   }

/*
* Return the name of this cipher mode
*/
std::string EAX_Mode::name() const
   {
   return (cipher_name + "/EAX");
   }

void EAX_Mode::write(const byte input[], size_t length)
   {
   Buffered_Filter::write(input, length);
   }

void EAX_Mode::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void EAX_Encryption::buffered_block(const byte input[], size_t length)
   {
   while(length)
      {
      size_t copied = std::min<size_t>(length, ctr_buf.size());

      ctr->cipher(input, &ctr_buf[0], copied);
      cmac->update(&ctr_buf[0], copied);

      send(ctr_buf, copied);

      input += copied;
      length -= copied;
      }
   }

void EAX_Encryption::buffered_final(const byte input[], size_t input_length)
   {
   buffered_block(input, input_length);

   secure_vector<byte> data_mac = cmac->final();
   xor_buf(data_mac, nonce_mac, data_mac.size());
   xor_buf(data_mac, ad_mac, data_mac.size());

   send(data_mac, TAG_SIZE);
   }

void EAX_Decryption::buffered_block(const byte input[], size_t length)
   {
   cmac->update(&input[0], length);

   while(length)
      {
      size_t copied = std::min<size_t>(length, ctr_buf.size());

      ctr->cipher(input, &ctr_buf[0], copied);

      send(ctr_buf, copied);

      input += copied;
      length -= copied;
      }
   }

void EAX_Decryption::buffered_final(const byte input[], size_t input_length)
   {
   BOTAN_ASSERT(input_length >= TAG_SIZE, "Have the tag as part of final input");

   const byte* included_tag = &input[input_length - TAG_SIZE];
   input_length -= TAG_SIZE;

   if(input_length) // handle any remaining input
      buffered_block(input, input_length);

   secure_vector<byte> mac = cmac->final();
   mac ^= nonce_mac;
   mac ^= ad_mac;

   if(!same_mem(&mac[0], included_tag, TAG_SIZE))
      throw Integrity_Failure("EAX tag check failed");
   }


}
