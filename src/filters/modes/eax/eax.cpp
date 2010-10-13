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
SecureVector<byte> eax_prf(byte tag, size_t BLOCK_SIZE,
                           MessageAuthenticationCode* mac,
                           const byte in[], size_t length)
   {
   for(size_t i = 0; i != BLOCK_SIZE - 1; ++i)
      mac->update(0);
   mac->update(tag);
   mac->update(in, length);
   return mac->final();
   }

}

/*
* EAX_Base Constructor
*/
EAX_Base::EAX_Base(BlockCipher* cipher, size_t tag_size) :
   BLOCK_SIZE(cipher->block_size()),
   TAG_SIZE(tag_size ? tag_size / 8 : BLOCK_SIZE),
   cipher_name(cipher->name()),
   ctr_buf(DEFAULT_BUFFERSIZE)
   {
   cmac = new CMAC(cipher->clone());
   ctr = new CTR_BE(cipher); // takes ownership

   if(tag_size % 8 != 0 || TAG_SIZE == 0 || TAG_SIZE > cmac->output_length())
      throw Invalid_Argument(name() + ": Bad tag size " + to_string(tag_size));
   }

/*
* Check if a keylength is valid for EAX
*/
bool EAX_Base::valid_keylength(size_t n) const
   {
   if(!ctr->valid_keylength(n))
      return false;
   return true;
   }

/*
* Set the EAX key
*/
void EAX_Base::set_key(const SymmetricKey& key)
   {
   /*
   * These could share the key schedule, which is one nice part of EAX,
   * but it's much easier to ignore that here...
   */
   ctr->set_key(key);
   cmac->set_key(key);

   header_mac = eax_prf(1, BLOCK_SIZE, cmac, 0, 0);
   }

/*
* Do setup at the start of each message
*/
void EAX_Base::start_msg()
   {
   for(size_t i = 0; i != BLOCK_SIZE - 1; ++i)
      cmac->update(0);
   cmac->update(2);
   }

/*
* Set the EAX nonce
*/
void EAX_Base::set_iv(const InitializationVector& iv)
   {
   nonce_mac = eax_prf(0, BLOCK_SIZE, cmac, iv.begin(), iv.length());
   ctr->set_iv(&nonce_mac[0], nonce_mac.size());
   }

/*
* Set the EAX header
*/
void EAX_Base::set_header(const byte header[], size_t length)
   {
   header_mac = eax_prf(1, BLOCK_SIZE, cmac, header, length);
   }

/*
* Return the name of this cipher mode
*/
std::string EAX_Base::name() const
   {
   return (cipher_name + "/EAX");
   }

/*
* Encrypt in EAX mode
*/
void EAX_Encryption::write(const byte input[], size_t length)
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

/*
* Finish encrypting in EAX mode
*/
void EAX_Encryption::end_msg()
   {
   SecureVector<byte> data_mac = cmac->final();
   xor_buf(data_mac, nonce_mac, data_mac.size());
   xor_buf(data_mac, header_mac, data_mac.size());

   send(data_mac, TAG_SIZE);
   }

}
