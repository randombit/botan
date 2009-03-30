/*
* EAX Mode Encryption
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eax.h>
#include <botan/cmac.h>
#include <botan/xor_buf.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

namespace {

/*
* EAX MAC-based PRF
*/
SecureVector<byte> eax_prf(byte tag, u32bit BLOCK_SIZE,
                           MessageAuthenticationCode* mac,
                           const byte in[], u32bit length)
   {
   for(u32bit j = 0; j != BLOCK_SIZE - 1; ++j)
      mac->update(0);
   mac->update(tag);
   mac->update(in, length);
   return mac->final();
   }

}

/*
* EAX_Base Constructor
*/
EAX_Base::EAX_Base(BlockCipher* ciph,
                   u32bit tag_size) :
   TAG_SIZE(tag_size ? tag_size / 8 : ciph->BLOCK_SIZE),
   BLOCK_SIZE(ciph->BLOCK_SIZE)
   {
   cipher = ciph;
   mac = new CMAC(cipher->clone());

   if(tag_size % 8 != 0 || TAG_SIZE == 0 || TAG_SIZE > mac->OUTPUT_LENGTH)
      throw Invalid_Argument(name() + ": Bad tag size " + to_string(tag_size));

   state.create(BLOCK_SIZE);
   buffer.create(BLOCK_SIZE);
   position = 0;
   }

/*
* Check if a keylength is valid for EAX
*/
bool EAX_Base::valid_keylength(u32bit n) const
   {
   if(!cipher->valid_keylength(n))
      return false;
   if(!mac->valid_keylength(n))
      return false;
   return true;
   }

/*
* Set the EAX key
*/
void EAX_Base::set_key(const SymmetricKey& key)
   {
   cipher->set_key(key);
   mac->set_key(key);
   header_mac = eax_prf(1, BLOCK_SIZE, mac, 0, 0);
   }

/*
* Do setup at the start of each message
*/
void EAX_Base::start_msg()
   {
   for(u32bit j = 0; j != BLOCK_SIZE - 1; ++j)
      mac->update(0);
   mac->update(2);
   }

/*
* Set the EAX nonce
*/
void EAX_Base::set_iv(const InitializationVector& iv)
   {
   nonce_mac = eax_prf(0, BLOCK_SIZE, mac, iv.begin(), iv.length());
   state = nonce_mac;
   cipher->encrypt(state, buffer);
   }

/*
* Set the EAX header
*/
void EAX_Base::set_header(const byte header[], u32bit length)
   {
   header_mac = eax_prf(1, BLOCK_SIZE, mac, header, length);
   }

/*
* Return the name of this cipher mode
*/
std::string EAX_Base::name() const
   {
   return (cipher->name() + "/EAX");
   }

/*
* Increment the counter and update the buffer
*/
void EAX_Base::increment_counter()
   {
   for(s32bit j = BLOCK_SIZE - 1; j >= 0; --j)
      if(++state[j])
         break;
   cipher->encrypt(state, buffer);
   position = 0;
   }

/*
* Encrypt in EAX mode
*/
void EAX_Encryption::write(const byte input[], u32bit length)
   {
   u32bit copied = std::min(BLOCK_SIZE - position, length);
   xor_buf(buffer + position, input, copied);
   send(buffer + position, copied);
   mac->update(buffer + position, copied);
   input += copied;
   length -= copied;
   position += copied;

   if(position == BLOCK_SIZE)
      increment_counter();

   while(length >= BLOCK_SIZE)
      {
      xor_buf(buffer, input, BLOCK_SIZE);
      send(buffer, BLOCK_SIZE);
      mac->update(buffer, BLOCK_SIZE);

      input += BLOCK_SIZE;
      length -= BLOCK_SIZE;
      increment_counter();
      }

   xor_buf(buffer + position, input, length);
   send(buffer + position, length);
   mac->update(buffer + position, length);
   position += length;
   }

/*
* Finish encrypting in EAX mode
*/
void EAX_Encryption::end_msg()
   {
   SecureVector<byte> data_mac = mac->final();
   xor_buf(data_mac, nonce_mac, data_mac.size());
   xor_buf(data_mac, header_mac, data_mac.size());

   send(data_mac, TAG_SIZE);

   state.clear();
   buffer.clear();
   position = 0;
   }

}
