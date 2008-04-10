/*************************************************
* EAX Mode Source File                           *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/eax.h>
#include <botan/lookup.h>
#include <botan/bit_ops.h>
#include <botan/parsing.h>
#include <algorithm>

namespace Botan {

namespace {

/*************************************************
* EAX MAC-based PRF                              *
*************************************************/
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

/*************************************************
* EAX_Base Constructor                           *
*************************************************/
EAX_Base::EAX_Base(const std::string& cipher_name,
                   u32bit tag_size) :
   TAG_SIZE(tag_size ? tag_size / 8 : block_size_of(cipher_name)),
   BLOCK_SIZE(block_size_of(cipher_name))
   {
   const std::string mac_name = "CMAC(" + cipher_name + ")";

   cipher = get_block_cipher(cipher_name);
   mac = get_mac(mac_name);

   if(tag_size % 8 != 0 || TAG_SIZE == 0 || TAG_SIZE > mac->OUTPUT_LENGTH)
      throw Invalid_Argument(name() + ": Bad tag size " + to_string(tag_size));

   state.create(BLOCK_SIZE);
   buffer.create(BLOCK_SIZE);
   position = 0;
   }

/*************************************************
* Check if a keylength is valid for EAX          *
*************************************************/
bool EAX_Base::valid_keylength(u32bit n) const
   {
   if(!cipher->valid_keylength(n))
      return false;
   if(!mac->valid_keylength(n))
      return false;
   return true;
   }

/*************************************************
* Set the EAX key                                *
*************************************************/
void EAX_Base::set_key(const SymmetricKey& key)
   {
   cipher->set_key(key);
   mac->set_key(key);
   header_mac = eax_prf(1, BLOCK_SIZE, mac, 0, 0);
   }

/*************************************************
* Do setup at the start of each message          *
*************************************************/
void EAX_Base::start_msg()
   {
   for(u32bit j = 0; j != BLOCK_SIZE - 1; ++j)
      mac->update(0);
   mac->update(2);
   }

/*************************************************
* Set the EAX nonce                              *
*************************************************/
void EAX_Base::set_iv(const InitializationVector& iv)
   {
   nonce_mac = eax_prf(0, BLOCK_SIZE, mac, iv.begin(), iv.length());
   state = nonce_mac;
   cipher->encrypt(state, buffer);
   }

/*************************************************
* Set the EAX header                             *
*************************************************/
void EAX_Base::set_header(const byte header[], u32bit length)
   {
   header_mac = eax_prf(1, BLOCK_SIZE, mac, header, length);
   }

/*************************************************
* Return the name of this cipher mode            *
*************************************************/
std::string EAX_Base::name() const
   {
   return (cipher->name() + "/EAX");
   }

/*************************************************
* Increment the counter and update the buffer    *
*************************************************/
void EAX_Base::increment_counter()
   {
   for(s32bit j = BLOCK_SIZE - 1; j >= 0; --j)
      if(++state[j])
         break;
   cipher->encrypt(state, buffer);
   position = 0;
   }

/*************************************************
* EAX_Encryption Constructor                     *
*************************************************/
EAX_Encryption::EAX_Encryption(const std::string& cipher_name,
                               u32bit tag_size) :
   EAX_Base(cipher_name, tag_size)
   {
   }

/*************************************************
* EAX_Encryption Constructor                     *
*************************************************/
EAX_Encryption::EAX_Encryption(const std::string& cipher_name,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               u32bit tag_size) :
   EAX_Base(cipher_name, tag_size)
   {
   set_key(key);
   set_iv(iv);
   }

/*************************************************
* Encrypt in EAX mode                            *
*************************************************/
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

/*************************************************
* Finish encrypting in EAX mode                  *
*************************************************/
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

/*************************************************
* EAX_Decryption Constructor                     *
*************************************************/
EAX_Decryption::EAX_Decryption(const std::string& cipher_name,
                               u32bit tag_size) :
   EAX_Base(cipher_name, tag_size)
   {
   queue.create(2*TAG_SIZE + DEFAULT_BUFFERSIZE);
   queue_start = queue_end = 0;
   }

/*************************************************
* EAX_Decryption Constructor                     *
*************************************************/
EAX_Decryption::EAX_Decryption(const std::string& cipher_name,
                               const SymmetricKey& key,
                               const InitializationVector& iv,
                               u32bit tag_size) :
   EAX_Base(cipher_name, tag_size)
   {
   set_key(key);
   set_iv(iv);
   queue.create(2*TAG_SIZE + DEFAULT_BUFFERSIZE);
   queue_start = queue_end = 0;
   }

/*************************************************
* Decrypt in EAX mode                            *
*************************************************/
void EAX_Decryption::write(const byte input[], u32bit length)
   {
   while(length)
      {
      const u32bit copied = std::min(length, queue.size() - queue_end);

      queue.copy(queue_end, input, copied);
      input += copied;
      length -= copied;
      queue_end += copied;

      SecureVector<byte> block_buf(cipher->BLOCK_SIZE);
      while((queue_end - queue_start) > TAG_SIZE)
         {
         u32bit removed = (queue_end - queue_start) - TAG_SIZE;
         do_write(queue + queue_start, removed);
         queue_start += removed;
         }

      if(queue_start + TAG_SIZE == queue_end &&
         queue_start >= queue.size() / 2)
         {
         SecureVector<byte> queue_data(TAG_SIZE);
         queue_data.copy(queue + queue_start, TAG_SIZE);
         queue.copy(queue_data, TAG_SIZE);
         queue_start = 0;
         queue_end = TAG_SIZE;
         }
      }
   }

/*************************************************
* Decrypt in EAX mode                            *
*************************************************/
void EAX_Decryption::do_write(const byte input[], u32bit length)
   {
   mac->update(input, length);

   u32bit copied = std::min(BLOCK_SIZE - position, length);
   xor_buf(buffer + position, input, copied);
   send(buffer + position, copied);
   input += copied;
   length -= copied;
   position += copied;

   if(position == BLOCK_SIZE)
      increment_counter();

   while(length >= BLOCK_SIZE)
      {
      xor_buf(buffer, input, BLOCK_SIZE);
      send(buffer, BLOCK_SIZE);

      input += BLOCK_SIZE;
      length -= BLOCK_SIZE;
      increment_counter();
      }

   xor_buf(buffer + position, input, length);
   send(buffer + position, length);
   position += length;
   }

/*************************************************
* Finish decrypting in EAX mode                  *
*************************************************/
void EAX_Decryption::end_msg()
   {
   if((queue_end - queue_start) != TAG_SIZE)
      throw Integrity_Failure(name() + ": Message authentication failure");

   SecureVector<byte> data_mac = mac->final();

   for(u32bit j = 0; j != TAG_SIZE; ++j)
      if(queue[queue_start+j] != (data_mac[j] ^ nonce_mac[j] ^ header_mac[j]))
         throw Integrity_Failure(name() + ": Message authentication failure");

   state.clear();
   buffer.clear();
   position = 0;
   queue_start = queue_end = 0;
   }

}
