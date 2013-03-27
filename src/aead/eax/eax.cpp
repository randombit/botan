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
secure_vector<byte> eax_prf(byte tag, size_t block_size,
                           MessageAuthenticationCode& mac,
                           const byte in[], size_t length)
   {
   for(size_t i = 0; i != block_size - 1; ++i)
      mac.update(0);
   mac.update(tag);
   mac.update(in, length);
   return mac.final();
   }

}

/*
* EAX_Mode Constructor
*/
EAX_Mode::EAX_Mode(BlockCipher* cipher, size_t tag_size) :
   m_tag_size(tag_size),
   m_cipher(cipher),
   m_ctr(new CTR_BE(m_cipher->clone())),
   m_cmac(new CMAC(m_cipher->clone()))
   {
   if(tag_size < 8 || tag_size > m_cmac->output_length())
      throw Invalid_Argument(name() + ": Bad tag size " + std::to_string(tag_size));
   }

void EAX_Mode::clear()
   {
   m_cipher.reset();
   m_ctr.reset();
   m_cmac.reset();
   zeroise(m_ad_mac);
   zeroise(m_nonce_mac);
   }

std::string EAX_Mode::name() const
   {
   return (m_cipher->name() + "/EAX");
   }

size_t EAX_Mode::update_granularity() const
   {
   return 8 * m_cipher->parallel_bytes();
   }

Key_Length_Specification EAX_Mode::key_spec() const
   {
   return m_cipher->key_spec();
   }

/*
* Set the EAX key
*/
void EAX_Mode::key_schedule(const byte key[], size_t length)
   {
   /*
   * These could share the key schedule, which is one nice part of EAX,
   * but it's much easier to ignore that here...
   */
   m_ctr->set_key(key, length);
   m_cmac->set_key(key, length);

   m_ad_mac = eax_prf(1, block_size(), *m_cmac, nullptr, 0);
   }

/*
* Set the EAX associated data
*/
void EAX_Mode::set_associated_data(const byte ad[], size_t length)
   {
   m_ad_mac = eax_prf(1, block_size(), *m_cmac, ad, length);
   }

secure_vector<byte> EAX_Mode::start(const byte nonce[], size_t nonce_len)
   {
   m_nonce_mac = eax_prf(0, block_size(), *m_cmac, nonce, nonce_len);

   m_ctr->set_iv(&m_nonce_mac[0], m_nonce_mac.size());

   for(size_t i = 0; i != block_size() - 1; ++i)
      m_cmac->update(0);
   m_cmac->update(2);

   return secure_vector<byte>();
   }

void EAX_Encryption::update(secure_vector<byte>& buffer)
   {
   m_ctr->cipher(&buffer[0], &buffer[0], buffer.size());
   m_cmac->update(&buffer[0], buffer.size());
   }

void EAX_Encryption::finish(secure_vector<byte>& buffer)
   {
   update(buffer);

   secure_vector<byte> data_mac = m_cmac->final();
   xor_buf(data_mac, m_nonce_mac, data_mac.size());
   xor_buf(data_mac, m_ad_mac, data_mac.size());

   buffer += std::make_pair(&data_mac[0], tag_size());
   }

void EAX_Decryption::update(secure_vector<byte>& buffer)
   {
   m_cmac->update(&buffer[0], buffer.size());
   m_ctr->cipher(&buffer[0], &buffer[0], buffer.size());
   }

void EAX_Decryption::finish(secure_vector<byte>& buffer)
   {
   BOTAN_ASSERT(buffer.size() >= tag_size(),
                "Have the tag as part of final input");

   const size_t remaining = buffer.size() - tag_size();

   if(remaining) // handle any remaining input
      {
      m_cmac->update(&buffer[0], remaining);
      m_ctr->cipher(&buffer[0], &buffer[0], remaining);
      }

   const byte* included_tag = &buffer[remaining];

   secure_vector<byte> mac = m_cmac->final();
   mac ^= m_nonce_mac;
   mac ^= m_ad_mac;

   if(!same_mem(&mac[0], included_tag, tag_size()))
      throw Integrity_Failure("EAX tag check failed");

   buffer.resize(remaining);
   }

}
