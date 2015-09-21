/*
* Filters
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>
#include <algorithm>

namespace Botan {

StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher) :
   m_buffer(DEFAULT_BUFFERSIZE),
   m_cipher(cipher)
   {
   }

StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher, const SymmetricKey& key) :
   m_buffer(DEFAULT_BUFFERSIZE),
   m_cipher(cipher)
   {
   m_cipher->set_key(key);
   }

StreamCipher_Filter::StreamCipher_Filter(const std::string& sc_name) :
   m_buffer(DEFAULT_BUFFERSIZE),
   m_cipher(StreamCipher::create(sc_name))
   {
   if(!m_cipher)
      throw Algorithm_Not_Found(sc_name);
   }

StreamCipher_Filter::StreamCipher_Filter(const std::string& sc_name, const SymmetricKey& key) :
   m_buffer(DEFAULT_BUFFERSIZE),
   m_cipher(StreamCipher::create(sc_name))
   {
   if(!m_cipher)
      throw Algorithm_Not_Found(sc_name);
   m_cipher->set_key(key);
   }

void StreamCipher_Filter::write(const byte input[], size_t length)
   {
   while(length)
      {
      size_t copied = std::min<size_t>(length, m_buffer.size());
      m_cipher->cipher(input, m_buffer.data(), copied);
      send(m_buffer, copied);
      input += copied;
      length -= copied;
      }
   }

Hash_Filter::Hash_Filter(const std::string& hash_name, size_t len) :
   m_hash(HashFunction::create(hash_name)),
   m_out_len(len)
   {
   if(!m_hash)
      throw Algorithm_Not_Found(hash_name);
   }
void Hash_Filter::end_msg()   {
   secure_vector<byte> output = m_hash->final();
   if(m_out_len)
      send(output, std::min<size_t>(m_out_len, output.size()));
   else
      send(output);
   }

MAC_Filter::MAC_Filter(const std::string& mac_name, size_t len) :
   m_mac(MessageAuthenticationCode::create(mac_name)),
   m_out_len(len)
   {
   if(!m_mac)
      throw Algorithm_Not_Found(mac_name);
   }

MAC_Filter::MAC_Filter(const std::string& mac_name, const SymmetricKey& key, size_t len) :
   m_mac(MessageAuthenticationCode::create(mac_name)),
   m_out_len(len)
   {
   if(!m_mac)
      throw Algorithm_Not_Found(mac_name);
   m_mac->set_key(key);
   }

void MAC_Filter::end_msg()
   {
   secure_vector<byte> output = m_mac->final();
   if(m_out_len)
      send(output, std::min<size_t>(m_out_len, output.size()));
   else
      send(output);
   }

}
