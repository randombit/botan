/*
* Filters
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>
#include <botan/algo_registry.h>
#include <algorithm>

namespace Botan {

/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher) :
   buffer(DEFAULT_BUFFERSIZE), m_cipher(cipher)
   {
   }

/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher,
                                         const SymmetricKey& key) :
   buffer(DEFAULT_BUFFERSIZE),
   m_cipher(cipher)
   {
   m_cipher->set_key(key);
   }

/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(const std::string& sc_name) :
   buffer(DEFAULT_BUFFERSIZE)
   {
   m_cipher.reset(Algo_Registry<StreamCipher>::global_registry().make(sc_name));
   }

/*
* StreamCipher_Filter Constructor
*/
StreamCipher_Filter::StreamCipher_Filter(const std::string& sc_name,
                                         const SymmetricKey& key) :
   buffer(DEFAULT_BUFFERSIZE)
   {
   m_cipher.reset(Algo_Registry<StreamCipher>::global_registry().make(sc_name));
   m_cipher->set_key(key);
   }

/*
* Set the IV of a stream cipher
*/
void StreamCipher_Filter::set_iv(const InitializationVector& iv)
   {
   m_cipher->set_iv(iv.begin(), iv.length());
   }

/*
* Write data into a StreamCipher_Filter
*/
void StreamCipher_Filter::write(const byte input[], size_t length)
   {
   while(length)
      {
      size_t copied = std::min<size_t>(length, buffer.size());
      m_cipher->cipher(input, &buffer[0], copied);
      send(buffer, copied);
      input += copied;
      length -= copied;
      }
   }

/*
* Hash_Filter Constructor
*/
Hash_Filter::Hash_Filter(const std::string& algo_spec,
                         size_t len) :
   OUTPUT_LENGTH(len)
   {
   m_hash.reset(Algo_Registry<HashFunction>::global_registry().make(algo_spec));
   }

/*
* Complete a calculation by a Hash_Filter
*/
void Hash_Filter::end_msg()
   {
   secure_vector<byte> output = m_hash->final();
   if(OUTPUT_LENGTH)
      send(output, std::min<size_t>(OUTPUT_LENGTH, output.size()));
   else
      send(output);
   }

/*
* MAC_Filter Constructor
*/
MAC_Filter::MAC_Filter(const std::string& mac_name, size_t len) :
   OUTPUT_LENGTH(len)
   {
   m_mac.reset(Algo_Registry<MessageAuthenticationCode>::global_registry().make(mac_name));
   }

/*
* MAC_Filter Constructor
*/
MAC_Filter::MAC_Filter(const std::string& mac_name, const SymmetricKey& key,
                       size_t len) : OUTPUT_LENGTH(len)
   {
   m_mac.reset(Algo_Registry<MessageAuthenticationCode>::global_registry().make(mac_name));
   m_mac->set_key(key);
   }

/*
* Complete a calculation by a MAC_Filter
*/
void MAC_Filter::end_msg()
   {
   secure_vector<byte> output = m_mac->final();
   if(OUTPUT_LENGTH)
      send(output, std::min<size_t>(OUTPUT_LENGTH, output.size()));
   else
      send(output);
   }

}
