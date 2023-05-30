/*
* Filters
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/filters.h>
#include <algorithm>

namespace Botan {

#if defined(BOTAN_HAS_STREAM_CIPHER)

StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher) : m_cipher(cipher), m_buffer(m_cipher->buffer_size()) {}

StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher, const SymmetricKey& key) : StreamCipher_Filter(cipher) {
   m_cipher->set_key(key);
}

StreamCipher_Filter::StreamCipher_Filter(std::string_view sc_name) :
      m_cipher(StreamCipher::create_or_throw(sc_name)), m_buffer(m_cipher->buffer_size()) {}

StreamCipher_Filter::StreamCipher_Filter(std::string_view sc_name, const SymmetricKey& key) :
      StreamCipher_Filter(sc_name) {
   m_cipher->set_key(key);
}

void StreamCipher_Filter::write(const uint8_t input[], size_t length) {
   while(length) {
      size_t copied = std::min<size_t>(length, m_buffer.size());
      m_cipher->cipher(input, m_buffer.data(), copied);
      send(m_buffer, copied);
      input += copied;
      length -= copied;
   }
}

#endif

#if defined(BOTAN_HAS_HASH)

Hash_Filter::Hash_Filter(std::string_view hash_name, size_t len) :
      m_hash(HashFunction::create_or_throw(hash_name)), m_out_len(len) {}

void Hash_Filter::end_msg() {
   secure_vector<uint8_t> output = m_hash->final();
   if(m_out_len) {
      send(output, std::min<size_t>(m_out_len, output.size()));
   } else {
      send(output);
   }
}
#endif

#if defined(BOTAN_HAS_MAC)

MAC_Filter::MAC_Filter(std::string_view mac_name, size_t len) :
      m_mac(MessageAuthenticationCode::create_or_throw(mac_name)), m_out_len(len) {}

MAC_Filter::MAC_Filter(std::string_view mac_name, const SymmetricKey& key, size_t len) : MAC_Filter(mac_name, len) {
   m_mac->set_key(key);
}

void MAC_Filter::end_msg() {
   secure_vector<uint8_t> output = m_mac->final();
   if(m_out_len) {
      send(output, std::min<size_t>(m_out_len, output.size()));
   } else {
      send(output);
   }
}

#endif

}  // namespace Botan
