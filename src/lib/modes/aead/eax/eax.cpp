/*
* EAX Mode Encryption
* (C) 1999-2007 Jack Lloyd
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/eax.h>
#include <botan/cmac.h>
#include <botan/ctr.h>
#include <botan/parsing.h>

namespace Botan {

namespace {

/*
* EAX MAC-based PRF
*/
secure_vector<uint8_t> eax_prf(uint8_t tag, size_t block_size,
                               MessageAuthenticationCode& mac,
                               const uint8_t in[], size_t length) {
  for (size_t i = 0; i != block_size - 1; ++i) {
    mac.update(0);
  }
  mac.update(tag);
  mac.update(in, length);
  return mac.final();
}

}

/*
* EAX_Mode Constructor
*/
EAX_Mode::EAX_Mode(BlockCipher* cipher, size_t tag_size) :
  m_tag_size(tag_size ? tag_size : cipher->block_size()),
  m_cipher(cipher),
  m_ctr(new CTR_BE(m_cipher->clone())),
  m_cmac(new CMAC(m_cipher->clone())) {
  if (m_tag_size < 8 || m_tag_size > m_cmac->output_length()) {
    throw Invalid_Argument(name() + ": Bad tag size " + std::to_string(tag_size));
  }
}

void EAX_Mode::clear() {
  m_cipher->clear();
  m_ctr->clear();
  m_cmac->clear();
  reset();
}

void EAX_Mode::reset() {
  m_ad_mac.clear();
  m_nonce_mac.clear();
}

std::string EAX_Mode::name() const {
  return (m_cipher->name() + "/EAX");
}

size_t EAX_Mode::update_granularity() const {
  return 1;
}

Key_Length_Specification EAX_Mode::key_spec() const {
  return m_cipher->key_spec();
}

/*
* Set the EAX key
*/
void EAX_Mode::key_schedule(const uint8_t key[], size_t length) {
  /*
  * These could share the key schedule, which is one nice part of EAX,
  * but it's much easier to ignore that here...
  */
  m_ctr->set_key(key, length);
  m_cmac->set_key(key, length);
}

/*
* Set the EAX associated data
*/
void EAX_Mode::set_associated_data(const uint8_t ad[], size_t length) {
  m_ad_mac = eax_prf(1, block_size(), *m_cmac, ad, length);
}

void EAX_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
  if (!valid_nonce_length(nonce_len)) {
    throw Invalid_IV_Length(name(), nonce_len);
  }

  m_nonce_mac = eax_prf(0, block_size(), *m_cmac, nonce, nonce_len);

  m_ctr->set_iv(m_nonce_mac.data(), m_nonce_mac.size());

  for (size_t i = 0; i != block_size() - 1; ++i) {
    m_cmac->update(0);
  }
  m_cmac->update(2);
}

size_t EAX_Encryption::process(uint8_t buf[], size_t sz) {
  m_ctr->cipher(buf, buf, sz);
  m_cmac->update(buf, sz);
  return sz;
}

void EAX_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset) {
  update(buffer, offset);

  secure_vector<uint8_t> data_mac = m_cmac->final();
  xor_buf(data_mac, m_nonce_mac, data_mac.size());

  if (m_ad_mac.empty()) {
    m_ad_mac = eax_prf(1, block_size(), *m_cmac, nullptr, 0);
  }

  xor_buf(data_mac, m_ad_mac, data_mac.size());

  buffer += std::make_pair(data_mac.data(), tag_size());
}

size_t EAX_Decryption::process(uint8_t buf[], size_t sz) {
  m_cmac->update(buf, sz);
  m_ctr->cipher(buf, buf, sz);
  return sz;
}

void EAX_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset) {
  BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
  const size_t sz = buffer.size() - offset;
  uint8_t* buf = buffer.data() + offset;

  BOTAN_ASSERT(sz >= tag_size(), "Have the tag as part of final input");

  const size_t remaining = sz - tag_size();

  if (remaining) {
    m_cmac->update(buf, remaining);
    m_ctr->cipher(buf, buf, remaining);
  }

  const uint8_t* included_tag = &buf[remaining];

  secure_vector<uint8_t> mac = m_cmac->final();
  mac ^= m_nonce_mac;

  if (m_ad_mac.empty()) {
    m_ad_mac = eax_prf(1, block_size(), *m_cmac, nullptr, 0);
  }

  mac ^= m_ad_mac;

  if (!same_mem(mac.data(), included_tag, tag_size())) {
    throw Integrity_Failure("EAX tag check failed");
  }

  buffer.resize(offset + remaining);
}

}
