/*
* TLS CBC Record Handling
* (C) 2012,2013,2014,2015,2016 Jack Lloyd
* (C) 2016 Juraj Somorovsky
* (C) 2016 Matthias Gierlings
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_cbc.h>
#include <botan/internal/rounding.h>
#include <botan/internal/ct_utils.h>
#include <botan/tls_alert.h>
#include <botan/tls_magic.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

/*
* TLS_CBC_HMAC_AEAD_Mode Constructor
*/
TLS_CBC_HMAC_AEAD_Mode::TLS_CBC_HMAC_AEAD_Mode(const std::string& cipher_name,
    size_t cipher_keylen,
    const std::string& mac_name,
    size_t mac_keylen,
    bool use_explicit_iv,
    bool use_encrypt_then_mac) :
  m_cipher_name(cipher_name),
  m_mac_name(mac_name),
  m_cipher_keylen(cipher_keylen),
  m_mac_keylen(mac_keylen),
  m_use_encrypt_then_mac(use_encrypt_then_mac) {
  m_cipher = BlockCipher::create_or_throw(m_cipher_name);
  m_mac = MessageAuthenticationCode::create_or_throw("HMAC(" + m_mac_name + ")");

  m_tag_size = m_mac->output_length();
  m_block_size = m_cipher->block_size();

  m_iv_size = use_explicit_iv ? m_block_size : 0;
}

void TLS_CBC_HMAC_AEAD_Mode::clear() {
  cipher().clear();
  mac().clear();
  reset();
}

void TLS_CBC_HMAC_AEAD_Mode::reset() {
  cbc_state().clear();
  m_ad.clear();
  m_msg.clear();
}

std::string TLS_CBC_HMAC_AEAD_Mode::name() const {
  return "TLS_CBC(" + m_cipher_name + "," + m_mac_name + ")";
}

size_t TLS_CBC_HMAC_AEAD_Mode::update_granularity() const {
  return 1; // just buffers anyway
}

bool TLS_CBC_HMAC_AEAD_Mode::valid_nonce_length(size_t nl) const {
  if (m_cbc_state.empty()) {
    return nl == block_size();
  }
  return nl == iv_size();
}

Key_Length_Specification TLS_CBC_HMAC_AEAD_Mode::key_spec() const {
  return Key_Length_Specification(m_cipher_keylen + m_mac_keylen);
}

void TLS_CBC_HMAC_AEAD_Mode::key_schedule(const uint8_t key[], size_t keylen) {
  // Both keys are of fixed length specified by the ciphersuite

  if (keylen != m_cipher_keylen + m_mac_keylen) {
    throw Invalid_Key_Length(name(), keylen);
  }

  cipher().set_key(&key[0], m_cipher_keylen);
  mac().set_key(&key[m_cipher_keylen], m_mac_keylen);
}

void TLS_CBC_HMAC_AEAD_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
  if (!valid_nonce_length(nonce_len)) {
    throw Invalid_IV_Length(name(), nonce_len);
  }

  m_msg.clear();

  if (nonce_len > 0) {
    m_cbc_state.assign(nonce, nonce + nonce_len);
  }
}

size_t TLS_CBC_HMAC_AEAD_Mode::process(uint8_t buf[], size_t sz) {
  m_msg.insert(m_msg.end(), buf, buf + sz);
  return 0;
}

std::vector<uint8_t> TLS_CBC_HMAC_AEAD_Mode::assoc_data_with_len(uint16_t len) {
  std::vector<uint8_t> ad = m_ad;
  BOTAN_ASSERT(ad.size() == 13, "Expected AAD size");
  ad[11] = get_byte(0, len);
  ad[12] = get_byte(1, len);
  return ad;
}

void TLS_CBC_HMAC_AEAD_Mode::set_associated_data(const uint8_t ad[], size_t ad_len) {
  if (ad_len != 13) {
    throw Exception("Invalid TLS AEAD associated data length");
  }
  m_ad.assign(ad, ad + ad_len);
}

void TLS_CBC_HMAC_AEAD_Encryption::set_associated_data(const uint8_t ad[], size_t ad_len) {
  TLS_CBC_HMAC_AEAD_Mode::set_associated_data(ad, ad_len);

  if (use_encrypt_then_mac()) {
    // AAD hack for EtM
    size_t pt_size = make_uint16(assoc_data()[11], assoc_data()[12]);
    size_t enc_size = round_up(iv_size() + pt_size + 1, block_size());
    assoc_data()[11] = get_byte<uint16_t>(0, enc_size);
    assoc_data()[12] = get_byte<uint16_t>(1, enc_size);
  }
}

void TLS_CBC_HMAC_AEAD_Encryption::cbc_encrypt_record(uint8_t buf[], size_t buf_size) {
  const size_t blocks = buf_size / block_size();
  BOTAN_ASSERT(buf_size % block_size() == 0, "Valid CBC input");

  xor_buf(buf, cbc_state().data(), block_size());
  cipher().encrypt(buf);

  for (size_t i = 1; i < blocks; ++i) {
    xor_buf(&buf[block_size()*i], &buf[block_size()*(i-1)], block_size());
    cipher().encrypt(&buf[block_size()*i]);
  }

  cbc_state().assign(&buf[block_size()*(blocks-1)],
                     &buf[block_size()*blocks]);
}

size_t TLS_CBC_HMAC_AEAD_Encryption::output_length(size_t input_length) const {
  return round_up(input_length + 1 + (use_encrypt_then_mac() ? 0 : tag_size()), block_size()) +
         (use_encrypt_then_mac() ? tag_size() : 0);
}

void TLS_CBC_HMAC_AEAD_Encryption::finish(secure_vector<uint8_t>& buffer, size_t offset) {
  update(buffer, offset);
  buffer.resize(offset); // truncate, leaving just header
  const size_t header_size = offset;

  buffer.insert(buffer.end(), msg().begin(), msg().end());

  const size_t input_size = msg().size() + 1 + (use_encrypt_then_mac() ? 0 : tag_size());
  const size_t enc_size = round_up(input_size, block_size());
  const size_t pad_val = enc_size - input_size;
  const size_t buf_size = enc_size + (use_encrypt_then_mac() ? tag_size() : 0);

  BOTAN_ASSERT(enc_size % block_size() == 0,
               "Buffer is an even multiple of block size");

  mac().update(assoc_data());

  if (use_encrypt_then_mac()) {
    if (iv_size() > 0) {
      mac().update(cbc_state());
    }

    for (size_t i = 0; i != pad_val + 1; ++i) {
      buffer.push_back(static_cast<uint8_t>(pad_val));
    }
    cbc_encrypt_record(&buffer[header_size], enc_size);
  }

  // EtM also uses ciphertext size instead of plaintext size for AEAD input
  const uint8_t* mac_input = (use_encrypt_then_mac() ? &buffer[header_size] : msg().data());
  const size_t mac_input_len = (use_encrypt_then_mac() ? enc_size : msg().size());

  mac().update(mac_input, mac_input_len);

  buffer.resize(buffer.size() + tag_size());
  mac().final(&buffer[buffer.size() - tag_size()]);

  if (use_encrypt_then_mac() == false) {
    for (size_t i = 0; i != pad_val + 1; ++i) {
      buffer.push_back(static_cast<uint8_t>(pad_val));
    }
    cbc_encrypt_record(&buffer[header_size], buf_size);
  }
}

namespace {


/*
* Checks the TLS padding. Returns 0 if the padding is invalid (we
* count the padding_length field as part of the padding size so a
* valid padding will always be at least one byte long), or the length
* of the padding otherwise. This is actually padding_length + 1
* because both the padding and padding_length fields are padding from
* our perspective.
*
* Returning 0 in the error case should ensure the MAC check will fail.
* This approach is suggested in section 6.2.3.2 of RFC 5246.
*/
uint16_t check_tls_padding(const uint8_t record[], size_t record_len) {
  /*
  * TLS v1.0 and up require all the padding bytes be the same value
  * and allows up to 255 bytes.
  */

  const uint8_t pad_byte = record[(record_len-1)];

  uint8_t pad_invalid = 0;
  for (size_t i = 0; i != record_len; ++i) {
    const size_t left = record_len - i - 2;
    const uint8_t delim_mask = CT::is_less<uint16_t>(static_cast<uint16_t>(left), pad_byte) & 0xFF;
    pad_invalid |= (delim_mask & (record[i] ^ pad_byte));
  }

  uint16_t pad_invalid_mask = CT::expand_mask<uint16_t>(pad_invalid);
  return CT::select<uint16_t>(pad_invalid_mask, 0, pad_byte + 1);
}

}

void TLS_CBC_HMAC_AEAD_Decryption::cbc_decrypt_record(uint8_t record_contents[], size_t record_len) {
  BOTAN_ASSERT(record_len % block_size() == 0,
               "Buffer is an even multiple of block size");

  const size_t blocks = record_len / block_size();

  BOTAN_ASSERT(blocks >= 1, "At least one ciphertext block");

  uint8_t* buf = record_contents;

  secure_vector<uint8_t> last_ciphertext(block_size());
  copy_mem(last_ciphertext.data(), buf, block_size());

  cipher().decrypt(buf);
  xor_buf(buf, cbc_state().data(), block_size());

  secure_vector<uint8_t> last_ciphertext2;

  for (size_t i = 1; i < blocks; ++i) {
    last_ciphertext2.assign(&buf[block_size()*i], &buf[block_size()*(i+1)]);
    cipher().decrypt(&buf[block_size()*i]);
    xor_buf(&buf[block_size()*i], last_ciphertext.data(), block_size());
    std::swap(last_ciphertext, last_ciphertext2);
  }

  cbc_state().assign(last_ciphertext.begin(), last_ciphertext.end());
}

size_t TLS_CBC_HMAC_AEAD_Decryption::output_length(size_t) const {
  /*
  * We don't know this because the padding is arbitrary
  */
  return 0;
}

/*
* This function performs additional compression calls in order
* to protect from the Lucky 13 attack. It adds new compression
* function calls over dummy data, by computing additional HMAC updates.
*
* The countermeasure was described (in a similar way) in the Lucky 13 paper.
*
* Background:
* - One SHA-1/SHA-256 compression is performed with 64 bytes of data.
* - HMAC adds 8 byte length field and padding (at least 1 byte) so that we have:
*   - 0 - 55 bytes: 1 compression
*   - 56 - 55+64 bytes: 2 compressions
*   - 56+64 - 55+2*64 bytes: 3 compressions ...
* - For SHA-384, this works similarly, but we have 128 byte blocks and 16 byte
*   long length field. This results in:
*   - 0 - 111 bytes: 1 compression
*   - 112 - 111+128 bytes: 2 compressions ...
*
* The implemented countermeasure works as follows:
* 1) It computes max_compressions: number of maximum compressions performed on
*    the decrypted data
* 2) It computes current_compressions: number of compressions performed on the
*    decrypted data, after padding has been removed
* 3) If current_compressions != max_compressions: It invokes an HMAC update
*    over dummy data so that (max_compressions - current_compressions)
*    compressions are performed. Otherwise, it invokes an HMAC update so that
*    no compressions are performed.
*
* Note that the padding validation in Botan is always performed over
* min(plen,256) bytes, see the function check_tls_padding. This differs
* from the countermeasure described in the paper.
*
* Note that the padding length padlen does also count the last byte
* of the decrypted plaintext. This is different from the Lucky 13 paper.
*
* This countermeasure leaves a difference of about 100 clock cycles (in
* comparison to >1000 clock cycles observed without it).
*
* plen represents the length of the decrypted plaintext message P
* padlen represents the padding length
*
*/
void TLS_CBC_HMAC_AEAD_Decryption::perform_additional_compressions(size_t plen, size_t padlen) {
  uint16_t block_size;
  uint16_t max_bytes_in_first_block;
  if (mac().name() == "HMAC(SHA-384)") {
    block_size = 128;
    max_bytes_in_first_block = 111;
  }
  else {
    block_size = 64;
    max_bytes_in_first_block = 55;
  }
  // number of maximum MACed bytes
  const uint16_t L1 = 13 + plen - tag_size();
  // number of current MACed bytes (L1 - padlen)
  // Here the Lucky 13 paper is different because the padlen length in the paper
  // does not count the last message byte.
  const uint16_t L2 = 13 + plen - padlen - tag_size();
  // From the paper, for SHA-256/SHA-1 compute: ceil((L1-55)/64) and ceil((L2-55)/64)
  // ceil((L1-55)/64) = floor((L1+64-1-55)/64)
  // Here we compute number of compressions for SHA-* in general
  const uint16_t max_compresssions = ((L1 + block_size - 1 - max_bytes_in_first_block) / block_size);
  const uint16_t current_compressions = ((L2 + block_size - 1 - max_bytes_in_first_block) / block_size);
  // number of additional compressions we have to perform
  const uint16_t add_compressions = max_compresssions - current_compressions;
  const uint8_t equal = CT::is_equal(max_compresssions, current_compressions) & 0x01;
  // We compute the data length we need to achieve the number of compressions.
  // If there are no compressions, we just add 55/111 dummy bytes so that no
  // compression is performed.
  const uint16_t data_len = block_size * add_compressions + equal * max_bytes_in_first_block;
  secure_vector<uint8_t> data(data_len);
  mac().update(unlock(data));
  // we do not need to clear the MAC since the connection is broken anyway
}

void TLS_CBC_HMAC_AEAD_Decryption::finish(secure_vector<uint8_t>& buffer, size_t offset) {
  update(buffer, offset);
  buffer.resize(offset);

  const size_t record_len = msg().size();
  uint8_t* record_contents = msg().data();

  // This early exit does not leak info because all the values compared are public
  if (record_len < tag_size() ||
      (record_len - (use_encrypt_then_mac() ? tag_size() : 0)) % block_size() != 0) {
    throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
  }

  if (use_encrypt_then_mac()) {
    const size_t enc_size = record_len - tag_size();

    mac().update(assoc_data_with_len(iv_size() + enc_size));
    if (iv_size() > 0) {
      mac().update(cbc_state());
    }
    mac().update(record_contents, enc_size);

    std::vector<uint8_t> mac_buf(tag_size());
    mac().final(mac_buf.data());

    const size_t mac_offset = enc_size;

    const bool mac_ok = same_mem(&record_contents[mac_offset], mac_buf.data(), tag_size());

    if (!mac_ok) {
      throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
    }

    cbc_decrypt_record(record_contents, enc_size);

    // 0 if padding was invalid, otherwise 1 + padding_bytes
    uint16_t pad_size = check_tls_padding(record_contents, enc_size);

    // No oracle here, whoever sent us this had the key since MAC check passed
    if (pad_size == 0) {
      throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
    }

    const uint8_t* plaintext_block = &record_contents[0];
    const uint16_t plaintext_length = enc_size - pad_size;

    buffer.insert(buffer.end(), plaintext_block, plaintext_block + plaintext_length);
  }
  else {
    CT::poison(record_contents, record_len);

    cbc_decrypt_record(record_contents, record_len);

    // 0 if padding was invalid, otherwise 1 + padding_bytes
    uint16_t pad_size = check_tls_padding(record_contents, record_len);

    /*
    This mask is zero if there is not enough room in the packet to get a valid MAC.

    We have to accept empty packets, since otherwise we are not compatible
    with how OpenSSL's countermeasure for fixing BEAST in TLS 1.0 CBC works
    (sending empty records, instead of 1/(n-1) splitting)
    */

    const uint16_t size_ok_mask = CT::is_lte<uint16_t>(static_cast<uint16_t>(tag_size() + pad_size),
                                  static_cast<uint16_t>(record_len + 1));
    pad_size &= size_ok_mask;

    CT::unpoison(record_contents, record_len);

    /*
    This is unpoisoned sooner than it should. The pad_size leaks to plaintext_length and
    then to the timing channel in the MAC computation described in the Lucky 13 paper.
    */
    CT::unpoison(pad_size);

    const uint8_t* plaintext_block = &record_contents[0];
    const uint16_t plaintext_length = static_cast<uint16_t>(record_len - tag_size() - pad_size);

    mac().update(assoc_data_with_len(plaintext_length));
    mac().update(plaintext_block, plaintext_length);

    std::vector<uint8_t> mac_buf(tag_size());
    mac().final(mac_buf.data());

    const size_t mac_offset = record_len - (tag_size() + pad_size);

    const bool mac_ok = same_mem(&record_contents[mac_offset], mac_buf.data(), tag_size());

    const uint16_t ok_mask = size_ok_mask & CT::expand_mask<uint16_t>(mac_ok) & CT::expand_mask<uint16_t>(pad_size);

    CT::unpoison(ok_mask);

    if (ok_mask) {
      buffer.insert(buffer.end(), plaintext_block, plaintext_block + plaintext_length);
    }
    else {
      perform_additional_compressions(record_len, pad_size);
      throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
    }
  }
}

}

}
