/*
* TLS CBC Record Handling
* (C) 2012,2013,2014,2015,2016,2020 Jack Lloyd
* (C) 2016 Juraj Somorovsky
* (C) 2016 Matthias Gierlings
* (C) 2016 Daniel Neus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_cbc.h>

#include <botan/internal/cbc.h>

#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/rounding.h>

namespace Botan::TLS {

/*
* TLS_CBC_HMAC_AEAD_Mode Constructor
*/
TLS_CBC_HMAC_AEAD_Mode::TLS_CBC_HMAC_AEAD_Mode(Cipher_Dir dir,
                                               std::unique_ptr<BlockCipher> cipher,
                                               std::unique_ptr<MessageAuthenticationCode> mac,
                                               size_t cipher_keylen,
                                               size_t mac_keylen,
                                               Protocol_Version version,
                                               bool use_encrypt_then_mac) :
      m_mac(std::move(mac)),
      m_cipher_name(cipher->name()),
      m_mac_name(m_mac->name()),
      m_cipher_keylen(cipher_keylen),
      m_block_size(cipher->block_size()),
      m_iv_size(m_block_size),
      m_mac_keylen(mac_keylen),
      m_tag_size(m_mac->output_length()),
      m_use_encrypt_then_mac(use_encrypt_then_mac),
      m_is_datagram(version.is_datagram_protocol()) {
   BOTAN_ASSERT_NOMSG(m_mac->valid_keylength(m_mac_keylen));
   BOTAN_ASSERT_NOMSG(cipher->valid_keylength(m_cipher_keylen));

   auto null_padding = std::make_unique<Null_Padding>();
   if(dir == Cipher_Dir::Encryption) {
      m_cbc = std::make_unique<CBC_Encryption>(std::move(cipher), std::move(null_padding));
   } else {
      m_cbc = std::make_unique<CBC_Decryption>(std::move(cipher), std::move(null_padding));
   }
}

void TLS_CBC_HMAC_AEAD_Mode::clear() {
   cbc().clear();
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
   return 1;  // just buffers anyway
}

size_t TLS_CBC_HMAC_AEAD_Mode::ideal_granularity() const {
   return 1;  // just buffers anyway
}

bool TLS_CBC_HMAC_AEAD_Mode::valid_nonce_length(size_t nl) const {
   if(m_cbc_state.empty()) {
      return nl == block_size();
   }
   return nl == iv_size();
}

Key_Length_Specification TLS_CBC_HMAC_AEAD_Mode::key_spec() const {
   return Key_Length_Specification(m_cipher_keylen + m_mac_keylen);
}

bool TLS_CBC_HMAC_AEAD_Mode::has_keying_material() const {
   return mac().has_keying_material() && cbc().has_keying_material();
}

void TLS_CBC_HMAC_AEAD_Mode::key_schedule(std::span<const uint8_t> key) {
   // Both keys are of fixed length specified by the ciphersuite

   if(key.size() != m_cipher_keylen + m_mac_keylen) {
      throw Invalid_Key_Length(name(), key.size());
   }

   mac().set_key(key.first(m_mac_keylen));
   cbc().set_key(key.subspan(m_mac_keylen, m_cipher_keylen));
}

void TLS_CBC_HMAC_AEAD_Mode::start_msg(const uint8_t nonce[], size_t nonce_len) {
   if(!valid_nonce_length(nonce_len)) {
      throw Invalid_IV_Length(name(), nonce_len);
   }

   m_msg.clear();

   if(nonce_len > 0) {
      m_cbc_state.assign(nonce, nonce + nonce_len);
   }
}

size_t TLS_CBC_HMAC_AEAD_Mode::process_msg(uint8_t buf[], size_t sz) {
   m_msg.insert(m_msg.end(), buf, buf + sz);
   return 0;
}

std::vector<uint8_t> TLS_CBC_HMAC_AEAD_Mode::assoc_data_with_len(uint16_t len) {
   std::vector<uint8_t> ad = m_ad;
   BOTAN_ASSERT(ad.size() == 13, "Expected AAD size");
   ad[11] = get_byte<0>(len);
   ad[12] = get_byte<1>(len);
   return ad;
}

void TLS_CBC_HMAC_AEAD_Mode::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   BOTAN_ARG_CHECK(idx == 0, "TLS 1.2 CBC/HMAC: cannot handle non-zero index in set_associated_data_n");
   if(ad.size() != 13) {
      throw Invalid_Argument("Invalid TLS AEAD associated data length");
   }
   m_ad.assign(ad.begin(), ad.end());
}

void TLS_CBC_HMAC_AEAD_Encryption::set_associated_data_n(size_t idx, std::span<const uint8_t> ad) {
   TLS_CBC_HMAC_AEAD_Mode::set_associated_data_n(idx, ad);

   if(use_encrypt_then_mac()) {
      // AAD hack for EtM
      // EtM uses ciphertext size instead of plaintext size for AEAD input
      const uint16_t pt_size = make_uint16(assoc_data()[11], assoc_data()[12]);
      const uint16_t enc_size = static_cast<uint16_t>(round_up(iv_size() + pt_size + 1, block_size()));
      assoc_data()[11] = get_byte<0, uint16_t>(enc_size);
      assoc_data()[12] = get_byte<1, uint16_t>(enc_size);
   }
}

void TLS_CBC_HMAC_AEAD_Encryption::cbc_encrypt_record(std::span<uint8_t> buffer, size_t padding_length) {
   const auto BS = block_size();

   // We always do short padding:
   BOTAN_ASSERT_NOMSG(padding_length <= 16);
   BOTAN_ASSERT_NOMSG(buffer.size() >= padding_length);
   BOTAN_DEBUG_ASSERT(buffer.size() % BS == 0);

   const uint8_t padding_val = static_cast<uint8_t>(padding_length - 1);

   const auto last_block = buffer.last(BS);

   {
      auto poison = CT::scoped_poison(padding_val, padding_length, last_block);
      const size_t padding_starts = last_block.size() - padding_length;
      for(size_t i = 0; i != last_block.size(); ++i) {
         auto add_padding = CT::Mask<uint8_t>(CT::Mask<size_t>::is_gte(i, padding_starts));
         last_block[i] = add_padding.select(padding_val, last_block[i]);
      }
   }

   cbc().start(cbc_state());
   cbc().process(buffer);
   cbc_state().assign(last_block.begin(), last_block.end());
}

size_t TLS_CBC_HMAC_AEAD_Encryption::output_length(size_t input_length) const {
   return round_up(input_length + 1 + (use_encrypt_then_mac() ? 0 : tag_size()), block_size()) +
          (use_encrypt_then_mac() ? tag_size() : 0);
}

size_t TLS_CBC_HMAC_AEAD_Encryption::bytes_needed_for_finalization(size_t final_input_length) const {
   return output_length(msg().size() + final_input_length);
}

size_t TLS_CBC_HMAC_AEAD_Encryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   const auto tag_length = tag_size();
   const auto BS = block_size();

   const auto& buffered_msg = msg();
   BOTAN_ASSERT_NOMSG(buffer.size() > buffered_msg.size() + input_bytes);
   const auto full_msg = buffer.first(buffered_msg.size() + input_bytes);

   // If we had previously buffered data that came in via `process()`, we have
   // to prepend this buffer to the final bytes passed into `finish()`.
   if(!buffered_msg.empty()) {
      copy_mem(full_msg.last(input_bytes), full_msg.first(input_bytes));
      copy_mem(full_msg.first(buffered_msg.size()), buffered_msg);
   }

   const size_t input_size = full_msg.size() + 1 + (use_encrypt_then_mac() ? 0 : tag_length);
   const size_t enc_size = round_up(input_size, BS);
   BOTAN_DEBUG_ASSERT(enc_size % BS == 0);

   const uint8_t padding_val = static_cast<uint8_t>(enc_size - input_size);
   const size_t padding_length = static_cast<size_t>(padding_val) + 1;

   mac().update(assoc_data());
   if(use_encrypt_then_mac()) {
      BOTAN_ASSERT_NOMSG(buffer.size() == enc_size + tag_length);
      const auto payload_and_padding = buffer.first(enc_size);
      const auto tag = buffer.last(tag_length);

      if(iv_size() > 0) {
         mac().update(cbc_state());
      }

      cbc_encrypt_record(payload_and_padding, padding_length);
      mac().update(payload_and_padding);
      mac().final(tag);
   } else {
      BOTAN_ASSERT_NOMSG(buffer.size() == enc_size);
      const auto tag = buffer.subspan(full_msg.size(), tag_length);

      if(!full_msg.empty()) {
         mac().update(full_msg);
      }
      mac().final(tag);
      cbc_encrypt_record(buffer, padding_length);
   }

   return buffer.size();
}

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
uint16_t check_tls_cbc_padding(std::span<const uint8_t> record) {
   if(record.empty() || record.size() > 0xFFFF) {
      return 0;
   }

   const uint16_t rec16 = static_cast<uint16_t>(record.size());

   /*
   * TLS v1.0 and up require all the padding bytes be the same value
   * and allows up to 255 bytes.
   */

   const uint16_t to_check = std::min<uint16_t>(256, static_cast<uint16_t>(record.size()));
   const uint8_t pad_byte = record.back();
   const uint16_t pad_bytes = 1 + pad_byte;

   auto pad_invalid = CT::Mask<uint16_t>::is_lt(rec16, pad_bytes);

   for(uint16_t i = rec16 - to_check; i != rec16; ++i) {
      const uint16_t offset = rec16 - i;
      const auto in_pad_range = CT::Mask<uint16_t>::is_lte(offset, pad_bytes);
      const auto pad_correct = CT::Mask<uint16_t>::is_equal(record[i], pad_byte);
      pad_invalid |= in_pad_range & ~pad_correct;
   }

   return pad_invalid.if_not_set_return(pad_bytes);
}

void TLS_CBC_HMAC_AEAD_Decryption::cbc_decrypt_record(std::span<uint8_t> record) {
   const auto BS = block_size();

   if(record.empty() || record.size() % BS != 0) {
      throw Decoding_Error("Received TLS CBC ciphertext with invalid length");
   }

   const auto final_block = record.last(BS);

   cbc().start(cbc_state());
   cbc_state().assign(final_block.begin(), final_block.end());

   cbc().process(record);
}

size_t TLS_CBC_HMAC_AEAD_Decryption::output_length(size_t /*input_length*/) const {
   /*
   * We don't know this because the padding is arbitrary
   */
   return 0;
}

size_t TLS_CBC_HMAC_AEAD_Decryption::bytes_needed_for_finalization(size_t final_input_length) const {
   BOTAN_ARG_CHECK(final_input_length >= tag_size(), "Sufficient input");
   return msg().size() + final_input_length;
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
* min(plen,256) bytes, see the function check_tls_cbc_padding. This differs
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
   const bool is_sha384 = mac().name() == "HMAC(SHA-384)";
   const uint16_t block_size = is_sha384 ? 128 : 64;
   const uint16_t max_bytes_in_first_block = is_sha384 ? 111 : 55;

   // number of maximum MACed bytes
   const uint16_t L1 = static_cast<uint16_t>(13 + plen - tag_size());
   // number of current MACed bytes (L1 - padlen)
   // Here the Lucky 13 paper is different because the padlen length in the paper
   // does not count the last message byte.
   const uint16_t L2 = static_cast<uint16_t>(13 + plen - padlen - tag_size());
   // From the paper, for SHA-256/SHA-1 compute: ceil((L1-55)/64) and ceil((L2-55)/64)
   // ceil((L1-55)/64) = floor((L1+64-1-55)/64)
   // Here we compute number of compressions for SHA-* in general
   const uint16_t max_compresssions = ((L1 + block_size - 1 - max_bytes_in_first_block) / block_size);
   const uint16_t current_compressions = ((L2 + block_size - 1 - max_bytes_in_first_block) / block_size);
   // number of additional compressions we have to perform
   const uint16_t add_compressions = max_compresssions - current_compressions;
   const uint16_t equal = CT::Mask<uint16_t>::is_equal(max_compresssions, current_compressions).if_set_return(1);
   // We compute the data length we need to achieve the number of compressions.
   // If there are no compressions, we just add 55/111 dummy bytes so that no
   // compression is performed.
   const uint16_t data_len = block_size * add_compressions + equal * max_bytes_in_first_block;
   std::vector<uint8_t> data(data_len);
   mac().update(data);
   // we do not need to clear the MAC since the connection is broken anyway
}

size_t TLS_CBC_HMAC_AEAD_Decryption::finish_msg(std::span<uint8_t> buffer, size_t input_bytes) {
   const auto tag_length = tag_size();
   const auto BS = block_size();

   const auto& buffered_msg = msg();
   BOTAN_ASSERT_NOMSG(buffer.size() == buffered_msg.size() + input_bytes);
   const auto record = buffer.first(buffered_msg.size() + input_bytes);

   // If we had previously buffered data that came in via `process()`, we have
   // to prepend this buffer to the final bytes passed into `finish()`.
   if(!buffered_msg.empty()) {
      copy_mem(record.last(input_bytes), record.first(input_bytes));
      copy_mem(record.first(buffered_msg.size()), buffered_msg);
   }

   // This early exit does not leak info because all the values compared are public
   if(record.size() < tag_length || (record.size() - (use_encrypt_then_mac() ? tag_length : 0)) % BS != 0) {
      throw TLS_Exception(Alert::BadRecordMac, "Message authentication failure");
   }

   if(use_encrypt_then_mac()) {
      const auto payload_and_padding = record.first(record.size() - tag_length);
      const auto tag = record.last(tag_length);
      const size_t enc_iv_size = payload_and_padding.size() + iv_size();

      BOTAN_ASSERT_NOMSG(enc_iv_size <= 0xFFFF);

      mac().update(assoc_data_with_len(static_cast<uint16_t>(enc_iv_size)));
      if(iv_size() > 0) {
         mac().update(cbc_state());
      }
      mac().update(payload_and_padding);

      const auto mac_buf = mac().final<std::vector<uint8_t>>();
      BOTAN_DEBUG_ASSERT(mac_buf.size() == tag_length);

      const auto mac_ok = CT::is_equal(tag.data(), mac_buf.data(), tag_length);

      if(!mac_ok.as_bool()) {
         throw TLS_Exception(Alert::BadRecordMac, "Message authentication failure");
      }

      cbc_decrypt_record(payload_and_padding);

      // 0 if padding was invalid, otherwise 1 + padding_bytes
      const uint16_t pad_size = check_tls_cbc_padding(payload_and_padding);

      // No oracle here, whoever sent us this had the key since MAC check passed
      if(pad_size == 0) {
         throw TLS_Exception(Alert::BadRecordMac, "Message authentication failure");
      }

      BOTAN_DEBUG_ASSERT(payload_and_padding.size() >= pad_size);
      return payload_and_padding.size() - pad_size;
   } else {
      cbc_decrypt_record(record);
      CT::poison(record);

      // 0 if padding was invalid, otherwise 1 + padding_bytes
      uint16_t pad_size = check_tls_cbc_padding(record);

      /*
      This mask is zero if there is not enough room in the packet to get a valid MAC.

      We have to accept empty packets, since otherwise we are not compatible
      with how OpenSSL's countermeasure for fixing BEAST in TLS 1.0 CBC works
      (sending empty records, instead of 1/(n-1) splitting)
      */

      // We know the cast cannot overflow as pad_size <= 256 && tag_size <= 32
      const auto size_ok_mask =
         CT::Mask<uint16_t>::is_lte(static_cast<uint16_t>(tag_length + pad_size), static_cast<uint16_t>(record.size()));

      /*
      This is unpoisoned sooner than it should. The pad_size leaks to plaintext_length and
      then to the timing channel in the MAC computation described in the Lucky 13 paper.
      */
      pad_size = CT::driveby_unpoison(size_ok_mask.if_set_return(pad_size));
      CT::unpoison(record);

      BOTAN_DEBUG_ASSERT(record.size() >= tag_length + pad_size);
      const auto payload = record.first(record.size() - tag_length - pad_size);
      const auto tag = record.subspan(payload.size(), tag_length);

      mac().update(assoc_data_with_len(static_cast<uint16_t>(payload.size())));
      mac().update(payload);

      const auto mac_buf = mac().final<std::vector<uint8_t>>();
      const auto mac_ok = CT::is_equal(tag.data(), mac_buf.data(), tag_length);

      const auto ok_mask =
         CT::driveby_unpoison(size_ok_mask & CT::Mask<uint16_t>::expand(mac_ok) & CT::Mask<uint16_t>::expand(pad_size));

      if(!ok_mask.as_bool()) {
         perform_additional_compressions(record.size(), pad_size);

         /*
         * In DTLS case we have to finish computing the MAC since we require the
         * MAC state be reset for future packets. This extra timing channel may
         * be exploitable in a Lucky13 variant.
         */
         if(is_datagram_protocol()) {
            std::ignore = mac().final();
         }
         throw TLS_Exception(Alert::BadRecordMac, "Message authentication failure");
      }

      return payload.size();
   }

   BOTAN_ASSERT_UNREACHABLE();
}

}  // namespace Botan::TLS
