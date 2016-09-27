/*
* TLS Record Handling
* (C) 2012,2013,2014,2015,2016 Jack Lloyd
*     2016 Juraj Somorovsky
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/tls_record.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/loadstor.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/rounding.h>
#include <botan/internal/ct_utils.h>
#include <botan/rng.h>

namespace Botan {

namespace TLS {

Connection_Cipher_State::Connection_Cipher_State(Protocol_Version version,
                                                 Connection_Side side,
                                                 bool our_side,
                                                 const Ciphersuite& suite,
                                                 const Session_Keys& keys,
                                                 bool uses_encrypt_then_mac) :
   m_start_time(std::chrono::system_clock::now()),
   m_nonce_bytes_from_handshake(suite.nonce_bytes_from_handshake()),
   m_nonce_bytes_from_record(suite.nonce_bytes_from_record()),
   m_uses_encrypt_then_mac(uses_encrypt_then_mac)
   {
   SymmetricKey mac_key, cipher_key;
   InitializationVector iv;

   if(side == CLIENT)
      {
      cipher_key = keys.client_cipher_key();
      iv = keys.client_iv();
      mac_key = keys.client_mac_key();
      }
   else
      {
      cipher_key = keys.server_cipher_key();
      iv = keys.server_iv();
      mac_key = keys.server_mac_key();
      }

   const std::string cipher_algo = suite.cipher_algo();
   const std::string mac_algo = suite.mac_algo();

   if(AEAD_Mode* aead = get_aead(cipher_algo, our_side ? ENCRYPTION : DECRYPTION))
      {
      m_aead.reset(aead);
      m_aead->set_key(cipher_key + mac_key);

      BOTAN_ASSERT_EQUAL(iv.length(), nonce_bytes_from_handshake(), "Matching nonce sizes");
      m_nonce = unlock(iv.bits_of());

      BOTAN_ASSERT(nonce_bytes_from_record() == 0 || nonce_bytes_from_record() == 8,
                   "Ciphersuite uses implemented IV length");

      if(m_nonce.size() != 12)
         {
         m_nonce.resize(m_nonce.size() + 8);
         }

      return;
      }

   m_block_cipher = BlockCipher::create(cipher_algo);
   m_mac = MessageAuthenticationCode::create("HMAC(" + mac_algo + ")");
   if(!m_block_cipher)
      throw Invalid_Argument("Unknown TLS cipher " + cipher_algo);

   m_block_cipher->set_key(cipher_key);
   m_block_cipher_cbc_state = iv.bits_of();
   m_block_size = m_block_cipher->block_size();

   if(version.supports_explicit_cbc_ivs())
      m_iv_size = m_block_size;

   m_mac->set_key(mac_key);
   }

std::vector<byte> Connection_Cipher_State::aead_nonce(u64bit seq)
   {
   if(nonce_bytes_from_handshake() == 12)
      {
      std::vector<byte> nonce(12);
      store_be(seq, nonce.data() + 4);
      xor_buf(nonce, m_nonce.data(), m_nonce.size());
      return nonce;
      }
   else
      {
      std::vector<byte> nonce = m_nonce;
      store_be(seq, &nonce[nonce_bytes_from_handshake()]);
      return nonce;
      }
   }

std::vector<byte>
Connection_Cipher_State::aead_nonce(const byte record[], size_t record_len, u64bit seq)
   {
   if(nonce_bytes_from_handshake() == 12)
      {
      /*
      Assumes if the suite specifies 12 bytes come from the handshake then
      use the XOR nonce construction from draft-ietf-tls-chacha20-poly1305
      */

      std::vector<byte> nonce(12);
      store_be(seq, nonce.data() + 4);
      xor_buf(nonce, m_nonce.data(), m_nonce.size());
      return nonce;
      }
   else if(nonce_bytes_from_record() > 0)
      {
      if(record_len < nonce_bytes_from_record())
         throw Decoding_Error("Invalid AEAD packet too short to be valid");
      std::vector<byte> nonce = m_nonce;
      copy_mem(&nonce[nonce_bytes_from_handshake()], record, nonce_bytes_from_record());
      return nonce;
      }
   else
      {
      /*
      nonce_len == 0 is assumed to mean no nonce in the message but
      instead the AEAD uses the seq number in network order.
      */
      std::vector<byte> nonce = m_nonce;
      store_be(seq, &nonce[nonce_bytes_from_handshake()]);
      return nonce;
      }
   }

std::vector<byte>
Connection_Cipher_State::format_ad(u64bit msg_sequence,
                                   byte msg_type,
                                   Protocol_Version version,
                                   u16bit msg_length)
   {
   std::vector<byte> ad(13);

   store_be(msg_sequence, &ad[0]);
   ad[8] = msg_type;
   ad[9] = version.major_version();
   ad[10] = version.minor_version();
   ad[11] = get_byte(0, msg_length);
   ad[12] = get_byte(1, msg_length);

   return ad;
   }

namespace {

void cbc_encrypt_record(const BlockCipher& bc,
                        secure_vector<byte>& cbc_state,
                        byte buf[],
                        size_t buf_size)
   {
   const size_t block_size = bc.block_size();
   const size_t blocks = buf_size / block_size;
   BOTAN_ASSERT(buf_size % block_size == 0, "CBC input");
   BOTAN_ASSERT(blocks > 0, "Expected at least 1 block");

   xor_buf(buf, cbc_state.data(), block_size);
   bc.encrypt(buf);

   for(size_t i = 1; i < blocks; ++i)
      {
      xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
      bc.encrypt(&buf[block_size*i]);
      }

   cbc_state.assign(&buf[block_size*(blocks-1)],
                    &buf[block_size*blocks]);
   }

inline void append_u16_len(secure_vector<byte>& output, size_t len_field)
   {
   const uint16_t len16 = len_field;
   BOTAN_ASSERT_EQUAL(len_field, len16, "No truncation");
   output.push_back(get_byte(0, len16));
   output.push_back(get_byte(1, len16));
   }

}

void write_record(secure_vector<byte>& output,
                  Record_Message msg,
                  Protocol_Version version,
                  u64bit seq,
                  Connection_Cipher_State* cs,
                  RandomNumberGenerator& rng)
   {
   output.clear();

   output.push_back(msg.get_type());
   output.push_back(version.major_version());
   output.push_back(version.minor_version());

   if(version.is_datagram_protocol())
      {
      for(size_t i = 0; i != 8; ++i)
         output.push_back(get_byte(i, seq));
      }

   if(!cs) // initial unencrypted handshake records
      {
      append_u16_len(output, msg.get_size());
      output.insert(output.end(), msg.get_data(), msg.get_data() + msg.get_size());

      return;
      }

   std::vector<byte> aad = cs->format_ad(seq, msg.get_type(), version, static_cast<u16bit>(msg.get_size()));

   if(AEAD_Mode* aead = cs->aead())
      {
      const size_t ctext_size = aead->output_length(msg.get_size());

      const std::vector<byte> nonce = cs->aead_nonce(seq);

      const size_t rec_size = ctext_size + cs->nonce_bytes_from_record();

      BOTAN_ASSERT(rec_size <= 0xFFFF, "Ciphertext length fits in field");
      append_u16_len(output, rec_size);

      aead->set_ad(aad);

      if(cs->nonce_bytes_from_record() > 0)
         {
         output += std::make_pair(&nonce[cs->nonce_bytes_from_handshake()], cs->nonce_bytes_from_record());
         }
      const size_t header_size = output.size();
      output += std::make_pair(msg.get_data(), msg.get_size());

      aead->start(nonce);
      aead->finish(output, header_size);

      BOTAN_ASSERT(output.size() < MAX_CIPHERTEXT_SIZE,
                   "Produced ciphertext larger than protocol allows");
      return;
      }

   const size_t block_size = cs->block_size();
   const size_t iv_size = cs->iv_size();
   const size_t mac_size = cs->mac_size();

   const size_t input_size =
      iv_size + msg.get_size() + 1 + (cs->uses_encrypt_then_mac() ? 0 : mac_size);
   const size_t enc_size = round_up(input_size, block_size);
   const size_t pad_val = enc_size - input_size;
   const size_t buf_size = enc_size + (cs->uses_encrypt_then_mac() ? mac_size : 0);

   if(cs->uses_encrypt_then_mac())
      {
      aad[11] = get_byte<uint16_t>(0, enc_size);
      aad[12] = get_byte<uint16_t>(1, enc_size);
      }

   BOTAN_ASSERT(enc_size % block_size == 0,
                "Buffer is an even multiple of block size");

   append_u16_len(output, buf_size);

   const size_t header_size = output.size();

   if(iv_size)
      {
      output.resize(output.size() + iv_size);
      rng.randomize(&output[output.size() - iv_size], iv_size);
      }

   output.insert(output.end(), msg.get_data(), msg.get_data() + msg.get_size());

   // EtM also uses ciphertext size instead of plaintext size for AEAD input
   const byte* mac_input = (cs->uses_encrypt_then_mac() ? &output[header_size] : msg.get_data());
   const size_t mac_input_len = (cs->uses_encrypt_then_mac() ? enc_size : msg.get_size());

   if(cs->uses_encrypt_then_mac())
      {
      for(size_t i = 0; i != pad_val + 1; ++i)
         output.push_back(static_cast<byte>(pad_val));
      cbc_encrypt_record(*cs->block_cipher(), cs->cbc_state(), &output[header_size], enc_size);
      }

   output.resize(output.size() + mac_size);
   cs->mac()->update(aad);
   cs->mac()->update(mac_input, mac_input_len);
   cs->mac()->final(&output[output.size() - mac_size]);

   if(cs->uses_encrypt_then_mac() == false)
      {
      for(size_t i = 0; i != pad_val + 1; ++i)
         output.push_back(static_cast<byte>(pad_val));
      cbc_encrypt_record(*cs->block_cipher(), cs->cbc_state(), &output[header_size], buf_size);
      }

   if(buf_size > MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Output record is larger than allowed by protocol");

   BOTAN_ASSERT_EQUAL(buf_size + header_size, output.size(),
                      "Output buffer is sized properly");
   }

namespace {

size_t fill_buffer_to(secure_vector<byte>& readbuf,
                      const byte*& input,
                      size_t& input_size,
                      size_t& input_consumed,
                      size_t desired)
   {
   if(readbuf.size() >= desired)
      return 0; // already have it

   const size_t taken = std::min(input_size, desired - readbuf.size());

   readbuf.insert(readbuf.end(), input, input + taken);
   input_consumed += taken;
   input_size -= taken;
   input += taken;

   return (desired - readbuf.size()); // how many bytes do we still need?
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
u16bit tls_padding_check(const byte record[], size_t record_len)
   {
   /*
   * TLS v1.0 and up require all the padding bytes be the same value
   * and allows up to 255 bytes.
   */

   const byte pad_byte = record[(record_len-1)];

   byte pad_invalid = 0;
   for(size_t i = 0; i != record_len; ++i)
      {
      const size_t left = record_len - i - 2;
      const byte delim_mask = CT::is_less<u16bit>(static_cast<u16bit>(left), pad_byte) & 0xFF;
      pad_invalid |= (delim_mask & (record[i] ^ pad_byte));
      }

   u16bit pad_invalid_mask = CT::expand_mask<u16bit>(pad_invalid);
   return CT::select<u16bit>(pad_invalid_mask, 0, pad_byte + 1);
   }

void cbc_decrypt_record(byte record_contents[], size_t record_len,
                        Connection_Cipher_State& cs,
                        const BlockCipher& bc)
   {
   const size_t block_size = cs.block_size();

   BOTAN_ASSERT(record_len % block_size == 0,
                "Buffer is an even multiple of block size");

   const size_t blocks = record_len / block_size;

   BOTAN_ASSERT(blocks >= 1, "At least one ciphertext block");

   byte* buf = record_contents;

   secure_vector<byte> last_ciphertext(block_size);
   copy_mem(last_ciphertext.data(), buf, block_size);

   bc.decrypt(buf);
   xor_buf(buf, &cs.cbc_state()[0], block_size);

   secure_vector<byte> last_ciphertext2;

   for(size_t i = 1; i < blocks; ++i)
      {
      last_ciphertext2.assign(&buf[block_size*i], &buf[block_size*(i+1)]);
      bc.decrypt(&buf[block_size*i]);
      xor_buf(&buf[block_size*i], last_ciphertext.data(), block_size);
      std::swap(last_ciphertext, last_ciphertext2);
      }

   cs.cbc_state() = last_ciphertext;
   }

void decrypt_record(secure_vector<byte>& output,
                    byte record_contents[], size_t record_len,
                    u64bit record_sequence,
                    Protocol_Version record_version,
                    Record_Type record_type,
                    Connection_Cipher_State& cs)
   {
   if(AEAD_Mode* aead = cs.aead())
      {
      const std::vector<byte> nonce = cs.aead_nonce(record_contents, record_len, record_sequence);
      const byte* msg = &record_contents[cs.nonce_bytes_from_record()];
      const size_t msg_length = record_len - cs.nonce_bytes_from_record();

      const size_t ptext_size = aead->output_length(msg_length);

      aead->set_associated_data_vec(
         cs.format_ad(record_sequence, record_type, record_version, static_cast<u16bit>(ptext_size))
         );

      aead->start(nonce);

      const size_t offset = output.size();
      output += std::make_pair(msg, msg_length);
      aead->finish(output, offset);

      BOTAN_ASSERT(output.size() == ptext_size + offset, "Produced expected size");
      }
   else
      {
      // GenericBlockCipher case
      BlockCipher* bc = cs.block_cipher();
      BOTAN_ASSERT(bc != nullptr, "No cipher state set but needed to decrypt");

      const size_t mac_size = cs.mac_size();
      const size_t iv_size = cs.iv_size();

      if(!cs.uses_encrypt_then_mac())
         {
         // This early exit does not leak info because all the values are public
         if((record_len < mac_size + iv_size) || (record_len % cs.block_size() != 0))
            throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

         CT::poison(record_contents, record_len);

         cbc_decrypt_record(record_contents, record_len, cs, *bc);

         // 0 if padding was invalid, otherwise 1 + padding_bytes
         u16bit pad_size = tls_padding_check(record_contents, record_len);

         // This mask is zero if there is not enough room in the packet to get
         // a valid MAC. We have to accept empty packets, since otherwise we
         // are not compatible with the BEAST countermeasure (thus record_len+1).
         const u16bit size_ok_mask = CT::is_lte<u16bit>(static_cast<u16bit>(mac_size + pad_size + iv_size), static_cast<u16bit>(record_len + 1));
         pad_size &= size_ok_mask;

         CT::unpoison(record_contents, record_len);

         /*
         This is unpoisoned sooner than it should. The pad_size leaks to plaintext_length and
         then to the timing channel in the MAC computation described in the Lucky 13 paper.
         */
         CT::unpoison(pad_size);

         const byte* plaintext_block = &record_contents[iv_size];
         const u16bit plaintext_length = static_cast<u16bit>(record_len - mac_size - iv_size - pad_size);

         cs.mac()->update(cs.format_ad(record_sequence, record_type, record_version, plaintext_length));
         cs.mac()->update(plaintext_block, plaintext_length);

         std::vector<byte> mac_buf(mac_size);
         cs.mac()->final(mac_buf.data());

         const size_t mac_offset = record_len - (mac_size + pad_size);

         const bool mac_ok = same_mem(&record_contents[mac_offset], mac_buf.data(), mac_size);

         const u16bit ok_mask = size_ok_mask & CT::expand_mask<u16bit>(mac_ok) & CT::expand_mask<u16bit>(pad_size);

         CT::unpoison(ok_mask);

         if(ok_mask)
            {
            output.assign(plaintext_block, plaintext_block + plaintext_length);
            }
         else
            {
            throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
            }
         }
      else
         {
         const size_t enc_size = record_len - mac_size;
         // This early exit does not leak info because all the values are public
         if((record_len < mac_size + iv_size) || ( enc_size % cs.block_size() != 0))
            throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

         cs.mac()->update(cs.format_ad(record_sequence, record_type, record_version, enc_size));
         cs.mac()->update(record_contents, enc_size);

         std::vector<byte> mac_buf(mac_size);
         cs.mac()->final(mac_buf.data());

         const size_t mac_offset = enc_size;

         const bool mac_ok = same_mem(&record_contents[mac_offset], mac_buf.data(), mac_size);

         if(!mac_ok)
            {
            throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
            }

         cbc_decrypt_record(record_contents, enc_size, cs, *bc);

         // 0 if padding was invalid, otherwise 1 + padding_bytes
         u16bit pad_size = tls_padding_check(record_contents, enc_size);

         const byte* plaintext_block = &record_contents[iv_size];
         const u16bit plaintext_length = enc_size - iv_size - pad_size;

         output.assign(plaintext_block, plaintext_block + plaintext_length);
         }
      }
   }

size_t read_tls_record(secure_vector<byte>& readbuf,
                       Record_Raw_Input& raw_input,
                       Record& rec,
                       Connection_Sequence_Numbers* sequence_numbers,
                       get_cipherstate_fn get_cipherstate)
   {
   if(readbuf.size() < TLS_HEADER_SIZE) // header incomplete?
      {
      if(size_t needed = fill_buffer_to(readbuf,
                                        raw_input.get_data(), raw_input.get_size(), raw_input.get_consumed(),
                                        TLS_HEADER_SIZE))
         return needed;

      BOTAN_ASSERT_EQUAL(readbuf.size(), TLS_HEADER_SIZE, "Have an entire header");
      }

   *rec.get_protocol_version() = Protocol_Version(readbuf[1], readbuf[2]);

   BOTAN_ASSERT(!rec.get_protocol_version()->is_datagram_protocol(), "Expected TLS");

   const size_t record_size = make_u16bit(readbuf[TLS_HEADER_SIZE-2],
                                         readbuf[TLS_HEADER_SIZE-1]);

   if(record_size > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Received a record that exceeds maximum size");

   if(record_size == 0)
      throw TLS_Exception(Alert::DECODE_ERROR,
                          "Received a completely empty record");

   if(size_t needed = fill_buffer_to(readbuf,
                                     raw_input.get_data(), raw_input.get_size(), raw_input.get_consumed(),
                                     TLS_HEADER_SIZE + record_size))
      return needed;

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(TLS_HEADER_SIZE) + record_size,
                      readbuf.size(),
                      "Have the full record");

   *rec.get_type() = static_cast<Record_Type>(readbuf[0]);

   u16bit epoch = 0;

   if(sequence_numbers)
      {
      *rec.get_sequence() = sequence_numbers->next_read_sequence();
      epoch = sequence_numbers->current_read_epoch();
      }
   else
      {
      // server initial handshake case
      *rec.get_sequence() = 0;
      epoch = 0;
      }

   byte* record_contents = &readbuf[TLS_HEADER_SIZE];

   if(epoch == 0) // Unencrypted initial handshake
      {
      rec.get_data().assign(readbuf.begin() + TLS_HEADER_SIZE, readbuf.begin() + TLS_HEADER_SIZE + record_size);
      readbuf.clear();
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext
   auto cs = get_cipherstate(epoch);

   BOTAN_ASSERT(cs, "Have cipherstate for this epoch");

   decrypt_record(rec.get_data(),
                  record_contents,
                  record_size,
                  *rec.get_sequence(),
                  *rec.get_protocol_version(),
                  *rec.get_type(),
                  *cs);

   if(sequence_numbers)
      sequence_numbers->read_accept(*rec.get_sequence());

   readbuf.clear();
   return 0;
   }

size_t read_dtls_record(secure_vector<byte>& readbuf,
                        Record_Raw_Input& raw_input,
                        Record& rec,
                        Connection_Sequence_Numbers* sequence_numbers,
                        get_cipherstate_fn get_cipherstate)
   {
   if(readbuf.size() < DTLS_HEADER_SIZE) // header incomplete?
      {
      if(fill_buffer_to(readbuf, raw_input.get_data(), raw_input.get_size(), raw_input.get_consumed(), DTLS_HEADER_SIZE))
         {
         readbuf.clear();
         return 0;
         }

      BOTAN_ASSERT_EQUAL(readbuf.size(), DTLS_HEADER_SIZE, "Have an entire header");
      }

   *rec.get_protocol_version() = Protocol_Version(readbuf[1], readbuf[2]);

   BOTAN_ASSERT(rec.get_protocol_version()->is_datagram_protocol(), "Expected DTLS");

   const size_t record_size = make_u16bit(readbuf[DTLS_HEADER_SIZE-2],
                                          readbuf[DTLS_HEADER_SIZE-1]);

   if(record_size > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Got message that exceeds maximum size");

   if(fill_buffer_to(readbuf, raw_input.get_data(), raw_input.get_size(), raw_input.get_consumed(), DTLS_HEADER_SIZE + record_size))
      {
      // Truncated packet?
      readbuf.clear();
      return 0;
      }

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(DTLS_HEADER_SIZE) + record_size, readbuf.size(),
                      "Have the full record");

   *rec.get_type() = static_cast<Record_Type>(readbuf[0]);

   u16bit epoch = 0;

   *rec.get_sequence() = load_be<u64bit>(&readbuf[3], 0);
   epoch = (*rec.get_sequence() >> 48);

   if(sequence_numbers && sequence_numbers->already_seen(*rec.get_sequence()))
      {
      readbuf.clear();
      return 0;
      }

   byte* record_contents = &readbuf[DTLS_HEADER_SIZE];

   if(epoch == 0) // Unencrypted initial handshake
      {
      rec.get_data().assign(readbuf.begin() + DTLS_HEADER_SIZE, readbuf.begin() + DTLS_HEADER_SIZE + record_size);
      readbuf.clear();
      return 0; // got a full record
      }

   try
      {
      // Otherwise, decrypt, check MAC, return plaintext
      auto cs = get_cipherstate(epoch);

      BOTAN_ASSERT(cs, "Have cipherstate for this epoch");

      decrypt_record(rec.get_data(),
                     record_contents,
                     record_size,
                     *rec.get_sequence(),
                     *rec.get_protocol_version(),
                     *rec.get_type(),
                     *cs);
      }
   catch(std::exception)
      {
      readbuf.clear();
      *rec.get_type() = NO_RECORD;
      return 0;
      }

   if(sequence_numbers)
      sequence_numbers->read_accept(*rec.get_sequence());

   readbuf.clear();
   return 0;
   }

}

size_t read_record(secure_vector<byte>& readbuf,
                   Record_Raw_Input& raw_input,
                   Record& rec,
                   Connection_Sequence_Numbers* sequence_numbers,
                   get_cipherstate_fn get_cipherstate)
   {
   if(raw_input.is_datagram())
      return read_dtls_record(readbuf, raw_input, rec,
                              sequence_numbers, get_cipherstate);
   else
      return read_tls_record(readbuf, raw_input, rec,
                             sequence_numbers, get_cipherstate);
   }

}

}
