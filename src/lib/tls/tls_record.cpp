/*
* TLS Record Handling
* (C) 2012,2013,2014,2015 Jack Lloyd
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
                                                 const Session_Keys& keys) :
   m_start_time(std::chrono::system_clock::now()),
   m_nonce_bytes_from_handshake(suite.nonce_bytes_from_handshake()),
   m_nonce_bytes_from_record(suite.nonce_bytes_from_record())
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
      m_nonce = iv.bits_of();

      BOTAN_ASSERT(nonce_bytes_from_record() == 0 || nonce_bytes_from_record() == 8,
                   "Ciphersuite uses implemented IV length");

      m_nonce.resize(m_nonce.size() + 8);
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

const secure_vector<byte>& Connection_Cipher_State::aead_nonce(u64bit seq)
   {
   store_be(seq, &m_nonce[nonce_bytes_from_handshake()]);
   return m_nonce;
   }

const secure_vector<byte>&
Connection_Cipher_State::aead_nonce(const byte record[], size_t record_len, u64bit seq)
   {
   if(nonce_bytes_from_record())
      {
      if(record_len < nonce_bytes_from_record())
         throw Decoding_Error("Invalid AEAD packet too short to be valid");
      copy_mem(&m_nonce[nonce_bytes_from_handshake()], record, nonce_bytes_from_record());
      }
   else
      {
      /*
      nonce_len == 0 is assumed to mean no nonce in the message but
      instead the AEAD uses the seq number in network order.
      */
      store_be(seq, &m_nonce[nonce_bytes_from_handshake()]);
      }
   return m_nonce;
   }

const secure_vector<byte>&
Connection_Cipher_State::format_ad(u64bit msg_sequence,
                                   byte msg_type,
                                   Protocol_Version version,
                                   u16bit msg_length)
   {
   m_ad.clear();
   for(size_t i = 0; i != 8; ++i)
      m_ad.push_back(get_byte(i, msg_sequence));
   m_ad.push_back(msg_type);

   m_ad.push_back(version.major_version());
   m_ad.push_back(version.minor_version());

   m_ad.push_back(get_byte(0, msg_length));
   m_ad.push_back(get_byte(1, msg_length));

   return m_ad;
   }

void write_record(secure_vector<byte>& output,
                  byte msg_type, const byte msg[], size_t msg_length,
                  Protocol_Version version,
                  u64bit seq,
                  Connection_Cipher_State* cs,
                  RandomNumberGenerator& rng)
   {
   output.clear();

   output.push_back(msg_type);
   output.push_back(version.major_version());
   output.push_back(version.minor_version());

   if(version.is_datagram_protocol())
      {
      for(size_t i = 0; i != 8; ++i)
         output.push_back(get_byte(i, seq));
      }

   if(!cs) // initial unencrypted handshake records
      {
      output.push_back(get_byte<u16bit>(0, msg_length));
      output.push_back(get_byte<u16bit>(1, msg_length));

      output.insert(output.end(), msg, msg + msg_length);

      return;
      }

   if(AEAD_Mode* aead = cs->aead())
      {
      const size_t ctext_size = aead->output_length(msg_length);

      const secure_vector<byte>& nonce = cs->aead_nonce(seq);

      // wrong if start returns something
      const size_t rec_size = ctext_size + cs->nonce_bytes_from_record();

      BOTAN_ASSERT(rec_size <= 0xFFFF, "Ciphertext length fits in field");
      output.push_back(get_byte<u16bit>(0, rec_size));
      output.push_back(get_byte<u16bit>(1, rec_size));

      aead->set_ad(cs->format_ad(seq, msg_type, version, msg_length));

      output += std::make_pair(&nonce[cs->nonce_bytes_from_handshake()], cs->nonce_bytes_from_record());
      BOTAN_ASSERT(aead->start(nonce).empty(), "AEAD doesn't return anything from start");

      const size_t offset = output.size();
      output += std::make_pair(msg, msg_length);
      aead->finish(output, offset);

      BOTAN_ASSERT(output.size() == offset + ctext_size, "Expected size");

      BOTAN_ASSERT(output.size() < MAX_CIPHERTEXT_SIZE,
                   "Produced ciphertext larger than protocol allows");
      return;
      }

   cs->mac()->update(cs->format_ad(seq, msg_type, version, msg_length));

   cs->mac()->update(msg, msg_length);

   const size_t block_size = cs->block_size();
   const size_t iv_size = cs->iv_size();
   const size_t mac_size = cs->mac_size();

   const size_t buf_size = round_up(
      iv_size + msg_length + mac_size + (block_size ? 1 : 0),
      block_size);

   if(buf_size > MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Output record is larger than allowed by protocol");

   output.push_back(get_byte<u16bit>(0, buf_size));
   output.push_back(get_byte<u16bit>(1, buf_size));

   const size_t header_size = output.size();

   if(iv_size)
      {
      output.resize(output.size() + iv_size);
      rng.randomize(&output[output.size() - iv_size], iv_size);
      }

   output.insert(output.end(), msg, msg + msg_length);

   output.resize(output.size() + mac_size);
   cs->mac()->final(&output[output.size() - mac_size]);

   if(block_size)
      {
      const size_t pad_val =
         buf_size - (iv_size + msg_length + mac_size + 1);

      for(size_t i = 0; i != pad_val + 1; ++i)
         output.push_back(pad_val);
      }

   if(buf_size > MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Produced ciphertext larger than protocol allows");

   BOTAN_ASSERT_EQUAL(buf_size + header_size, output.size(),
                      "Output buffer is sized properly");

   if(BlockCipher* bc = cs->block_cipher())
      {
      secure_vector<byte>& cbc_state = cs->cbc_state();

      BOTAN_ASSERT(buf_size % block_size == 0,
                   "Buffer is an even multiple of block size");

      byte* buf = &output[header_size];

      const size_t blocks = buf_size / block_size;

      xor_buf(buf, cbc_state.data(), block_size);
      bc->encrypt(buf);

      for(size_t i = 1; i < blocks; ++i)
         {
         xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
         bc->encrypt(&buf[block_size*i]);
         }

      cbc_state.assign(&buf[block_size*(blocks-1)],
                       &buf[block_size*blocks]);
      }
   else
      throw Internal_Error("NULL cipher not supported");
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
      const byte delim_mask = CT::is_less<u16bit>(left, pad_byte) & 0xFF;
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
      const secure_vector<byte>& nonce = cs.aead_nonce(record_contents, record_len, record_sequence);
      const byte* msg = &record_contents[cs.nonce_bytes_from_record()];
      const size_t msg_length = record_len - cs.nonce_bytes_from_record();

      const size_t ptext_size = aead->output_length(msg_length);

      aead->set_associated_data_vec(
         cs.format_ad(record_sequence, record_type, record_version, ptext_size)
         );

      output += aead->start(nonce);

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

      // This early exit does not leak info because all the values are public
      if((record_len < mac_size + iv_size) || (record_len % cs.block_size() != 0))
         throw Decoding_Error("Record sent with invalid length");

      CT::poison(record_contents, record_len);

      cbc_decrypt_record(record_contents, record_len, cs, *bc);

      // 0 if padding was invalid, otherwise 1 + padding_bytes
      u16bit pad_size = tls_padding_check(record_contents, record_len);

      // This mask is zero if there is not enough room in the packet
      const u16bit size_ok_mask = CT::is_less<u16bit>(mac_size + pad_size + iv_size, record_len);
      pad_size &= size_ok_mask;

      CT::unpoison(record_contents, record_len);

      /*
      This is unpoisoned sooner than it should. The pad_size leaks to plaintext_length and
      then to the timing channel in the MAC computation described in the Lucky 13 paper.
      */
      CT::unpoison(pad_size);

      const byte* plaintext_block = &record_contents[iv_size];
      const u16bit plaintext_length = record_len - mac_size - iv_size - pad_size;

      cs.mac()->update(cs.format_ad(record_sequence, record_type, record_version, plaintext_length));
      cs.mac()->update(plaintext_block, plaintext_length);

      std::vector<byte> mac_buf(mac_size);
      cs.mac()->final(mac_buf.data());

      const size_t mac_offset = record_len - (mac_size + pad_size);

      const bool mac_ok = same_mem(&record_contents[mac_offset], mac_buf.data(), mac_size);

      const u16bit ok_mask = size_ok_mask & CT::expand_mask<u16bit>(mac_ok) & CT::expand_mask<u16bit>(pad_size);

      CT::unpoison(ok_mask);

      if(ok_mask)
         output.assign(plaintext_block, plaintext_block + plaintext_length);
      else
         throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");
      }
   }

size_t read_tls_record(secure_vector<byte>& readbuf,
                       const byte input[],
                       size_t input_sz,
                       size_t& consumed,
                       secure_vector<byte>& record,
                       u64bit* record_sequence,
                       Protocol_Version* record_version,
                       Record_Type* record_type,
                       Connection_Sequence_Numbers* sequence_numbers,
                       get_cipherstate_fn get_cipherstate)
   {
   consumed = 0;

   if(readbuf.size() < TLS_HEADER_SIZE) // header incomplete?
      {
      if(size_t needed = fill_buffer_to(readbuf,
                                        input, input_sz, consumed,
                                        TLS_HEADER_SIZE))
         return needed;

      BOTAN_ASSERT_EQUAL(readbuf.size(), TLS_HEADER_SIZE, "Have an entire header");
      }

   *record_version = Protocol_Version(readbuf[1], readbuf[2]);

   BOTAN_ASSERT(!record_version->is_datagram_protocol(), "Expected TLS");

   const size_t record_len = make_u16bit(readbuf[TLS_HEADER_SIZE-2],
                                         readbuf[TLS_HEADER_SIZE-1]);

   if(record_len > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Received a record that exceeds maximum size");

   if(record_len == 0)
      throw TLS_Exception(Alert::DECODE_ERROR,
                          "Received a completely empty record");

   if(size_t needed = fill_buffer_to(readbuf,
                                     input, input_sz, consumed,
                                     TLS_HEADER_SIZE + record_len))
      return needed;

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(TLS_HEADER_SIZE) + record_len,
                      readbuf.size(),
                      "Have the full record");

   *record_type = static_cast<Record_Type>(readbuf[0]);

   u16bit epoch = 0;

   if(sequence_numbers)
      {
      *record_sequence = sequence_numbers->next_read_sequence();
      epoch = sequence_numbers->current_read_epoch();
      }
   else
      {
      // server initial handshake case
      *record_sequence = 0;
      epoch = 0;
      }

   byte* record_contents = &readbuf[TLS_HEADER_SIZE];

   if(epoch == 0) // Unencrypted initial handshake
      {
      record.assign(readbuf.begin() + TLS_HEADER_SIZE, readbuf.begin() + TLS_HEADER_SIZE + record_len);
      readbuf.clear();
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext
   auto cs = get_cipherstate(epoch);

   BOTAN_ASSERT(cs, "Have cipherstate for this epoch");

   decrypt_record(record,
                  record_contents,
                  record_len,
                  *record_sequence,
                  *record_version,
                  *record_type,
                  *cs);

   if(sequence_numbers)
      sequence_numbers->read_accept(*record_sequence);

   readbuf.clear();
   return 0;
   }

size_t read_dtls_record(secure_vector<byte>& readbuf,
                        const byte input[],
                        size_t input_sz,
                        size_t& consumed,
                        secure_vector<byte>& record,
                        u64bit* record_sequence,
                        Protocol_Version* record_version,
                        Record_Type* record_type,
                        Connection_Sequence_Numbers* sequence_numbers,
                        get_cipherstate_fn get_cipherstate)
   {
   consumed = 0;

   if(readbuf.size() < DTLS_HEADER_SIZE) // header incomplete?
      {
      if(fill_buffer_to(readbuf, input, input_sz, consumed, DTLS_HEADER_SIZE))
         {
         readbuf.clear();
         return 0;
         }

      BOTAN_ASSERT_EQUAL(readbuf.size(), DTLS_HEADER_SIZE, "Have an entire header");
      }

   *record_version = Protocol_Version(readbuf[1], readbuf[2]);

   BOTAN_ASSERT(record_version->is_datagram_protocol(), "Expected DTLS");

   const size_t record_len = make_u16bit(readbuf[DTLS_HEADER_SIZE-2],
                                         readbuf[DTLS_HEADER_SIZE-1]);

   // Invalid packet:
   if(record_len == 0 || record_len > MAX_CIPHERTEXT_SIZE)
      {
      readbuf.clear();
      return 0;
      }

   if(fill_buffer_to(readbuf, input, input_sz, consumed, DTLS_HEADER_SIZE + record_len))
      {
      // Truncated packet?
      readbuf.clear();
      return 0;
      }

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(DTLS_HEADER_SIZE) + record_len, readbuf.size(),
                      "Have the full record");

   *record_type = static_cast<Record_Type>(readbuf[0]);

   u16bit epoch = 0;

   *record_sequence = load_be<u64bit>(&readbuf[3], 0);
   epoch = (*record_sequence >> 48);

   if(sequence_numbers && sequence_numbers->already_seen(*record_sequence))
      {
      readbuf.clear();
      return 0;
      }

   byte* record_contents = &readbuf[DTLS_HEADER_SIZE];

   if(epoch == 0) // Unencrypted initial handshake
      {
      record.assign(readbuf.begin() + DTLS_HEADER_SIZE, readbuf.begin() + DTLS_HEADER_SIZE + record_len);
      readbuf.clear();
      return 0; // got a full record
      }

   try
      {
      // Otherwise, decrypt, check MAC, return plaintext
      auto cs = get_cipherstate(epoch);

      BOTAN_ASSERT(cs, "Have cipherstate for this epoch");

      decrypt_record(record,
                     record_contents,
                     record_len,
                     *record_sequence,
                     *record_version,
                     *record_type,
                     *cs);
      }
   catch(std::exception)
      {
      readbuf.clear();
      *record_type = NO_RECORD;
      return 0;
      }

   if(sequence_numbers)
      sequence_numbers->read_accept(*record_sequence);

   readbuf.clear();
   return 0;
   }

}

size_t read_record(secure_vector<byte>& readbuf,
                   const byte input[],
                   size_t input_sz,
                   bool is_datagram,
                   size_t& consumed,
                   secure_vector<byte>& record,
                   u64bit* record_sequence,
                   Protocol_Version* record_version,
                   Record_Type* record_type,
                   Connection_Sequence_Numbers* sequence_numbers,
                   get_cipherstate_fn get_cipherstate)
   {
   if(is_datagram)
      return read_dtls_record(readbuf, input, input_sz, consumed,
                              record, record_sequence, record_version, record_type,
                              sequence_numbers, get_cipherstate);
   else
      return read_tls_record(readbuf, input, input_sz, consumed,
                             record, record_sequence, record_version, record_type,
                             sequence_numbers, get_cipherstate);
   }

}

}
