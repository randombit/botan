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

#if defined(BOTAN_HAS_TLS_CBC)
  #include <botan/internal/tls_cbc.h>
#endif

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

   BOTAN_ASSERT_EQUAL(iv.length(), nonce_bytes_from_handshake(), "Matching nonce sizes");

   m_nonce = unlock(iv.bits_of());

   if(suite.mac_algo() == "AEAD")
      {
      m_aead.reset(get_aead(suite.cipher_algo(), our_side ? ENCRYPTION : DECRYPTION));
      BOTAN_ASSERT(m_aead, "Have AEAD");

      m_aead->set_key(cipher_key + mac_key);

      BOTAN_ASSERT(nonce_bytes_from_record() == 0 || nonce_bytes_from_record() == 8,
                   "Ciphersuite uses implemented IV length");

      m_cbc_nonce = false;
      if(m_nonce.size() != 12)
         {
         m_nonce.resize(m_nonce.size() + 8);
         }
      }
   else
      {
#if defined(BOTAN_HAS_TLS_CBC)
      // legacy CBC+HMAC mode
      if(our_side)
         {
         m_aead.reset(new TLS_CBC_HMAC_AEAD_Encryption(
                         suite.cipher_algo(),
                         suite.cipher_keylen(),
                         suite.mac_algo(),
                         suite.mac_keylen(),
                         version.supports_explicit_cbc_ivs(),
                         uses_encrypt_then_mac));
         }
      else
         {
         m_aead.reset(new TLS_CBC_HMAC_AEAD_Decryption(
                         suite.cipher_algo(),
                         suite.cipher_keylen(),
                         suite.mac_algo(),
                         suite.mac_keylen(),
                         version.supports_explicit_cbc_ivs(),
                         uses_encrypt_then_mac));
         }

      m_aead->set_key(cipher_key + mac_key);

      m_cbc_nonce = true;
      if(version.supports_explicit_cbc_ivs())
         m_nonce_bytes_from_record = m_nonce_bytes_from_handshake;
      else if(our_side == false)
         m_aead->start(iv.bits_of());
#else
      throw Exception("Negotiated disabled TLS CBC+HMAC ciphersuite");
#endif
      }
   }

std::vector<byte> Connection_Cipher_State::aead_nonce(u64bit seq, RandomNumberGenerator& rng)
   {
   if(m_cbc_nonce)
      {
      if(m_nonce.size())
         {
         std::vector<byte> nonce;
         nonce.swap(m_nonce);
         return nonce;
         }
      std::vector<byte> nonce(nonce_bytes_from_record());
      rng.randomize(nonce.data(), nonce.size());
      return nonce;
      }
   else if(nonce_bytes_from_handshake() == 12)
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
   if(m_cbc_nonce)
      {
      if(record_len < nonce_bytes_from_record())
         throw Decoding_Error("Invalid CBC packet too short to be valid");
      std::vector<byte> nonce(record, record + nonce_bytes_from_record());
      return nonce;
      }
   else if(nonce_bytes_from_handshake() == 12)
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

   AEAD_Mode* aead = cs->aead();
   std::vector<byte> aad = cs->format_ad(seq, msg.get_type(), version, static_cast<u16bit>(msg.get_size()));

   const size_t ctext_size = aead->output_length(msg.get_size());

   const size_t rec_size = ctext_size + cs->nonce_bytes_from_record();

   aead->set_ad(aad);

   const std::vector<byte> nonce = cs->aead_nonce(seq, rng);

   append_u16_len(output, rec_size);

   if(cs->nonce_bytes_from_record() > 0)
      {
      if(cs->cbc_nonce())
         output += nonce;
      else
         output += std::make_pair(&nonce[cs->nonce_bytes_from_handshake()], cs->nonce_bytes_from_record());
      }

   const size_t header_size = output.size();
   output += std::make_pair(msg.get_data(), msg.get_size());

   aead->start(nonce);
   aead->finish(output, header_size);

   BOTAN_ASSERT(output.size() < MAX_CIPHERTEXT_SIZE,
                "Produced ciphertext larger than protocol allows");
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

void decrypt_record(secure_vector<byte>& output,
                    byte record_contents[], size_t record_len,
                    u64bit record_sequence,
                    Protocol_Version record_version,
                    Record_Type record_type,
                    Connection_Cipher_State& cs)
   {
   AEAD_Mode* aead = cs.aead();
   BOTAN_ASSERT(aead, "Cannot decrypt without cipher");

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
