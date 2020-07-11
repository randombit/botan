/*
* TLS Record Handling
* (C) 2012,2013,2014,2015,2016,2019 Jack Lloyd
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
   m_start_time(std::chrono::system_clock::now())
   {
   m_nonce_format = suite.nonce_format();
   m_nonce_bytes_from_record = suite.nonce_bytes_from_record(version);
   m_nonce_bytes_from_handshake = suite.nonce_bytes_from_handshake();

   const secure_vector<uint8_t>& aead_key = keys.aead_key(side);
   m_nonce = keys.nonce(side);

   BOTAN_ASSERT_NOMSG(m_nonce.size() == m_nonce_bytes_from_handshake);

   if(nonce_format() == Nonce_Format::CBC_MODE)
      {
#if defined(BOTAN_HAS_TLS_CBC)
      // legacy CBC+HMAC mode
      auto mac = MessageAuthenticationCode::create_or_throw("HMAC(" + suite.mac_algo() + ")");
      auto cipher = BlockCipher::create_or_throw(suite.cipher_algo());

      if(our_side)
         {
         m_aead.reset(new TLS_CBC_HMAC_AEAD_Encryption(
                         std::move(cipher),
                         std::move(mac),
                         suite.cipher_keylen(),
                         suite.mac_keylen(),
                         version,
                         uses_encrypt_then_mac));
         }
      else
         {
         m_aead.reset(new TLS_CBC_HMAC_AEAD_Decryption(
                         std::move(cipher),
                         std::move(mac),
                         suite.cipher_keylen(),
                         suite.mac_keylen(),
                         version,
                         uses_encrypt_then_mac));
         }

#else
      BOTAN_UNUSED(uses_encrypt_then_mac);
      throw Internal_Error("Negotiated disabled TLS CBC+HMAC ciphersuite");
#endif
      }
   else
      {
      m_aead = AEAD_Mode::create_or_throw(suite.cipher_algo(), our_side ? ENCRYPTION : DECRYPTION);
      }

   m_aead->set_key(aead_key);
   }

std::vector<uint8_t> Connection_Cipher_State::aead_nonce(uint64_t seq, RandomNumberGenerator& rng)
   {
   switch(m_nonce_format)
      {
      case Nonce_Format::CBC_MODE:
         {
         if(m_nonce.size())
            {
            std::vector<uint8_t> nonce;
            nonce.swap(m_nonce);
            return nonce;
            }
         std::vector<uint8_t> nonce(nonce_bytes_from_record());
         rng.randomize(nonce.data(), nonce.size());
         return nonce;
         }
      case Nonce_Format::AEAD_XOR_12:
         {
         std::vector<uint8_t> nonce(12);
         store_be(seq, nonce.data() + 4);
         xor_buf(nonce, m_nonce.data(), m_nonce.size());
         return nonce;
         }
      case Nonce_Format::AEAD_IMPLICIT_4:
         {
         BOTAN_ASSERT_NOMSG(m_nonce.size() == 4);
         std::vector<uint8_t> nonce(12);
         copy_mem(&nonce[0], m_nonce.data(), 4);
         store_be(seq, &nonce[nonce_bytes_from_handshake()]);
         return nonce;
         }
      }

   throw Invalid_State("Unknown nonce format specified");
   }

std::vector<uint8_t>
Connection_Cipher_State::aead_nonce(const uint8_t record[], size_t record_len, uint64_t seq)
   {
   switch(m_nonce_format)
      {
      case Nonce_Format::CBC_MODE:
         {
         if(nonce_bytes_from_record() == 0 && m_nonce.size())
            {
            std::vector<uint8_t> nonce;
            nonce.swap(m_nonce);
            return nonce;
            }
         if(record_len < nonce_bytes_from_record())
            throw Decoding_Error("Invalid CBC packet too short to be valid");
         std::vector<uint8_t> nonce(record, record + nonce_bytes_from_record());
         return nonce;
         }
      case Nonce_Format::AEAD_XOR_12:
         {
         std::vector<uint8_t> nonce(12);
         store_be(seq, nonce.data() + 4);
         xor_buf(nonce, m_nonce.data(), m_nonce.size());
         return nonce;
         }
      case Nonce_Format::AEAD_IMPLICIT_4:
         {
         BOTAN_ASSERT_NOMSG(m_nonce.size() == 4);
         if(record_len < nonce_bytes_from_record())
            throw Decoding_Error("Invalid AEAD packet too short to be valid");
         std::vector<uint8_t> nonce(12);
         copy_mem(&nonce[0], m_nonce.data(), 4);
         copy_mem(&nonce[nonce_bytes_from_handshake()], record, nonce_bytes_from_record());
         return nonce;
         }
      }

   throw Invalid_State("Unknown nonce format specified");
   }

std::vector<uint8_t>
Connection_Cipher_State::format_ad(uint64_t msg_sequence,
                                   uint8_t msg_type,
                                   Protocol_Version version,
                                   uint16_t msg_length)
   {
   std::vector<uint8_t> ad(13);

   store_be(msg_sequence, &ad[0]);
   ad[8] = msg_type;
   ad[9] = version.major_version();
   ad[10] = version.minor_version();
   ad[11] = get_byte(0, msg_length);
   ad[12] = get_byte(1, msg_length);

   return ad;
   }

namespace {

inline void append_u16_len(secure_vector<uint8_t>& output, size_t len_field)
   {
   const uint16_t len16 = static_cast<uint16_t>(len_field);
   BOTAN_ASSERT_EQUAL(len_field, len16, "No truncation");
   output.push_back(get_byte(0, len16));
   output.push_back(get_byte(1, len16));
   }

void write_record_header(secure_vector<uint8_t>& output,
                         uint8_t record_type,
                         Protocol_Version version,
                         uint64_t record_sequence)
   {
   output.clear();

   output.push_back(record_type);
   output.push_back(version.major_version());
   output.push_back(version.minor_version());

   if(version.is_datagram_protocol())
      {
      for(size_t i = 0; i != 8; ++i)
         output.push_back(get_byte(i, record_sequence));
      }
   }

}

void write_unencrypted_record(secure_vector<uint8_t>& output,
                              uint8_t record_type,
                              Protocol_Version version,
                              uint64_t record_sequence,
                              const uint8_t* message,
                              size_t message_len)
   {
   if(record_type == APPLICATION_DATA)
      throw Internal_Error("Writing an unencrypted TLS application data record");
   write_record_header(output, record_type, version, record_sequence);
   append_u16_len(output, message_len);
   output.insert(output.end(), message, message + message_len);
   }

void write_record(secure_vector<uint8_t>& output,
                  uint8_t record_type,
                  Protocol_Version version,
                  uint64_t record_sequence,
                  const uint8_t* message,
                  size_t message_len,
                  Connection_Cipher_State& cs,
                  RandomNumberGenerator& rng)
   {
   write_record_header(output, record_type, version, record_sequence);

   AEAD_Mode& aead = cs.aead();
   std::vector<uint8_t> aad = cs.format_ad(record_sequence, record_type, version, static_cast<uint16_t>(message_len));

   const size_t ctext_size = aead.output_length(message_len);

   const size_t rec_size = ctext_size + cs.nonce_bytes_from_record();

   aead.set_ad(aad);

   const std::vector<uint8_t> nonce = cs.aead_nonce(record_sequence, rng);

   append_u16_len(output, rec_size);

   if(cs.nonce_bytes_from_record() > 0)
      {
      if(cs.nonce_format() == Nonce_Format::CBC_MODE)
         output += nonce;
      else
         output += std::make_pair(&nonce[cs.nonce_bytes_from_handshake()], cs.nonce_bytes_from_record());
      }

   const size_t header_size = output.size();
   output += std::make_pair(message, message_len);

   aead.start(nonce);
   aead.finish(output, header_size);

   BOTAN_ASSERT(output.size() < MAX_CIPHERTEXT_SIZE,
                "Produced ciphertext larger than protocol allows");
   }

namespace {

size_t fill_buffer_to(secure_vector<uint8_t>& readbuf,
                      const uint8_t*& input,
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

void decrypt_record(secure_vector<uint8_t>& output,
                    uint8_t record_contents[], size_t record_len,
                    uint64_t record_sequence,
                    Protocol_Version record_version,
                    Record_Type record_type,
                    Connection_Cipher_State& cs)
   {
   AEAD_Mode& aead = cs.aead();

   const std::vector<uint8_t> nonce = cs.aead_nonce(record_contents, record_len, record_sequence);
   const uint8_t* msg = &record_contents[cs.nonce_bytes_from_record()];
   const size_t msg_length = record_len - cs.nonce_bytes_from_record();

   /*
   * This early rejection is based just on public information (length of the
   * encrypted packet) and so does not leak any information. We used to use
   * decode_error here which really is more appropriate, but that confuses some
   * tools which are attempting automated detection of padding oracles,
   * including older versions of TLS-Attacker.
   */
   if(msg_length < aead.minimum_final_size())
      throw TLS_Exception(Alert::BAD_RECORD_MAC, "AEAD packet is shorter than the tag");

   const size_t ptext_size = aead.output_length(msg_length);

   aead.set_associated_data_vec(
      cs.format_ad(record_sequence,
                   static_cast<uint8_t>(record_type),
                   record_version,
                   static_cast<uint16_t>(ptext_size))
      );

   aead.start(nonce);

   output.assign(msg, msg + msg_length);
   aead.finish(output, 0);
   }

Record_Header read_tls_record(secure_vector<uint8_t>& readbuf,
                              const uint8_t input[],
                              size_t input_len,
                              size_t& consumed,
                              secure_vector<uint8_t>& recbuf,
                              Connection_Sequence_Numbers* sequence_numbers,
                              get_cipherstate_fn get_cipherstate)
   {
   if(readbuf.size() < TLS_HEADER_SIZE) // header incomplete?
      {
      if(size_t needed = fill_buffer_to(readbuf, input, input_len, consumed, TLS_HEADER_SIZE))
         {
         return Record_Header(needed);
         }

      BOTAN_ASSERT_EQUAL(readbuf.size(), TLS_HEADER_SIZE, "Have an entire header");
      }

   const Protocol_Version version(readbuf[1], readbuf[2]);

   if(version.is_datagram_protocol())
      throw TLS_Exception(Alert::PROTOCOL_VERSION,
                          "Expected TLS but got a record with DTLS version");

   const size_t record_size = make_uint16(readbuf[TLS_HEADER_SIZE-2],
                                          readbuf[TLS_HEADER_SIZE-1]);

   if(record_size > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Received a record that exceeds maximum size");

   if(record_size == 0)
      throw TLS_Exception(Alert::DECODE_ERROR,
                          "Received a completely empty record");

   if(size_t needed = fill_buffer_to(readbuf, input, input_len, consumed, TLS_HEADER_SIZE + record_size))
      {
      return Record_Header(needed);
      }

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(TLS_HEADER_SIZE) + record_size,
                      readbuf.size(),
                      "Have the full record");

   const Record_Type type = static_cast<Record_Type>(readbuf[0]);

   uint16_t epoch = 0;

   uint64_t sequence = 0;
   if(sequence_numbers)
      {
      sequence = sequence_numbers->next_read_sequence();
      epoch = sequence_numbers->current_read_epoch();
      }
   else
      {
      // server initial handshake case
      epoch = 0;
      }

   if(epoch == 0) // Unencrypted initial handshake
      {
      recbuf.assign(readbuf.begin() + TLS_HEADER_SIZE, readbuf.begin() + TLS_HEADER_SIZE + record_size);
      readbuf.clear();
      return Record_Header(sequence, version, type);
      }

   // Otherwise, decrypt, check MAC, return plaintext
   auto cs = get_cipherstate(epoch);

   BOTAN_ASSERT(cs, "Have cipherstate for this epoch");

   decrypt_record(recbuf,
                  &readbuf[TLS_HEADER_SIZE],
                  record_size,
                  sequence,
                  version,
                  type,
                  *cs);

   if(sequence_numbers)
      sequence_numbers->read_accept(sequence);

   readbuf.clear();
   return Record_Header(sequence, version, type);
   }

Record_Header read_dtls_record(secure_vector<uint8_t>& readbuf,
                               const uint8_t input[],
                               size_t input_len,
                               size_t& consumed,
                               secure_vector<uint8_t>& recbuf,
                               Connection_Sequence_Numbers* sequence_numbers,
                               get_cipherstate_fn get_cipherstate,
                               bool allow_epoch0_restart)
   {
   if(readbuf.size() < DTLS_HEADER_SIZE) // header incomplete?
      {
      if(fill_buffer_to(readbuf, input, input_len, consumed, DTLS_HEADER_SIZE))
         {
         readbuf.clear();
         return Record_Header(0);
         }

      BOTAN_ASSERT_EQUAL(readbuf.size(), DTLS_HEADER_SIZE, "Have an entire header");
      }

   const Protocol_Version version(readbuf[1], readbuf[2]);

   if(version.is_datagram_protocol() == false)
      {
      readbuf.clear();
      return Record_Header(0);
      }

   const size_t record_size = make_uint16(readbuf[DTLS_HEADER_SIZE-2],
                                          readbuf[DTLS_HEADER_SIZE-1]);

   if(record_size > MAX_CIPHERTEXT_SIZE)
      {
      // Too large to be valid, ignore it
      readbuf.clear();
      return Record_Header(0);
      }

   if(fill_buffer_to(readbuf, input, input_len, consumed, DTLS_HEADER_SIZE + record_size))
      {
      // Truncated packet?
      readbuf.clear();
      return Record_Header(0);
      }

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(DTLS_HEADER_SIZE) + record_size, readbuf.size(),
                      "Have the full record");

   const Record_Type type = static_cast<Record_Type>(readbuf[0]);

   const uint64_t sequence = load_be<uint64_t>(&readbuf[3], 0);
   const uint16_t epoch = (sequence >> 48);

   const bool already_seen = sequence_numbers && sequence_numbers->already_seen(sequence);

   if(already_seen && !(epoch == 0 && allow_epoch0_restart))
      {
      readbuf.clear();
      return Record_Header(0);
      }

   if(epoch == 0) // Unencrypted initial handshake
      {
      recbuf.assign(readbuf.begin() + DTLS_HEADER_SIZE, readbuf.begin() + DTLS_HEADER_SIZE + record_size);
      readbuf.clear();
      if(sequence_numbers)
         sequence_numbers->read_accept(sequence);
      return Record_Header(sequence, version, type);
      }

   try
      {
      // Otherwise, decrypt, check MAC, return plaintext
      auto cs = get_cipherstate(epoch);

      BOTAN_ASSERT(cs, "Have cipherstate for this epoch");

      decrypt_record(recbuf,
                     &readbuf[DTLS_HEADER_SIZE],
                     record_size,
                     sequence,
                     version,
                     type,
                     *cs);
      }
   catch(std::exception&)
      {
      readbuf.clear();
      return Record_Header(0);
      }

   if(sequence_numbers)
      sequence_numbers->read_accept(sequence);

   readbuf.clear();
   return Record_Header(sequence, version, type);
   }

}

Record_Header read_record(bool is_datagram,
                          secure_vector<uint8_t>& readbuf,
                          const uint8_t input[],
                          size_t input_len,
                          size_t& consumed,
                          secure_vector<uint8_t>& recbuf,
                          Connection_Sequence_Numbers* sequence_numbers,
                          get_cipherstate_fn get_cipherstate,
                          bool allow_epoch0_restart)
   {
   if(is_datagram)
      return read_dtls_record(readbuf, input, input_len, consumed,
                              recbuf, sequence_numbers, get_cipherstate, allow_epoch0_restart);
   else
      return read_tls_record(readbuf, input, input_len, consumed,
                             recbuf, sequence_numbers, get_cipherstate);
   }

}

}
