/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_RECORDS_H__
#define BOTAN_TLS_RECORDS_H__

#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
#include <vector>
#include <memory>

namespace Botan {

namespace TLS {

class Ciphersuite;
class Session_Keys;

/**
* TLS Cipher State
*/
class Connection_Cipher_State
   {
   public:
      /**
      * Initialize a new cipher state
      */
      Connection_Cipher_State(Protocol_Version version,
                              Connection_Side side,
                              const Ciphersuite& suite,
                              const Session_Keys& keys);

      BlockCipher* block_cipher() { return m_block_cipher.get(); }

      StreamCipher* stream_cipher() { return m_stream_cipher.get(); }

      MessageAuthenticationCode* mac() { return m_mac.get(); }

      secure_vector<byte>& cbc_state() { return m_block_cipher_cbc_state; }

      size_t block_size() const { return m_block_size; }

      size_t mac_size() const { return m_mac->output_length(); }

      size_t iv_size() const { return m_iv_size; }

      bool mac_includes_record_version() const { return !m_is_ssl3; }

      bool cipher_padding_single_byte() const { return m_is_ssl3; }
   private:
      std::unique_ptr<BlockCipher> m_block_cipher;
      secure_vector<byte> m_block_cipher_cbc_state;
      std::unique_ptr<StreamCipher> m_stream_cipher;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      size_t m_block_size = 0;
      size_t m_iv_size = 0;
      bool m_is_ssl3 = false;
   };

/**
* Create a TLS record
* @param write_buffer the output record is placed here
* @param msg_type is the type of the message (handshake, alert, ...)
* @param msg is the plaintext message
* @param msg_length is the length of msg
* @param msg_sequence_number is the sequence number
* @param version is the protocol version
* @param cipherstate is the writing cipher state
* @param rng is a random number generator
* @return number of bytes written to write_buffer
*/
void write_record(std::vector<byte>& write_buffer,
                  byte msg_type, const byte msg[], size_t msg_length,
                  u64bit msg_sequence_number,
                  Protocol_Version version,
                  Connection_Cipher_State* cipherstate,
                  RandomNumberGenerator& rng);

/**
* Decode a TLS record
* @return zero if full message, else number of bytes still needed
*/
size_t read_record(std::vector<byte>& read_buffer,
                   size_t& read_buffer_position,
                   const byte input[],
                   size_t input_length,
                   size_t& input_consumed,
                   byte& msg_type,
                   std::vector<byte>& msg,
                   u64bit msg_sequence,
                   Protocol_Version& record_version,
                   Connection_Cipher_State* cipherstate);

}

}

#endif
