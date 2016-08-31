/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*     2016 Matthias Gierlings
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_RECORDS_H__
#define BOTAN_TLS_RECORDS_H__

#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/mac.h>
#include <vector>
#include <chrono>

namespace Botan {

namespace TLS {

class Ciphersuite;
class Session_Keys;

class Connection_Sequence_Numbers;

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
                              Connection_Side which_side,
                              bool is_our_side,
                              const Ciphersuite& suite,
                              const Session_Keys& keys,
                              bool uses_encrypt_then_mac);

      AEAD_Mode* aead() { return m_aead.get(); }

      std::vector<byte> aead_nonce(u64bit seq);

      std::vector<byte> aead_nonce(const byte record[], size_t record_len, u64bit seq);

      std::vector<byte> format_ad(u64bit seq, byte type,
                                  Protocol_Version version,
                                  u16bit ptext_length);

      BlockCipher* block_cipher() { return m_block_cipher.get(); }

      MessageAuthenticationCode* mac() { return m_mac.get(); }

      secure_vector<byte>& cbc_state() { return m_block_cipher_cbc_state; }

      size_t block_size() const { return m_block_size; }

      size_t mac_size() const { return m_mac->output_length(); }

      size_t iv_size() const { return m_iv_size; }

      size_t nonce_bytes_from_record() const { return m_nonce_bytes_from_record; }

      size_t nonce_bytes_from_handshake() const { return m_nonce_bytes_from_handshake; }

      bool uses_encrypt_then_mac() const { return m_uses_encrypt_then_mac; }

      bool cbc_without_explicit_iv() const
         { return (m_block_size > 0) && (m_iv_size == 0); }

      std::chrono::seconds age() const
         {
         return std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now() - m_start_time);
         }

   private:
      std::chrono::system_clock::time_point m_start_time;
      std::unique_ptr<BlockCipher> m_block_cipher;
      secure_vector<byte> m_block_cipher_cbc_state;
      std::unique_ptr<MessageAuthenticationCode> m_mac;

      std::unique_ptr<AEAD_Mode> m_aead;
      std::vector<byte> m_nonce;

      size_t m_block_size = 0;
      size_t m_nonce_bytes_from_handshake;
      size_t m_nonce_bytes_from_record;
      size_t m_iv_size = 0;
      
      bool m_uses_encrypt_then_mac;
   };

class Record
   {
   public:
      Record(secure_vector<byte>& data,
             u64bit* sequence,
             Protocol_Version* protocol_version,
             Record_Type* type)
         : m_data(data), m_sequence(sequence), m_protocol_version(protocol_version),
           m_type(type), m_size(data.size()) {};

      secure_vector<byte>& get_data() { return m_data; }

      Protocol_Version* get_protocol_version() { return m_protocol_version; }

      u64bit* get_sequence() { return m_sequence; }

      Record_Type* get_type() { return m_type; }

      size_t& get_size() { return m_size; }

   private:
      secure_vector<byte>& m_data;
      u64bit* m_sequence;
      Protocol_Version* m_protocol_version;
      Record_Type* m_type;
      size_t m_size;
   };

class Record_Message
   {
   public:
      Record_Message(const byte* data, size_t size)
         : m_type(0), m_sequence(0), m_data(data), m_size(size) {};
      Record_Message(byte type, u64bit sequence, const byte* data, size_t size)
         : m_type(type), m_sequence(sequence), m_data(data),
           m_size(size) {};

      byte& get_type() { return m_type; };
      u64bit& get_sequence() { return m_sequence; };
      const byte* get_data() { return m_data; };
      size_t& get_size() { return m_size; };

   private:
      byte m_type;
      u64bit m_sequence;
      const byte* m_data;
      size_t m_size;
};

class Record_Raw_Input
   {
   public:
      Record_Raw_Input(const byte* data, size_t size, size_t& consumed,
                       bool is_datagram)
         : m_data(data), m_size(size), m_consumed(consumed),
           m_is_datagram(is_datagram) {};

      const byte*& get_data() { return m_data; };

      size_t& get_size() { return m_size; };

      size_t& get_consumed() { return m_consumed; };
      void set_consumed(size_t consumed) { m_consumed = consumed; }

      bool is_datagram() { return m_is_datagram; };

   private:
      const byte* m_data;
      size_t m_size;
      size_t& m_consumed;
      bool m_is_datagram;
   };


/**
* Create a TLS record
* @param write_buffer the output record is placed here
* @param msg_type is the type of the message (handshake, alert, ...)
* @param msg is the plaintext message
* @param msg_length is the length of msg
* @param msg_sequence is the sequence number
* @param version is the protocol version
* @param cipherstate is the writing cipher state
* @param rng is a random number generator
* @return number of bytes written to write_buffer
*/
void write_record(secure_vector<byte>& write_buffer,
                  Record_Message rec_msg,
                  Protocol_Version version,
                  u64bit msg_sequence,
                  Connection_Cipher_State* cipherstate,
                  RandomNumberGenerator& rng);

// epoch -> cipher state
typedef std::function<std::shared_ptr<Connection_Cipher_State> (u16bit)> get_cipherstate_fn;

/**
* Decode a TLS record
* @return zero if full message, else number of bytes still needed
*/
size_t read_record(secure_vector<byte>& read_buffer,
                   Record_Raw_Input& raw_input,
                   Record& rec,
                   Connection_Sequence_Numbers* sequence_numbers,
                   get_cipherstate_fn get_cipherstate);

}

}

#endif
