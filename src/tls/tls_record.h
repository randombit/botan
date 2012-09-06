/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_RECORDS_H__
#define BOTAN_TLS_RECORDS_H__

#include <botan/tls_ciphersuite.h>
#include <botan/tls_alert.h>
#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
#include <vector>
#include <functional>
#include <memory>

namespace Botan {

namespace TLS {

class Session_Keys;

/**
* TLS Cipher State
*/
class Connection_Cipher_State
   {
   public:
      /**
      * Create an empty (NULL_WITH_NULL_NULL) cipher state
      */
      Connection_Cipher_State() {}

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
   private:
      std::unique_ptr<BlockCipher> m_block_cipher;
      secure_vector<byte> m_block_cipher_cbc_state;
      std::unique_ptr<StreamCipher> m_stream_cipher;
      std::unique_ptr<MessageAuthenticationCode> m_mac;
      size_t m_block_size = 0;
      size_t m_iv_size = 0;
   };

/**
* TLS Record Writer
*/
class BOTAN_DLL Record_Writer
   {
   public:
      void send_array(byte type, const byte input[], size_t length);

      void send(byte type, const std::vector<byte>& input)
         { send_array(type, &input[0], input.size()); }

      void change_cipher_spec(Connection_Side side,
                              const Ciphersuite& suite,
                              const Session_Keys& keys,
                              byte compression_method);

      void set_version(Protocol_Version version);

      bool record_version_set() const { return m_version.valid(); }

      void reset();

      void set_maximum_fragment_size(size_t max_fragment);

      Record_Writer(std::function<void (const byte[], size_t)> output_fn,
                    RandomNumberGenerator& rng);

      Record_Writer(const Record_Writer&) = delete;
      Record_Writer& operator=(const Record_Writer&) = delete;
   private:
      void send_record(byte type, const byte input[], size_t length);

      std::function<void (const byte[], size_t)> m_output_fn;

      std::vector<byte> m_writebuf;

      std::unique_ptr<Connection_Cipher_State> m_write_cipherstate;

      RandomNumberGenerator& m_rng;

      size_t m_max_fragment = 0;

      u64bit m_write_seq_no = 0;
      Protocol_Version m_version;
   };

/**
* TLS Record Reader
*/
class BOTAN_DLL Record_Reader
   {
   public:

      /**
      * @param input new input data (may be NULL if input_size == 0)
      * @param input_size size of input in bytes
      * @param input_consumed is set to the number of bytes of input
      *        that were consumed
      * @param msg_type is set to the type of the message just read if
      *        this function returns 0
      * @param msg is set to the contents of the record
      * @param msg_sequence is set to this records sequence number
      * @return number of bytes still needed (minimum), or 0 if success
      */
      size_t add_input(const byte input[], size_t input_size,
                       size_t& input_consumed,
                       byte& msg_type,
                       std::vector<byte>& msg,
                       u64bit& msg_sequence);

      void change_cipher_spec(Connection_Side side,
                              const Ciphersuite& suite,
                              const Session_Keys& keys,
                              byte compression_method);

      void set_version(Protocol_Version version);

      Protocol_Version get_version() const;

      void reset();

      void set_maximum_fragment_size(size_t max_fragment);

      Record_Reader();

      Record_Reader(const Record_Reader&) = delete;
      Record_Reader& operator=(const Record_Reader&) = delete;
   private:
      size_t fill_buffer_to(const byte*& input,
                            size_t& input_size,
                            size_t& input_consumed,
                            size_t desired);

      std::vector<byte> m_readbuf;
      std::vector<byte> m_macbuf;
      size_t m_readbuf_pos;

      std::unique_ptr<BlockCipher> m_read_block_cipher;
      secure_vector<byte> m_read_block_cipher_cbc_state;
      std::unique_ptr<StreamCipher> m_read_stream_cipher;
      std::unique_ptr<MessageAuthenticationCode> m_read_mac;

      size_t m_block_size, m_iv_size, m_max_fragment;

      u64bit m_read_seq_no;
      Protocol_Version m_version;
   };

}

}

#endif
