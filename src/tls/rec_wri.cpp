/*
* TLS Record Writing
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_hash.h>
#include <botan/internal/rounding.h>
#include <botan/internal/assert.h>
#include <botan/internal/xor_buf.h>
#include <botan/loadstor.h>

namespace Botan {

namespace TLS {

/*
* Record_Writer Constructor
*/
Record_Writer::Record_Writer(std::function<void (const byte[], size_t)> out,
                             RandomNumberGenerator& rng) :
   m_output_fn(out),
   m_writebuf(TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE),
   m_rng(rng)
   {
   reset();
   }

void Record_Writer::set_maximum_fragment_size(size_t max_fragment)
   {
   if(max_fragment == 0)
      m_max_fragment = MAX_PLAINTEXT_SIZE;
   else
      m_max_fragment = clamp(max_fragment, 128, MAX_PLAINTEXT_SIZE);
   }

/*
* Reset the state
*/
void Record_Writer::reset()
   {
   set_maximum_fragment_size(0);

   m_write_cipherstate.reset();

   m_version = Protocol_Version();

   m_write_seq_no = 0;
   }

/*
* Set the version to use
*/
void Record_Writer::set_version(Protocol_Version version)
   {
   m_version = version;
   }

/*
* Set the keys for writing
*/
void Record_Writer::change_cipher_spec(Connection_Side side,
                                       const Ciphersuite& suite,
                                       const Session_Keys& keys,
                                       byte compression_method)
   {
   if(compression_method != NO_COMPRESSION)
      throw Internal_Error("Negotiated unknown compression algorithm");

   /*
   RFC 4346:
     A sequence number is incremented after each record: specifically,
     the first record transmitted under a particular connection state
     MUST use sequence number 0
   */
   m_write_seq_no = 0;

   m_write_cipherstate.reset(
      new Connection_Cipher_State(m_version, side, suite, keys)
      );
   }

/*
* Send one or more records to the other side
*/
void Record_Writer::send_array(byte type, const byte input[], size_t length)
   {
   if(length == 0)
      return;

   /*
   * If using CBC mode in SSLv3/TLS v1.0, send a single byte of
   * plaintext to randomize the (implicit) IV of the following main
   * block. If using a stream cipher, or TLS v1.1 or higher, this
   * isn't necessary.
   *
   * An empty record also works but apparently some implementations do
   * not like this (https://bugzilla.mozilla.org/show_bug.cgi?id=665814)
   *
   * See http://www.openssl.org/~bodo/tls-cbc.txt for background.
   */
   if((type == APPLICATION) &&
      (m_write_cipherstate->block_size() > 0) &&
      (m_write_cipherstate->iv_size() == 0))
      {
      send_record(type, &input[0], 1);
      input += 1;
      length -= 1;
      }

   while(length)
      {
      const size_t sending = std::min(length, m_max_fragment);
      send_record(type, &input[0], sending);

      input += sending;
      length -= sending;
      }
   }

/*
* Encrypt and send the record
*/
void Record_Writer::send_record(byte type, const byte input[], size_t length)
   {
   if(length >= MAX_PLAINTEXT_SIZE)
      throw Internal_Error("Record_Writer: Compressed packet is too big");

   if(!m_write_cipherstate) // initial unencrypted handshake records
      {
      m_writebuf[0] = type;
      m_writebuf[1] = m_version.major_version();
      m_writebuf[2] = m_version.minor_version();
      m_writebuf[3] = get_byte<u16bit>(0, length);
      m_writebuf[4] = get_byte<u16bit>(1, length);

      copy_mem(&m_writebuf[TLS_HEADER_SIZE], input, length);

      m_output_fn(&m_writebuf[0], TLS_HEADER_SIZE + length);
      return;
      }

   m_write_cipherstate->mac()->update_be(m_write_seq_no);
   m_write_cipherstate->mac()->update(type);

   if(m_version != Protocol_Version::SSL_V3)
      {
      m_write_cipherstate->mac()->update(m_version.major_version());
      m_write_cipherstate->mac()->update(m_version.minor_version());
      }

   m_write_cipherstate->mac()->update(get_byte<u16bit>(0, length));
   m_write_cipherstate->mac()->update(get_byte<u16bit>(1, length));
   m_write_cipherstate->mac()->update(input, length);

   const size_t block_size = m_write_cipherstate->block_size();
   const size_t iv_size = m_write_cipherstate->iv_size();
   const size_t mac_size = m_write_cipherstate->mac_size();

   const size_t buf_size = round_up(
      iv_size + length + mac_size + (block_size ? 1 : 0),
      block_size);

   if(buf_size >= MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Record_Writer: Record is too big");

   BOTAN_ASSERT(m_writebuf.size() >= TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE,
                "Write buffer is big enough");

   // TLS record header
   m_writebuf[0] = type;
   m_writebuf[1] = m_version.major_version();
   m_writebuf[2] = m_version.minor_version();
   m_writebuf[3] = get_byte<u16bit>(0, buf_size);
   m_writebuf[4] = get_byte<u16bit>(1, buf_size);

   byte* buf_write_ptr = &m_writebuf[TLS_HEADER_SIZE];

   if(iv_size)
      {
      m_rng.randomize(buf_write_ptr, iv_size);
      buf_write_ptr += iv_size;
      }

   copy_mem(buf_write_ptr, input, length);
   buf_write_ptr += length;

   m_write_cipherstate->mac()->final(buf_write_ptr);
   buf_write_ptr += mac_size;

   if(block_size)
      {
      const size_t pad_val =
         buf_size - (iv_size + length + mac_size + 1);

      for(size_t i = 0; i != pad_val + 1; ++i)
         {
         *buf_write_ptr = pad_val;
         buf_write_ptr += 1;
         }
      }

   if(buf_size > MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Produced ciphertext larger than protocol allows");

   if(StreamCipher* sc = m_write_cipherstate->stream_cipher())
      {
      sc->cipher1(&m_writebuf[TLS_HEADER_SIZE], buf_size);
      }
   else if(BlockCipher* bc = m_write_cipherstate->block_cipher())
      {
      secure_vector<byte>& cbc_state = m_write_cipherstate->cbc_state();

      BOTAN_ASSERT(buf_size % block_size == 0,
                   "Buffer is an even multiple of block size");

      byte* buf = &m_writebuf[TLS_HEADER_SIZE];

      const size_t blocks = buf_size / block_size;

      xor_buf(&buf[0], &cbc_state[0], block_size);
      bc->encrypt(&buf[0]);

      for(size_t i = 1; i <= blocks; ++i)
         {
         xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
         bc->encrypt(&buf[block_size*i]);
         }

      cbc_state.assign(&buf[block_size*(blocks-1)],
                       &buf[block_size*blocks]);
      }
   else
      throw Internal_Error("NULL cipher not supported");

   m_output_fn(&m_writebuf[0], TLS_HEADER_SIZE + buf_size);

   m_write_seq_no++;
   }

}

}
