/*
* TLS Record Writing
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/tls_magic.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/rounding.h>

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
   if((type == APPLICATION_DATA) &&
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

   const size_t written = write_record(m_writebuf,
                                       type,
                                       input,
                                       length,
                                       m_write_seq_no,
                                       m_version,
                                       m_write_cipherstate.get(),
                                       m_rng);

   m_write_seq_no += 1;
   m_output_fn(&m_writebuf[0], written);
   }

}

}
