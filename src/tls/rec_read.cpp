/*
* TLS Record Reading
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_record.h>
#include <botan/tls_exceptn.h>
#include <botan/internal/rounding.h>

namespace Botan {

namespace TLS {

Record_Reader::Record_Reader() :
   m_readbuf(TLS_HEADER_SIZE + MAX_CIPHERTEXT_SIZE)
   {
   reset();
   set_maximum_fragment_size(0);
   }

/*
* Reset the state
*/
void Record_Reader::reset()
   {
   set_maximum_fragment_size(0);

   m_macbuf.clear();

   zeroise(m_readbuf);
   m_readbuf_pos = 0;

   m_read_cipherstate.reset();

   m_version = Protocol_Version();
   m_read_seq_no = 0;
   }

void Record_Reader::set_maximum_fragment_size(size_t max_fragment)
   {
   if(max_fragment == 0)
      m_max_fragment = MAX_PLAINTEXT_SIZE;
   else
      m_max_fragment = clamp(max_fragment, 128, MAX_PLAINTEXT_SIZE);
   }

/*
* Set the version to use
*/
void Record_Reader::set_version(Protocol_Version version)
   {
   m_version = version;
   }

Protocol_Version Record_Reader::get_version() const
   {
   return m_version;
   }

/*
* Set the keys for reading
*/
void Record_Reader::change_cipher_spec(Connection_Side side,
                                       const Ciphersuite& suite,
                                       const Session_Keys& keys,
                                       byte compression_method)
   {
   if(compression_method != NO_COMPRESSION)
      throw Internal_Error("Negotiated unknown compression algorithm");

   m_read_seq_no = 0;

   // flip side as we are reading
   side = (side == CLIENT) ? SERVER : CLIENT;

   m_read_cipherstate.reset(
      new Connection_Cipher_State(m_version, side, suite, keys)
      );

   m_macbuf.resize(m_read_cipherstate->mac_size());
   }

/*
* Retrieve the next record
*/
size_t Record_Reader::add_input(const byte input_array[], size_t input_sz,
                                size_t& consumed,
                                byte& msg_type,
                                std::vector<byte>& msg,
                                u64bit& msg_sequence)
   {
   const size_t needed = read_record(m_readbuf,
                                     m_readbuf_pos,
                                     input_array,
                                     input_sz,
                                     consumed,
                                     msg_type,
                                     msg,
                                     m_read_seq_no,
                                     m_version,
                                     m_read_cipherstate.get());

   if(needed)
      return needed;

   // full message decoded
   if(msg.size() > m_max_fragment)
      throw TLS_Exception(Alert::RECORD_OVERFLOW, "Plaintext record is too large");

   msg_sequence = m_read_seq_no;
   m_read_seq_no += 1;

   return 0;
   }

}

}
