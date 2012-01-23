/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_RECORDS_H__
#define BOTAN_TLS_RECORDS_H__

#include <botan/tls_suites.h>
#include <botan/tls_version.h>
#include <botan/pipe.h>
#include <botan/mac.h>
#include <botan/secqueue.h>
#include <vector>

#if defined(BOTAN_USE_STD_TR1)

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
    #include <functional>
#else
    #include <tr1/functional>
#endif

#elif defined(BOTAN_USE_BOOST_TR1)
  #include <boost/tr1/functional.hpp>
#else
  #error "No TR1 library defined for use"
#endif

namespace Botan {

namespace TLS {

class Session_Keys;

/**
* TLS Record Writer
*/
class BOTAN_DLL Record_Writer
   {
   public:
      void send(byte type, const byte input[], size_t length);
      void send(byte type, byte val) { send(type, &val, 1); }

      void alert(Alert_Level level, Alert_Type type);

      void activate(const Ciphersuite& suite,
                    const Session_Keys& keys,
                    Connection_Side side);

      void set_version(Protocol_Version version);

      void reset();

      void set_maximum_fragment_size(size_t max_fragment);

      Record_Writer(std::tr1::function<void (const byte[], size_t)> output_fn);

      ~Record_Writer() { delete m_mac; }
   private:
      Record_Writer(const Record_Writer&) {}
      Record_Writer& operator=(const Record_Writer&) { return (*this); }

      void send_record(byte type, const byte input[], size_t length);

      std::tr1::function<void (const byte[], size_t)> m_output_fn;

      MemoryVector<byte> m_writebuf;

      Pipe m_cipher;
      MessageAuthenticationCode* m_mac;

      size_t m_block_size, m_mac_size, m_iv_size, m_max_fragment;

      u64bit m_seq_no;
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
      * @return number of bytes still needed (minimum), or 0 if success
      */
      size_t add_input(const byte input[], size_t input_size,
                       size_t& input_consumed,
                       byte& msg_type,
                       MemoryVector<byte>& msg);

      void activate(const Ciphersuite& suite,
                    const Session_Keys& keys,
                    Connection_Side side);

      void set_version(Protocol_Version version);

      void reset();

      void set_maximum_fragment_size(size_t max_fragment);

      Record_Reader();

      ~Record_Reader() { delete m_mac; }
   private:
      Record_Reader(const Record_Reader&) {}
      Record_Reader& operator=(const Record_Reader&) { return (*this); }

      size_t fill_buffer_to(const byte*& input,
                            size_t& input_size,
                            size_t& input_consumed,
                            size_t desired);

      MemoryVector<byte> m_readbuf;
      MemoryVector<byte> m_macbuf;
      size_t m_readbuf_pos;

      Pipe m_cipher;
      MessageAuthenticationCode* m_mac;
      size_t m_block_size, m_iv_size, m_max_fragment;
      u64bit m_seq_no;
      Protocol_Version m_version;
   };

}

}

#endif
