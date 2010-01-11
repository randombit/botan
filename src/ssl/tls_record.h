/**
* TLS Record Handling Header File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_RECORDS_H__
#define BOTAN_RECORDS_H__

#include <botan/tls_session_key.h>
#include <botan/tls_suites.h>
#include <botan/socket.h>
#include <botan/pipe.h>
#include <vector>

namespace Botan {

/**
* TLS Record Writer
*/
class BOTAN_DLL Record_Writer
   {
   public:
      void send(byte, const byte[], u32bit);
      void send(byte, byte);
      void flush();

      void alert(Alert_Level, Alert_Type);

      void set_keys(const CipherSuite&, const SessionKeys&, Connection_Side);
      void set_compressor(Filter*);

      void set_version(Version_Code);

      void reset();

      Record_Writer(Socket&);
   private:
      void send_record(byte, const byte[], u32bit);
      void send_record(byte, byte, byte, const byte[], u32bit);

      Socket& socket;
      Pipe compress, cipher, mac;
      SecureVector<byte> buffer;
      u32bit pad_amount, mac_size, buf_pos;
      u64bit seq_no;
      byte major, minor, buf_type;
      bool do_compress;
   };

/**
* TLS Record Reader
*/
class BOTAN_DLL Record_Reader
   {
   public:
      SecureVector<byte> get_record(byte&);

      void set_keys(const CipherSuite&, const SessionKeys&, Connection_Side);
      void set_compressor(Filter*);

      void set_version(Version_Code);

      void reset();

      Record_Reader(Socket&);
   private:
      Socket& socket;
      Pipe compress, cipher, mac;
      u32bit pad_amount, mac_size;
      u64bit seq_no;
      byte major, minor;
      bool do_compress;
   };

}

#endif
