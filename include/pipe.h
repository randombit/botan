/*************************************************
* Pipe Header File                               *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PIPE_H__
#define BOTAN_PIPE_H__

#include <botan/data_src.h>
#include <botan/filter.h>
#include <iosfwd>

namespace Botan {

/*************************************************
* Pipe                                           *
*************************************************/
class BOTAN_DLL Pipe : public DataSource
   {
   public:
      typedef u32bit message_id;

      class Invalid_Message_Number : public Invalid_Argument
         {
         public:
            Invalid_Message_Number(const std::string&, message_id);
         };

      static const message_id LAST_MESSAGE;
      static const message_id DEFAULT_MESSAGE;

      void write(const byte[], u32bit);
      void write(const MemoryRegion<byte>&);
      void write(const std::string&);
      void write(DataSource&);
      void write(byte);

      void process_msg(const byte[], u32bit);
      void process_msg(const MemoryRegion<byte>&);
      void process_msg(const std::string&);
      void process_msg(DataSource&);

      u32bit remaining(message_id = DEFAULT_MESSAGE) const;

      u32bit read(byte[], u32bit);
      u32bit read(byte[], u32bit, message_id);
      u32bit read(byte&, message_id = DEFAULT_MESSAGE);

      SecureVector<byte> read_all(message_id = DEFAULT_MESSAGE);
      std::string read_all_as_string(message_id = DEFAULT_MESSAGE);

      u32bit peek(byte[], u32bit, u32bit) const;
      u32bit peek(byte[], u32bit, u32bit, message_id) const;
      u32bit peek(byte&, u32bit, message_id = DEFAULT_MESSAGE) const;

      message_id default_msg() const { return default_read; }
      void set_default_msg(message_id);
      message_id message_count() const;
      bool end_of_data() const;

      void start_msg();
      void end_msg();

      void prepend(Filter*);
      void append(Filter*);
      void pop();
      void reset();

      Pipe(Filter* = 0, Filter* = 0, Filter* = 0, Filter* = 0);
      Pipe(Filter*[], u32bit);
      ~Pipe();
   private:
      Pipe(const Pipe&) : DataSource() {}
      Pipe& operator=(const Pipe&) { return (*this); }
      void init();
      void destruct(Filter*);
      void find_endpoints(Filter*);
      void clear_endpoints(Filter*);

      message_id get_message_no(const std::string&, message_id) const;

      Filter* pipe;
      class Output_Buffers* outputs;
      message_id default_read;
      bool inside_msg;
   };

/*************************************************
* I/O Operators for Pipe                         *
*************************************************/
BOTAN_DLL std::ostream& operator<<(std::ostream&, Pipe&);
BOTAN_DLL std::istream& operator>>(std::istream&, Pipe&);

}

#endif

#if defined(BOTAN_EXT_PIPE_UNIXFD_IO)
  #include <botan/fd_unix.h>
#endif
