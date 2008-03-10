/*************************************************
* Pipe Header File                               *
* (C) 1999-2007 The Botan Project                *
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
class Pipe : public DataSource
   {
   public:
      static const u32bit LAST_MESSAGE, DEFAULT_MESSAGE;

      void write(const byte[], u32bit);
      void write(const MemoryRegion<byte>&);
      void write(const std::string&);
      void write(DataSource&);
      void write(byte);

      void process_msg(const byte[], u32bit);
      void process_msg(const MemoryRegion<byte>&);
      void process_msg(const std::string&);
      void process_msg(DataSource&);

      u32bit remaining(u32bit = DEFAULT_MESSAGE) const;

      u32bit read(byte[], u32bit);
      u32bit read(byte[], u32bit, u32bit);
      u32bit read(byte&, u32bit = DEFAULT_MESSAGE);

      SecureVector<byte> read_all(u32bit = DEFAULT_MESSAGE);
      std::string read_all_as_string(u32bit = DEFAULT_MESSAGE);

      u32bit peek(byte[], u32bit, u32bit) const;
      u32bit peek(byte[], u32bit, u32bit, u32bit) const;
      u32bit peek(byte&, u32bit, u32bit = DEFAULT_MESSAGE) const;

      u32bit default_msg() const { return default_read; }
      void set_default_msg(u32bit);
      u32bit message_count() const;
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

      u32bit get_message_no(const std::string&, u32bit) const;

      Filter* pipe;
      class Output_Buffers* outputs;
      u32bit default_read;
      bool inside_msg;
   };

/*************************************************
* I/O Operators for Pipe                         *
*************************************************/
std::ostream& operator<<(std::ostream&, Pipe&);
std::istream& operator>>(std::istream&, Pipe&);

}

#endif

#if defined(BOTAN_EXT_PIPE_UNIXFD_IO)
  #include <botan/fd_unix.h>
#endif
