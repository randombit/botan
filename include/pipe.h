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
      typedef Filter::SharedFilterPtrConverter SharedFilterPtrConverter;
      typedef Filter::SharedFilterPtr SharedFilterPtr;

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

      void prepend(SharedFilterPtrConverter const&);
      void append(SharedFilterPtrConverter const&);
      void pop();
      void reset();

      Pipe(SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter(),
           SharedFilterPtrConverter const& = SharedFilterPtrConverter());
      // Assumes that [begin, end) is a range of objects o for which
      // SharedFilterPtrConverter(o) is valid.
      // ConstIter has to be a bidirectional iterator type.
      template<typename ConstIter>
      Pipe(ConstIter const& begin, ConstIter const& end) 
        : pipe(),
          outputs(),
          default_read(0),
          inside_msg(false) {
        this->init();
        for(; begin != end; ++begin) {
          this->append(*begin);
        }
      }
      ~Pipe();
   private:
      Pipe(const Pipe&) : DataSource() {}
      Pipe& operator=(const Pipe&) { return (*this); }
      void init();
      void destruct(Filter::SharedFilterPtr &);
      void find_endpoints(Filter::SharedFilterPtr const&);
      void clear_endpoints(Filter::SharedFilterPtr const&);

      u32bit get_message_no(const std::string&, u32bit) const;

      SharedFilterPtr pipe;
      std::tr1::shared_ptr<class Output_Buffers> outputs;
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
