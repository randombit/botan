/*************************************************
* DataSource Header File                         *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_DATA_SRC_H__
#define BOTAN_DATA_SRC_H__

#include <botan/base.h>
#include <iosfwd>

namespace Botan {

/*************************************************
* Generic DataSource Interface                   *
*************************************************/
class DataSource
   {
   public:
      virtual u32bit read(byte[], u32bit) = 0;
      virtual u32bit peek(byte[], u32bit, u32bit) const = 0;
      virtual bool end_of_data() const = 0;
      virtual std::string id() const { return ""; }

      u32bit read_byte(byte&);
      u32bit peek_byte(byte&) const;
      u32bit discard_next(u32bit);

      DataSource() {}
      virtual ~DataSource() {}
   private:
      DataSource& operator=(const DataSource&) { return (*this); }
      DataSource(const DataSource&);
   };

/*************************************************
* Memory-Based DataSource                        *
*************************************************/
class DataSource_Memory : public DataSource
   {
   public:
      u32bit read(byte[], u32bit);
      u32bit peek(byte[], u32bit, u32bit) const;
      bool end_of_data() const;

      DataSource_Memory(const std::string&);
      DataSource_Memory(const byte[], u32bit);
      DataSource_Memory(const MemoryRegion<byte>&);
   private:
      SecureVector<byte> source;
      u32bit offset;
   };

/*************************************************
* Stream-Based DataSource                        *
*************************************************/
class DataSource_Stream : public DataSource
   {
   public:
      u32bit read(byte[], u32bit);
      u32bit peek(byte[], u32bit, u32bit) const;
      bool end_of_data() const;
      std::string id() const;

      DataSource_Stream(const std::string&, bool = false);
      ~DataSource_Stream();
   private:
      const std::string fsname;
      std::istream* source;
      u32bit total_read;
   };

}

#endif
