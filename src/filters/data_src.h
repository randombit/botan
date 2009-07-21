/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DATA_SRC_H__
#define BOTAN_DATA_SRC_H__

#include <botan/secmem.h>
#include <string>
#include <iosfwd>

namespace Botan {

/**
* This class represents an abstract data source object.
*/
class BOTAN_DLL DataSource
   {
   public:
      /**
      * Read from the source. Moves the internal offset so that
      * every call to read will return a new portion of the source.
      * @param out the byte array to write the result to
      * @param length the length of the byte array out
      * @return the length in bytes that was actually read and put
      * into out
      */
      virtual u32bit read(byte out[], u32bit length) = 0;

      /**
      * Read from the source but do not modify the internal offset. Consecutive
      * calls to peek() will return portions of the source starting at the same
      * position.
      * @param out the byte array to write the output to
      * @param length the length of the byte array out
      * @return the length in bytes that was actually read and put
      * into out
      */
      virtual u32bit peek(byte out[], u32bit length,
                          u32bit peek_offset) const = 0;

      /**
      * Test whether the source still has data that can be read.
      * @return true if there is still data to read, false otherwise
      */
      virtual bool end_of_data() const = 0;
      /**
      * return the id of this data source
      * @return the std::string representing the id of this data source
      */
      virtual std::string id() const { return ""; }

      /**
      * Read one byte.
      * @param the byte to read to
      * @return the length in bytes that was actually read and put
      * into out
      */
      u32bit read_byte(byte& out);

      /**
      * Peek at one byte.
      * @param the byte to read to
      * @return the length in bytes that was actually read and put
      * into out
      */
      u32bit peek_byte(byte& out) const;

      /**
      * Discard the next N bytes of the data
      * @param N the number of bytes to discard
      * @return the number of bytes actually discarded
      */
      u32bit discard_next(u32bit N);

      DataSource() {}
      virtual ~DataSource() {}
   private:
      DataSource& operator=(const DataSource&) { return (*this); }
      DataSource(const DataSource&);
   };

/**
* This class represents a Memory-Based DataSource
*/
class BOTAN_DLL DataSource_Memory : public DataSource
   {
   public:
      u32bit read(byte[], u32bit);
      u32bit peek(byte[], u32bit, u32bit) const;
      bool end_of_data() const;

      /**
      * Construct a memory source that reads from a string
      * @param in the string to read from
      */
      DataSource_Memory(const std::string& in);

      /**
      * Construct a memory source that reads from a byte array
      * @param in the byte array to read from
      * @param length the length of the byte array
      */
      DataSource_Memory(const byte in[], u32bit length);

      /**
      * Construct a memory source that reads from a MemoryRegion
      * @param in the MemoryRegion to read from
      */
      DataSource_Memory(const MemoryRegion<byte>& in);
   private:
      SecureVector<byte> source;
      u32bit offset;
   };

/**
* This class represents a Stream-Based DataSource.
*/
class BOTAN_DLL DataSource_Stream : public DataSource
   {
   public:
      u32bit read(byte[], u32bit);
      u32bit peek(byte[], u32bit, u32bit) const;
      bool end_of_data() const;
      std::string id() const;

      DataSource_Stream(std::istream&, const std::string& id = "");

      /**
      * Construct a Stream-Based DataSource from file
      * @param file the name of the file
      * @param use_binary whether to treat the file as binary or not
      */
      DataSource_Stream(const std::string& file, bool use_binary = false);

      ~DataSource_Stream();
   private:
      const std::string identifier;
      const bool owner;

      std::istream* source;
      u32bit total_read;
   };

}

#endif
