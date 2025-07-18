/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_DATA_SRC_H_
#define BOTAN_DATA_SRC_H_

#include <botan/secmem.h>
#include <iosfwd>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace Botan {

/**
* This class represents an abstract data source object.
*/
class BOTAN_PUBLIC_API(2, 0) DataSource {
   public:
      /**
      * Read from the source. Moves the internal offset so that every
      * call to read will return a new portion of the source.
      *
      * @param out the byte array to write the result to
      * @param length the length of the byte array out
      * @return length in bytes that was actually read and put
      * into out
      */
      [[nodiscard]] virtual size_t read(uint8_t out[], size_t length) = 0;

      virtual bool check_available(size_t n) = 0;

      /**
      * Read from the source but do not modify the internal
      * offset. Consecutive calls to peek() will return portions of
      * the source starting at the same position.
      *
      * @param out the byte array to write the output to
      * @param length the length of the byte array out
      * @param peek_offset the offset into the stream to read at
      * @return length in bytes that was actually read and put
      * into out
      */
      [[nodiscard]] virtual size_t peek(uint8_t out[], size_t length, size_t peek_offset) const = 0;

      /**
      * Test whether the source still has data that can be read.
      * @return true if there is no more data to read, false otherwise
      */
      virtual bool end_of_data() const = 0;

      /**
      * return the id of this data source
      * @return std::string representing the id of this data source
      */
      virtual std::string id() const { return ""; }

      /**
      * Read one byte.
      * @param out the byte to read to
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t read_byte(uint8_t& out);

      /**
      * Read one byte.
      *
      * Returns nullopt if no further bytes are available
      */
      std::optional<uint8_t> read_byte();

      /**
      * Peek at one byte.
      * @param out an output byte
      * @return length in bytes that was actually read and put
      * into out
      */
      size_t peek_byte(uint8_t& out) const;

      /**
      * Discard the next N bytes of the data
      * @param N the number of bytes to discard
      * @return number of bytes actually discarded
      */
      size_t discard_next(size_t N);

      /**
      * @return number of bytes read so far.
      */
      virtual size_t get_bytes_read() const = 0;

      DataSource() = default;
      virtual ~DataSource() = default;
      DataSource(const DataSource&) = delete;
      DataSource(DataSource&&) = default;
      DataSource& operator=(const DataSource&) = delete;
      DataSource& operator=(DataSource&&) = default;
};

/**
* This class represents a Memory-Based DataSource
*/
class BOTAN_PUBLIC_API(2, 0) DataSource_Memory final : public DataSource {
   public:
      size_t read(uint8_t buf[], size_t length) override;
      size_t peek(uint8_t buf[], size_t length, size_t offset) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;

      /**
      * Construct a memory source that reads from a string
      * @param in the string to read from
      */
      explicit DataSource_Memory(std::string_view in);

      /**
      * Construct a memory source that reads from a byte array
      * @param in the byte array to read from
      * @param length the length of the byte array
      */
      DataSource_Memory(const uint8_t in[], size_t length) : m_source(in, in + length), m_offset(0) {}

      /**
      * Construct a memory source that reads from a secure_vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(secure_vector<uint8_t> in) : m_source(std::move(in)), m_offset(0) {}

      /**
      * Construct a memory source that reads from an arbitrary byte buffer
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(std::span<const uint8_t> in) : m_source(in.begin(), in.end()), m_offset(0) {}

      /**
      * Construct a memory source that reads from a std::vector
      * @param in the MemoryRegion to read from
      */
      explicit DataSource_Memory(const std::vector<uint8_t>& in) : m_source(in.begin(), in.end()), m_offset(0) {}

      size_t get_bytes_read() const override { return m_offset; }

   private:
      secure_vector<uint8_t> m_source;
      size_t m_offset;
};

/**
* This class represents a Stream-Based DataSource.
*/
class BOTAN_PUBLIC_API(2, 0) DataSource_Stream final : public DataSource {
   public:
      size_t read(uint8_t buf[], size_t length) override;
      size_t peek(uint8_t buf[], size_t length, size_t offset) const override;
      bool check_available(size_t n) override;
      bool end_of_data() const override;
      std::string id() const override;

      BOTAN_FUTURE_EXPLICIT DataSource_Stream(std::istream& in, std::string_view id = "<std::istream>");

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
      /**
      * Construct a Stream-Based DataSource from filesystem path
      * @param filename the path to the file
      * @param use_binary whether to treat the file as binary or not
      */
      BOTAN_FUTURE_EXPLICIT DataSource_Stream(std::string_view filename, bool use_binary = false);
#endif

      DataSource_Stream(const DataSource_Stream&) = delete;
      DataSource_Stream(DataSource_Stream&&) = delete;
      DataSource_Stream& operator=(const DataSource_Stream&) = delete;
      DataSource_Stream& operator=(DataSource_Stream&&) = delete;

      ~DataSource_Stream() override;

      size_t get_bytes_read() const override { return m_total_read; }

   private:
      const std::string m_identifier;

      std::unique_ptr<std::istream> m_source_memory;
      std::istream& m_source;
      size_t m_total_read;
};

}  // namespace Botan

#endif
