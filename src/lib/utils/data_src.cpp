/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/data_src.h>
#include <botan/exceptn.h>
#include <algorithm>

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
  #include <fstream>
#endif

namespace Botan {

/*
* Read a single byte from the DataSource
*/
size_t DataSource::read_byte(uint8_t& out) {
  return read(&out, 1);
}

/*
* Peek a single byte from the DataSource
*/
size_t DataSource::peek_byte(uint8_t& out) const {
  return peek(&out, 1, 0);
}

/*
* Discard the next N bytes of the data
*/
size_t DataSource::discard_next(size_t n) {
  uint8_t buf[64] = { 0 };
  size_t discarded = 0;

  while (n) {
    const size_t got = this->read(buf, std::min(n, sizeof(buf)));
    discarded += got;
    n -= got;

    if (got == 0) {
      break;
    }
  }

  return discarded;
}

/*
* Read from a memory buffer
*/
size_t DataSource_Memory::read(uint8_t out[], size_t length) {
  size_t got = std::min<size_t>(m_source.size() - m_offset, length);
  copy_mem(out, m_source.data() + m_offset, got);
  m_offset += got;
  return got;
}

bool DataSource_Memory::check_available(size_t n) {
  return (n <= (m_source.size() - m_offset));
}

/*
* Peek into a memory buffer
*/
size_t DataSource_Memory::peek(uint8_t out[], size_t length,
                               size_t peek_offset) const {
  const size_t bytes_left = m_source.size() - m_offset;
  if (peek_offset >= bytes_left) { return 0; }

  size_t got = std::min(bytes_left - peek_offset, length);
  copy_mem(out, &m_source[m_offset + peek_offset], got);
  return got;
}

/*
* Check if the memory buffer is empty
*/
bool DataSource_Memory::end_of_data() const {
  return (m_offset == m_source.size());
}

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(const std::string& in) :
  m_source(reinterpret_cast<const uint8_t*>(in.data()),
           reinterpret_cast<const uint8_t*>(in.data()) + in.length()),
  m_offset(0) {
}

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

/*
* Read from a stream
*/
size_t DataSource_Stream::read(uint8_t out[], size_t length) {
  m_source.read(reinterpret_cast<char*>(out), length);
  if (m_source.bad()) {
    throw Stream_IO_Error("DataSource_Stream::read: Source failure");
  }

  size_t got = m_source.gcount();
  m_total_read += got;
  return got;
}

bool DataSource_Stream::check_available(size_t n) {
  const std::streampos orig_pos = m_source.tellg();
  m_source.seekg(0, std::ios::end);
  const size_t avail = m_source.tellg() - orig_pos;
  m_source.seekg(orig_pos);
  return (avail >= n);
}

/*
* Peek into a stream
*/
size_t DataSource_Stream::peek(uint8_t out[], size_t length, size_t offset) const {
  if (end_of_data()) {
    throw Invalid_State("DataSource_Stream: Cannot peek when out of data");
  }

  size_t got = 0;

  if (offset) {
    secure_vector<uint8_t> buf(offset);
    m_source.read(reinterpret_cast<char*>(buf.data()), buf.size());
    if (m_source.bad()) {
      throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
    }
    got = m_source.gcount();
  }

  if (got == offset) {
    m_source.read(reinterpret_cast<char*>(out), length);
    if (m_source.bad()) {
      throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
    }
    got = m_source.gcount();
  }

  if (m_source.eof()) {
    m_source.clear();
  }
  m_source.seekg(m_total_read, std::ios::beg);

  return got;
}

/*
* Check if the stream is empty or in error
*/
bool DataSource_Stream::end_of_data() const {
  return (!m_source.good());
}

/*
* Return a human-readable ID for this stream
*/
std::string DataSource_Stream::id() const {
  return m_identifier;
}

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(const std::string& path,
                                     bool use_binary) :
  m_identifier(path),
  m_source_p(new std::ifstream(path,
                               use_binary ? std::ios::binary : std::ios::in)),
  m_source(*m_source_p),
  m_total_read(0) {
  if (!m_source.good()) {
    delete m_source_p;
    throw Stream_IO_Error("DataSource: Failure opening file " + path);
  }
}

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(std::istream& in,
                                     const std::string& name) :
  m_identifier(name),
  m_source_p(nullptr),
  m_source(in),
  m_total_read(0) {
}

/*
* DataSource_Stream Destructor
*/
DataSource_Stream::~DataSource_Stream() {
  delete m_source_p;
}

#endif

}
