/*
* DataSink
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/data_snk.h>
#include <botan/exceptn.h>

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
  #include <fstream>
#endif

namespace Botan {

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
/*
* Write to a stream
*/
void DataSink_Stream::write(const byte out[], size_t length)
   {
   m_sink.write(reinterpret_cast<const char*>(out), length);
   if(!m_sink.good())
      throw Stream_IO_Error("DataSink_Stream: Failure writing to " +
                            m_identifier);
   }

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(std::ostream& out,
                                 const std::string& name) :
   m_identifier(name),
   m_sink_p(nullptr),
   m_sink(out)
   {
   }

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(const std::string& path,
                                 bool use_binary) :
   m_identifier(path),
   m_sink_p(new std::ofstream(path,
                            use_binary ? std::ios::binary : std::ios::out)),
   m_sink(*m_sink_p)
   {
   if(!m_sink.good())
      {
      delete m_sink_p;
      throw Stream_IO_Error("DataSink_Stream: Failure opening " + path);
      }
   }

/*
* DataSink_Stream Destructor
*/
DataSink_Stream::~DataSink_Stream()
   {
   delete m_sink_p;
   }
#endif

}
