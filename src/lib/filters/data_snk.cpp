/*
* DataSink
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/data_snk.h>
#include <botan/exceptn.h>
#include <fstream>

namespace Botan {

/*
* Write to a stream
*/
void DataSink_Stream::write(const byte out[], size_t length)
   {
   sink.write(reinterpret_cast<const char*>(out), length);
   if(!sink.good())
      throw Stream_IO_Error("DataSink_Stream: Failure writing to " +
                            identifier);
   }

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(std::ostream& out,
                                 const std::string& name) :
   identifier(name),
   sink_p(nullptr),
   sink(out)
   {
   }

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(const std::string& path,
                                 bool use_binary) :
   identifier(path),
   sink_p(new std::ofstream(path,
                            use_binary ? std::ios::binary : std::ios::out)),
   sink(*sink_p)
   {
   if(!sink.good())
      {
      delete sink_p;
      throw Stream_IO_Error("DataSink_Stream: Failure opening " + path);
      }
   }

/*
* DataSink_Stream Destructor
*/
DataSink_Stream::~DataSink_Stream()
   {
   delete sink_p;
   }

}
