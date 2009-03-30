/*
* DataSink
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DATA_SINK_H__
#define BOTAN_DATA_SINK_H__

#include <botan/filter.h>
#include <iosfwd>

namespace Botan {

/**
* This class represents abstract data sink objects.
*/
class BOTAN_DLL DataSink : public Filter
   {
   public:
      bool attachable() { return false; }
      DataSink() {}
      virtual ~DataSink() {}
   private:
      DataSink& operator=(const DataSink&) { return (*this); }
      DataSink(const DataSink&);
   };

/**
* This class represents a data sink which writes its output to a stream.
*/
class BOTAN_DLL DataSink_Stream : public DataSink
   {
   public:
      void write(const byte[], u32bit);

      /**
      * Construct a DataSink_Stream from a stream.
      * @param stream the stream to write to
      * @param name identifier
      */
      DataSink_Stream(std::ostream& stream,
                      const std::string& name = "");

      /**
      * Construct a DataSink_Stream from a stream.
      * @param file the name of the file to open a stream to
      * @param use_binary indicates whether to treat the file
      * as a binary file or not
      */
      DataSink_Stream(const std::string& filename,
                      bool use_binary = false);

      ~DataSink_Stream();
   private:
      const std::string identifier;
      const bool owner;

      std::ostream* sink;
   };

}

#endif
