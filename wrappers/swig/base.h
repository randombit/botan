/*************************************************
* SWIG Interface for Botan                       *
* (C) 1999-2003 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_WRAP_BASE_H__
#define BOTAN_WRAP_BASE_H__

#include <botan/pipe.h>

#if !defined(SWIG)
  #define OUTPUT
  #define INOUT
#endif

/*************************************************
* Typedefs                                       *
*************************************************/
typedef unsigned char byte;
typedef unsigned int u32bit;

/*************************************************
* Library Initalization/Shutdown Object          *
*************************************************/
class LibraryInitializer
   {
   public:
      LibraryInitializer(const char*);
      ~LibraryInitializer();
   };

/*************************************************
* Symmetric Key Object                           *
*************************************************/
class SymmetricKey
   {
   public:
      std::string as_string() const { return key->as_string(); }
      u32bit length() const { return key->length(); }
      SymmetricKey(u32bit = 0);
      SymmetricKey(const std::string&);
      ~SymmetricKey();
   private:
      Botan::SymmetricKey* key;
   };

/*************************************************
* Initialization Vector Object                   *
*************************************************/
class InitializationVector
   {
   public:
      std::string as_string() const { return iv.as_string(); }
      u32bit length() const { return iv.length(); }
      InitializationVector(u32bit n = 0) { iv.change(n); }
      InitializationVector(const std::string&);
   private:
      Botan::InitializationVector iv;
   };

/*************************************************
* Filter Object                                  *
*************************************************/
class Filter
   {
   public:
      Filter(const char*);
      //Filter(const char*, const SymmetricKey&);
      //Filter(const char*, const SymmetricKey&, const InitializationVector&);
      ~Filter();
   private:
      friend class Pipe;
      Botan::Filter* filter;
      bool pipe_owns;
   };

/*************************************************
* Pipe Object                                    *
*************************************************/
class Pipe
   {
   public:
      static const u32bit DEFAULT_MESSAGE = 0xFFFFFFFF;

      void write_file(const char*);
      void write_string(const char*);

      u32bit read(byte*, u32bit, u32bit = DEFAULT_MESSAGE);
      std::string read_all_as_string(u32bit = DEFAULT_MESSAGE);

      u32bit remaining(u32bit = DEFAULT_MESSAGE);

      void start_msg();
      void end_msg();

      Pipe(Filter* = 0, Filter* = 0, Filter* = 0, Filter* = 0);
      ~Pipe();
   private:
      Botan::Pipe* pipe;
   };

#endif
