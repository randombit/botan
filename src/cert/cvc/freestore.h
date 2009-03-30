/**
* (C) 2007 Christoph Ludwig
*          ludwig@fh-worms.de
**/

#ifndef BOTAN_FREESTORE_H__
#define BOTAN_FREESTORE_H__

#include <botan/build.h>

#if defined(BOTAN_USE_STD_TR1)
  #include <tr1/memory>
#elif defined(BOTAN_USE_BOOST_TR1)
  #include <boost/tr1/memory.hpp>
#else
  #error "Please choose a TR1 implementation in build.h"
#endif

namespace Botan {

/**
* This class is intended as an function call parameter type and
* enables convenient automatic conversions between plain and smart
* pointer types. It internally stores a SharedPointer which can be
* accessed.
*
* Distributed under the terms of the Botan license
*/
template<typename T>
class BOTAN_DLL SharedPtrConverter
   {
   public:
      typedef std::tr1::shared_ptr<T> SharedPtr;

      /**
      * Construct a null pointer equivalent object.
      */
      SharedPtrConverter() : ptr() {}

      /**
      * Copy constructor.
      */
      SharedPtrConverter(SharedPtrConverter const& other) :
         ptr(other.ptr) {}

      /**
      * Construct a converter object from another pointer type.
      * @param p the pointer which shall be set as the internally stored
      * pointer value of this converter.
      */
      template<typename Ptr>
      SharedPtrConverter(Ptr p)
         : ptr(p) {}

      /**
      * Get the internally stored shared pointer.
      * @return the internally stored shared pointer
      */
      SharedPtr const& get_ptr() const { return this->ptr; }

      /**
      * Get the internally stored shared pointer.
      * @return the internally stored shared pointer
      */
      SharedPtr get_ptr() { return this->ptr; }

      /**
      * Get the internally stored shared pointer.
      * @return the internally stored shared pointer
      */
      SharedPtr const& get_shared() const { return this->ptr; }

      /**
      * Get the internally stored shared pointer.
      * @return the internally stored shared pointer
      */
      SharedPtr get_shared() { return this->ptr; }

   private:
      SharedPtr ptr;
   };

}

#endif
