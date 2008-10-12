/**************************************************
* (C) 2007 Christoph Ludwig                       *
*          ludwig@fh-worms.de                     *
**************************************************/

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

template<typename T>
class BOTAN_DLL SharedPtrConverter
   {
   public:
      typedef std::tr1::shared_ptr<T> SharedPtr;

      SharedPtrConverter() : ptr() {};
      SharedPtrConverter(SharedPtrConverter const& other)
         : ptr(other.ptr) {};

      template<typename Ptr>
      SharedPtrConverter(Ptr p)
         : ptr(p) {};

      SharedPtr const& get_ptr() const { return this->ptr; }
      SharedPtr get_ptr() { return this->ptr; }

      SharedPtr const& get_shared() const { return this->ptr; }
      SharedPtr get_shared() { return this->ptr; }

   private:
      SharedPtr ptr;
   };

}

#endif
