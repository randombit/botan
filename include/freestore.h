/*************************************************
 * mixin class to force that all instances        *
 * allocated on the free store are referenced     *
 * through smart pointers.                        *
 * (C) 2007 Christoph Ludwig                      *
 *          ludwig@fh-worms.de                    *
 *************************************************/

#ifndef BOTAN_FREESTORE_H_GUARD_
#define BOTAN_FREESTORE_H_GUARD_

// Standard / TR1 headers
#include <botan/pointers.h>

// Boost headers
#include <boost/preprocessor/arithmetic/inc.hpp>
#include <boost/preprocessor/repetition/enum_binary_params.hpp>
#include <boost/preprocessor/repetition/enum_params.hpp>
#include <boost/preprocessor/repetition/repeat.hpp>
#include <boost/preprocessor/stringize.hpp>

#ifndef BOTAN_CREATE_PTR_MAX_ARITY
#define BOTAN_CREATE_PTR_MAX_ARITY 10
#endif 

namespace Botan {

  template<typename T>
  class SharedPtrConverter {
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


  /*
   * Create an object of type T on the free store by means of the
   * default constructor and return an auto_ptr to this object.
   */
  template <class T>
  std::auto_ptr<T> create_auto_ptr() {
    T* raw = new T();
    return std::auto_ptr<T>(raw);
  }

  /*
   * Create an object of type T on the free store by means of the
   * default constructor and return a shared_ptr to this object.
   */
  template <class T>
  std::tr1::shared_ptr<T> create_shared_ptr() {
    T* raw = new T();
    return std::tr1::shared_ptr<T>(raw);
  }

  /*
   * Provide overloads of create_auto_ptr and create_shared_ptr for up to
   * BOTAN_CREATE_PTR_MAX_ARITY constructor parameters.
   *
   * The code below defines
   *   template<class T, typename A1>
   *   std::auto_ptr<T> create_auto_ptr(A1 p1);
   *
   *   template<class T, typename A1, typename A2>
   *   std::auto_ptr<T> create_auto_ptr(A1 p1, A2 p2);
   *
   * and so on up to
   *
   *   template<class T, typename A1, typename A2, ..., typename An>
   *   std::auto_ptr<T> create_auto_ptr(A1 p1, A2 p2, ..., An pn);
   *
   * where n = BOTAN_CREATE_PTR_MAX_ARITY. The code also defines similar
   * function template overloads for create_shared_pt.
   *
   * The idea for the preprocessor code is taken from:
   *   Grenyer, Paul: "All Heap No Leak". Overload, Issue 60, ACCU, Sept. 2004.
   *   Available at <URL:http://www.accu.org/index.php/journals/306>.
   */
  // Doxygen cannot handle the preprocessor code
#   ifndef DOXYGEN_IS_PARSING
#   define BOTAN_CREATE_PTR(z, n, _) \
    template<class T, \
             BOOST_PP_ENUM_PARAMS(BOOST_PP_INC(n), typename A)> \
    std::auto_ptr<T> \
    create_auto_ptr(BOOST_PP_ENUM_BINARY_PARAMS(BOOST_PP_INC(n), A, p)) {    \
      T* raw = new T(BOOST_PP_ENUM_PARAMS(BOOST_PP_INC(n), p)); \
      return std::auto_ptr<T>(raw); \
    } \
    \
    template<class T, \
             BOOST_PP_ENUM_PARAMS(BOOST_PP_INC(n), typename A)> \
    std::tr1::shared_ptr<T> \
    create_shared_ptr(BOOST_PP_ENUM_BINARY_PARAMS(BOOST_PP_INC(n), A, p)) {    \
      T* raw = new T(BOOST_PP_ENUM_PARAMS(BOOST_PP_INC(n), p)); \
      return std::tr1::shared_ptr<T>(raw);                      \
    } \
    /**/
    BOOST_PP_REPEAT(BOTAN_CREATE_PTR_MAX_ARITY, BOTAN_CREATE_PTR, ~)
#   if 0
      ;  // make emacs' and other editors' auto-indentation happy...
#   endif    
#   undef BOTAN_CREATE_PTR
#   else
    //! Preprocessor generated factory functions that return auto_ptr<T>
    template<typename T, typename P1, typename P2, typename P3, ... >
    std::auto_ptr<T> create_auto_ptr(P1 p1, P2 p2, P3 p3, ...);

    //! Preprocessor generated factory functions that return shared_ptr<T>
    template<typename T, typename P1, typename P2, typename P3, ... >
    std::tr1::shared_ptr<T> create_shared_ptr(P1 p1, P2 p2, P3 p3, ...);

#   endif // DOXYGEN_IS_PARSING



  /*
   * Freestore enforces that all objects (including objects of derived types)
   * can no longer be allocated on the free store by means of the
   * new (or new[]) operator, but only via one of the overloads
   * of function template Botan::create_ptr.
   */
  class Freestore {
  private: 
    static
    inline
    void* operator new(std::size_t size) throw (std::bad_alloc) {
      return ::operator new(size);
    }

    static
    inline
    void* operator new[](std::size_t size) throw (std::bad_alloc) {
      return ::operator new[](size);
    }

    template <class T>
    friend 
    std::auto_ptr<T> create_auto_ptr();

    template <class T>
    friend 
    std::tr1::shared_ptr<T> create_shared_ptr();

#   ifndef DOXYGEN_IS_PARSING
#   define BOTAN_FREESTORE_FRIEND_CREATE_PTR(z, n, _) \
    template<class T, \
             BOOST_PP_ENUM_PARAMS(BOOST_PP_INC(n), typename A)> \
    friend \
    std::auto_ptr<T> \
    create_auto_ptr(BOOST_PP_ENUM_BINARY_PARAMS(BOOST_PP_INC(n), A, p)); \
    \
    template<class T, \
             BOOST_PP_ENUM_PARAMS(BOOST_PP_INC(n), typename A)> \
    friend \
    std::tr1::shared_ptr<T> \
    create_shared_ptr(BOOST_PP_ENUM_BINARY_PARAMS(BOOST_PP_INC(n), A, p)); \
    /**/
    BOOST_PP_REPEAT(BOTAN_CREATE_PTR_MAX_ARITY, BOTAN_FREESTORE_FRIEND_CREATE_PTR, ~)
#   if 0
      ;  // make emacs' auto-indentation happy...
#   endif    
#   undef BOTAN_FREESTORE_FRIEND_CREATE_PTR
#   else
    template<typename T, typename P1, typename P2, typename P3, ... >
    friend
    std::auto_ptr<T> create_auto_ptr(P1 p1, P2 p2, P3 p3, ...);

    template<typename T, typename P1, typename P2, typename P3, ... >
    friend
    std::tr1::shared_ptr<T> create_shared_ptr(P1 p1, P2 p2, P3 p3, ...);
#   endif // DOXYGEN_IS_PARSING


  public:
    // implicitly defined constructors and assignment operator are
    // fine.
  };


  
} // namespace Botan

#endif // BOTAN_FREESTORE_H_GUARD_


//
// Customize emacs:
//

/*
Local Variables:
mode: C++
coding: utf-8
c-file-offsets: ((case-label            . 2)
                 (statement-block-intro . +)
                 (knr-argdecl-intro     . 0)
                 (substatement-open     . 0)
                 (label                 . 0)
                 (statement-cont        . +))
c-basic-offset: 2
c-comment-only-line-offset: 0
c-hanging-braces-alist: ((brace-list-open)
                         (brace-entry-open)
                         (substatement-open after)
                         (block-close . c-snug-do-while))
c-cleanup-list: (brace-else-brace)
indent-tabs-mode: nil
End:
*/
