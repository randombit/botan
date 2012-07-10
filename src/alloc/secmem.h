/*
* Secure Memory Buffers
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_SECURE_MEMORY_BUFFERS_H__
#define BOTAN_SECURE_MEMORY_BUFFERS_H__

#include <botan/allocate.h>
#include <botan/mem_ops.h>
#include <algorithm>

namespace Botan {

/**
* This class represents variable length memory buffers.
*/
template<typename T>
class MemoryRegion
   {
   public:
      /**
      * Find out the size of the buffer, i.e. how many objects of type T it
      * contains.
      * @return size of the buffer
      */
      size_t size() const { return used; }

      /**
      * Find out whether this buffer is empty.
      * @return true if the buffer is empty, false otherwise
      */
      bool empty() const { return (used == 0); }

      /**
      * Get a pointer to the first element in the buffer.
      * @return pointer to the first element in the buffer
      */
      operator T* () { return buf; }

      /**
      * Get a constant pointer to the first element in the buffer.
      * @return constant pointer to the first element in the buffer
      */
      operator const T* () const { return buf; }

      /**
      * Get a pointer to the first element in the buffer.
      * @return pointer to the first element in the buffer
      */
      T* begin() { return buf; }

      /**
      * Get a constant pointer to the first element in the buffer.
      * @return constant pointer to the first element in the buffer
      */
      const T* begin() const { return buf; }

      /**
      * Get a pointer to one past the last element in the buffer.
      * @return pointer to one past the last element in the buffer
      */
      T* end() { return (buf + size()); }

      /**
      * Get a const pointer to one past the last element in the buffer.
      * @return const pointer to one past the last element in the buffer
      */
      const T* end() const { return (buf + size()); }

      /**
      * Check two buffers for equality.
      * @return true iff the content of both buffers is byte-wise equal
      */
      bool operator==(const MemoryRegion<T>& other) const
         {
         return (size() == other.size() &&
                 same_mem(buf, other.buf, size()));
         }

      /**
      * Compare two buffers
      * @return true iff this is ordered before other
      */
      bool operator<(const MemoryRegion<T>& other) const;

      /**
      * Check two buffers for inequality.
      * @return false if the content of both buffers is byte-wise equal, true
      * otherwise.
      */
      bool operator!=(const MemoryRegion<T>& other) const
         { return (!(*this == other)); }

      /**
      * Copy the contents of another buffer into this buffer.
      * The former contents of *this are discarded.
      * @param other the buffer to copy the contents from.
      * @return reference to *this
      */
      MemoryRegion<T>& operator=(const MemoryRegion<T>& other)
         {
         if(this != &other)
            {
            this->resize(other.size());
            this->copy(&other[0], other.size());
            }
         return (*this);
         }

      /**
      * Copy the contents of an array of objects of type T into this buffer.
      * The former contents of *this are discarded.
      * The length of *this must be at least n, otherwise memory errors occur.
      * @param in the array to copy the contents from
      * @param n the length of in
      */
      void copy(const T in[], size_t n)
         {
         copy_mem(buf, in, std::min(n, size()));
         }

      /**
      * Copy the contents of an array of objects of type T into this buffer.
      * The former contents of *this are discarded.
      * The length of *this must be at least n, otherwise memory errors occur.
      * @param off the offset position inside this buffer to start inserting
      * the copied bytes
      * @param in the array to copy the contents from
      * @param n the length of in
      */
      void copy(size_t off, const T in[], size_t n)
         {
         copy_mem(buf + off, in, std::min(n, size() - off));
         }

      /**
      * Append a single element.
      * @param x the element to append
      */
      void push_back(T x)
         {
         resize(size() + 1);
         buf[size()-1] = x;
         }

      /**
      * Reset this buffer to an empty buffer with size zero.
      */
      void clear() { resize(0); }

      /**
      * Inserts or erases elements at the end such that the size
      * becomes n, leaving elements in the range 0...n unmodified if
      * set or otherwise zero-initialized
      * @param n length of the new buffer
      */
      void resize(size_t n);

      /**
      * Swap this buffer with another object.
      */
      void swap(MemoryRegion<T>& other);

      ~MemoryRegion() { deallocate(buf, allocated); }
   protected:
      MemoryRegion() : buf(0), used(0), allocated(0), alloc(0) {}

      /**
      * Copy constructor
      * @param other the other region to copy
      */
      MemoryRegion(const MemoryRegion<T>& other) :
         buf(0),
         used(0),
         allocated(0),
         alloc(other.alloc)
         {
         resize(other.size());
         copy(&other[0], other.size());
         }

      /**
      * @param locking should we use a locking allocator
      * @param length the initial length to use
      */
      void init(bool locking, size_t length = 0)
         { alloc = Allocator::get(locking); resize(length); }

   private:
      T* allocate(size_t n)
         {
         return static_cast<T*>(alloc->allocate(sizeof(T)*n));
         }

      void deallocate(T* p, size_t n)
         { if(alloc && p && n) alloc->deallocate(p, sizeof(T)*n); }

      T* buf;
      size_t used;
      size_t allocated;
      Allocator* alloc;
   };

/*
* Change the size of the buffer
*/
template<typename T>
void MemoryRegion<T>::resize(size_t n)
   {
   if(n <= allocated)
      {
      size_t zap = std::min(used, n);
      clear_mem(buf + zap, allocated - zap);
      used = n;
      }
   else
      {
      T* new_buf = allocate(n);
      copy_mem(new_buf, buf, used);
      deallocate(buf, allocated);
      buf = new_buf;
      allocated = used = n;
      }
   }

/*
* Compare this buffer with another one
*/
template<typename T>
bool MemoryRegion<T>::operator<(const MemoryRegion<T>& other) const
   {
   const size_t min_size = std::min(size(), other.size());

   // This should probably be rewritten to run in constant time
   for(size_t i = 0; i != min_size; ++i)
      {
      if(buf[i] < other[i])
         return true;
      if(buf[i] > other[i])
         return false;
      }

   // First min_size bytes are equal, shorter is first
   return (size() < other.size());
   }

/*
* Swap this buffer with another one
*/
template<typename T>
void MemoryRegion<T>::swap(MemoryRegion<T>& x)
   {
   std::swap(buf, x.buf);
   std::swap(used, x.used);
   std::swap(allocated, x.allocated);
   std::swap(alloc, x.alloc);
   }

/**
* This class represents variable length buffers that do not
* make use of memory locking.
*/
template<typename T>
class MemoryVector : public MemoryRegion<T>
   {
   public:
      /**
      * Copy the contents of another buffer into this buffer.
      * @param in the buffer to copy the contents from
      * @return reference to *this
      */
      MemoryVector<T>& operator=(const MemoryRegion<T>& in)
         {
         if(this != &in)
            {
            this->resize(in.size());
            this->copy(&in[0], in.size());
            }
         return (*this);
         }

      /**
      * Create a buffer of the specified length.
      * @param n the length of the buffer to create.
      */
      MemoryVector(size_t n = 0) { this->init(false, n); }

      /**
      * Create a buffer with the specified contents.
      * @param in the array containing the data to be initially copied
      * into the newly created buffer
      * @param n the size of the arry in
      */
      MemoryVector(const T in[], size_t n)
         {
         this->init(false);
         this->resize(n);
         this->copy(in, n);
         }

      /**
      * Copy constructor.
      */
      MemoryVector(const MemoryRegion<T>& in)
         {
         this->init(false);
         this->resize(in.size());
         this->copy(&in[0], in.size());
         }
   };

/**
* This class represents variable length buffers using the operating
* systems capability to lock memory, i.e. keeping it from being
* swapped out to disk. In this way, a security hole allowing attackers
* to find swapped out secret keys is closed.
*/
template<typename T>
class SecureVector : public MemoryRegion<T>
   {
   public:
      /**
      * Copy the contents of another buffer into this buffer.
      * @param other the buffer to copy the contents from
      * @return reference to *this
      */
      SecureVector<T>& operator=(const MemoryRegion<T>& other)
         {
         if(this != &other)
            {
            this->resize(other.size());
            this->copy(&other[0], other.size());
            }
         return (*this);
         }

      /**
      * Create a buffer of the specified length.
      * @param n the length of the buffer to create.
      */
      SecureVector(size_t n = 0) { this->init(true, n); }

      /**
      * Create a buffer with the specified contents.
      * @param in the array containing the data to be initially copied
      * into the newly created buffer
      * @param n the size of the array in
      */
      SecureVector(const T in[], size_t n)
         {
         this->init(true);
         this->resize(n);
         this->copy(&in[0], n);
         }

      /**
      * Create a buffer with contents specified contents.
      * @param in the buffer holding the contents that will be
      * copied into the newly created buffer.
      */
      SecureVector(const MemoryRegion<T>& in)
         {
         this->init(true);
         this->resize(in.size());
         this->copy(&in[0], in.size());
         }
   };

template<typename T>
MemoryRegion<T>& operator+=(MemoryRegion<T>& out,
                            const MemoryRegion<T>& in)
   {
   const size_t copy_offset = out.size();
   out.resize(out.size() + in.size());
   copy_mem(&out[copy_offset], &in[0], in.size());
   return out;
   }

template<typename T>
MemoryRegion<T>& operator+=(MemoryRegion<T>& out,
                            T in)
   {
   out.push_back(in);
   return out;
   }

template<typename T, typename L>
MemoryRegion<T>& operator+=(MemoryRegion<T>& out,
                            const std::pair<const T*, L>& in)
   {
   const size_t copy_offset = out.size();
   out.resize(out.size() + in.second);
   copy_mem(&out[copy_offset], in.first, in.second);
   return out;
   }

template<typename T, typename L>
MemoryRegion<T>& operator+=(MemoryRegion<T>& out,
                            const std::pair<T*, L>& in)
   {
   const size_t copy_offset = out.size();
   out.resize(out.size() + in.second);
   copy_mem(&out[copy_offset], in.first, in.second);
   return out;
   }

/**
* Zeroise the values; length remains unchanged
* @param vec the vector to zeroise
*/
template<typename T>
void zeroise(MemoryRegion<T>& vec)
   {
   clear_mem(&vec[0], vec.size());
   }

}

namespace std {

template<typename T>
inline void swap(Botan::MemoryRegion<T>& x, Botan::MemoryRegion<T>& y)
   {
   x.swap(y);
   }

}

#endif
