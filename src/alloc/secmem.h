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
      u32bit size() const { return used; }

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
      * Get a pointer to the last element in the buffer.
      * @return pointer to the last element in the buffer
      */
      T* end() { return (buf + size()); }

      /**
      * Get a constant pointer to the last element in the buffer.
      * @return constant pointer to the last element in the buffer
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
      * Compare two buffers lexicographically.
      * @return true if this buffer is lexicographically smaller than other.
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
         { if(this != &other) set(other); return (*this); }

      /**
      * Copy the contents of an array of objects of type T into this buffer.
      * The former contents of *this are discarded.
      * The length of *this must be at least n, otherwise memory errors occur.
      * @param in the array to copy the contents from
      * @param n the length of in
      */
      void copy(const T in[], u32bit n)
         { copy(0, in, n); }

      /**
      * Copy the contents of an array of objects of type T into this buffer.
      * The former contents of *this are discarded.
      * The length of *this must be at least n, otherwise memory errors occur.
      * @param off the offset position inside this buffer to start inserting
      * the copied bytes
      * @param in the array to copy the contents from
      * @param n the length of in
      */
      void copy(u32bit off, const T in[], u32bit n)
         { copy_mem(buf + off, in, (n > size() - off) ? (size() - off) : n); }

      /**
      * Set the contents of this according to the argument. The size of
      * *this is increased if necessary.
      * @param in the array of objects of type T to copy the contents from
      * @param n the size of array in
      */
      void set(const T in[], u32bit n)    { resize(n); copy(in, n); }

      /**
      * Set the contents of this according to the argument. The size of
      * *this is increased if necessary.
      * @param in the buffer to copy the contents from
      */
      void set(const MemoryRegion<T>& in) { set(in.begin(), in.size()); }

      /**
      * Append data to the end of this buffer.
      * @param data the array containing the data to append
      * @param n the size of the array data
      */
      void append(const T data[], u32bit n)
         { resize(size()+n); copy(size() - n, data, n); }

      /**
      * Append a single element.
      * @param x the element to append
      */
      void append(T x) { append(&x, 1); }

      /**
      * Append data to the end of this buffer.
      * @param other the buffer containing the data to append
      */
      void append(const MemoryRegion<T>& other)
         { append(other.begin(), other.size()); }

      /**
      * Zeroise the bytes of this buffer. The length remains unchanged.
      */
      void clear() { clear_mem(buf, allocated); }

      /**
      * Reset this buffer to an empty buffer with size zero.
      */
      void destroy() { resize(0); }

      /**
      * Inserts or erases elements at the end such that the size
      * becomes n, leaving elements in the range 0...n unmodified if
      * set or otherwise zero-initialized
      * @param n length of the new buffer
      */
      void resize(u32bit n);

      /**
      * Swap this buffer with another object.
      */
      void swap(MemoryRegion<T>& other);

      ~MemoryRegion() { deallocate(buf, allocated); }
   protected:
      MemoryRegion() { buf = 0; alloc = 0; used = allocated = 0; }

      /**
      * Copy constructor
      * @param other the other region to copy
      */
      MemoryRegion(const MemoryRegion<T>& other)
         {
         buf = 0;
         used = allocated = 0;
         alloc = other.alloc;
         set(other.buf, other.used);
         }

      /**
      * @param locking should we use a locking allocator
      * @param length the initial length to use
      */
      void init(bool locking, u32bit length = 0)
         { alloc = Allocator::get(locking); resize(length); }
   private:
      T* allocate(u32bit n)
         {
         return static_cast<T*>(alloc->allocate(sizeof(T)*n));
         }

      void deallocate(T* p, u32bit n)
         { if(alloc && p && n) alloc->deallocate(p, sizeof(T)*n); }

      T* buf;
      u32bit used;
      u32bit allocated;
      Allocator* alloc;
   };

/*
* Change the size of the buffer
*/
template<typename T>
void MemoryRegion<T>::resize(u32bit n)
   {
   if(n <= allocated)
      {
      u32bit zap = std::min(used, n);
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
   if(size() < other.size()) return true;
   if(size() > other.size()) return false;

   for(u32bit j = 0; j != size(); j++)
      {
      if(buf[j] < other[j]) return true;
      if(buf[j] > other[j]) return false;
      }

   return false;
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
      using MemoryRegion<T>::set;
      using MemoryRegion<T>::init;
      using MemoryRegion<T>::append;

      /**
      * Copy the contents of another buffer into this buffer.
      * @param in the buffer to copy the contents from
      * @return reference to *this
      */
      MemoryVector<T>& operator=(const MemoryRegion<T>& in)
         { if(this != &in) set(in); return (*this); }

      /**
      * Create a buffer of the specified length.
      * @param n the length of the buffer to create.
      */
      MemoryVector(u32bit n = 0) { init(false, n); }

      /**
      * Create a buffer with the specified contents.
      * @param in the array containing the data to be initially copied
      * into the newly created buffer
      * @param n the size of the arry in
      */
      MemoryVector(const T in[], u32bit n)
         { init(false); set(in, n); }

      /**
      * Copy constructor.
      */
      MemoryVector(const MemoryRegion<T>& in)
         { init(false); set(in); }

      /**
      * Create a buffer whose content is the concatenation of two other
      * buffers.
      * @param in1 the first part of the new contents
      * @param in2 the contents to be appended to in1
      */
      MemoryVector(const MemoryRegion<T>& in1, const MemoryRegion<T>& in2)
         { init(false); set(in1); append(in2); }
   };

/**
* This class represents variable length buffers using the operating
* systems capability to lock memory, i.e. keeping it from being
* swapped out to disk. In this way, a security hole allowing attackers
* to find swapped out secret keys is closed.
*/
template<typename T, u32bit INITIAL_LEN = 0>
class SecureVector : public MemoryRegion<T>
   {
   public:
      using MemoryRegion<T>::copy;
      using MemoryRegion<T>::set;
      using MemoryRegion<T>::init;
      using MemoryRegion<T>::append;

      /**
      * Copy the contents of another buffer into this buffer.
      * @param in the buffer to copy the contents from
      * @return reference to *this
      */
      SecureVector<T>& operator=(const MemoryRegion<T>& in)
         { if(this != &in) set(in); return (*this); }

      /**
      * Create a buffer of the specified length.
      * @param n the length of the buffer to create.
      */
      SecureVector(u32bit n = INITIAL_LEN)
         { init(true, n); }

      /**
      * Create a buffer with the specified contents.
      * @param in the array containing the data to be initially copied
      * into the newly created buffer
      * @param n the size of the array in
      */
      SecureVector(const T in[], u32bit n)
         {
         init(true, INITIAL_LEN);
         if(INITIAL_LEN)
            copy(in, n);
         else
            set(in, n);
         }

      /**
      * Create a buffer with contents specified contents.
      * @param in the buffer holding the contents that will be
      * copied into the newly created buffer.
      */
      SecureVector(const MemoryRegion<T>& in)
         {
         init(true, INITIAL_LEN);
         if(INITIAL_LEN)
            copy(in, in.size());
         else
            set(in);
         }

      /**
      * Create a buffer whose content is the concatenation of two other
      * buffers.
      * @param in1 the first part of the new contents
      * @param in2 the contents to be appended to in1
      */
      SecureVector(const MemoryRegion<T>& in1, const MemoryRegion<T>& in2)
         { init(true); set(in1); append(in2); }
   };

}

#endif
