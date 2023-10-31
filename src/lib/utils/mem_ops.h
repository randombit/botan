/*
* Memory Operations
* (C) 1999-2009,2012,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MEMORY_OPS_H_
#define BOTAN_MEMORY_OPS_H_

#include <botan/types.h>
#include <cstring>
#include <span>
#include <type_traits>
#include <vector>

/*
The header mem_ops.h previously included the contents of allocator.h

Library code should always include allocator.h to see these
declarations; however when we are not building the library continue to
include the header here to avoid breaking application code.
*/
#if !defined(BOTAN_IS_BEING_BUILT)
   #include <botan/allocator.h>
#endif

namespace Botan {

/**
* Scrub memory contents in a way that a compiler should not elide,
* using some system specific technique. Note that this function might
* not zero the memory (for example, in some hypothetical
* implementation it might combine the memory contents with the output
* of a system PRNG), but if you can detect any difference in behavior
* at runtime then the clearing is side-effecting and you can just
* use `clear_mem`.
*
* Use this function to scrub memory just before deallocating it, or on
* a stack buffer before returning from the function.
*
* @param ptr a pointer to memory to scrub
* @param n the number of bytes pointed to by ptr
*/
BOTAN_PUBLIC_API(2, 0) void secure_scrub_memory(void* ptr, size_t n);

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return 0xFF iff x[i] == y[i] forall i in [0...n) or 0x00 otherwise
*/
BOTAN_PUBLIC_API(2, 9) uint8_t ct_compare_u8(const uint8_t x[], const uint8_t y[], size_t len);

/**
* Memory comparison, input insensitive
* @param x a pointer to an array
* @param y a pointer to another array
* @param len the number of Ts in x and y
* @return true iff x[i] == y[i] forall i in [0...n)
*/
inline bool constant_time_compare(const uint8_t x[], const uint8_t y[], size_t len) {
   return ct_compare_u8(x, y, len) == 0xFF;
}

/**
* Zero out some bytes. Warning: use secure_scrub_memory instead if the
* memory is about to be freed or otherwise the compiler thinks it can
* elide the writes.
*
* @param ptr a pointer to memory to zero
* @param bytes the number of bytes to zero in ptr
*/
inline constexpr void clear_bytes(void* ptr, size_t bytes) {
   if(bytes > 0) {
      std::memset(ptr, 0, bytes);
   }
}

/**
* Zero memory before use. This simply calls memset and should not be
* used in cases where the compiler cannot see the call as a
* side-effecting operation (for example, if calling clear_mem before
* deallocating memory, the compiler would be allowed to omit the call
* to memset entirely under the as-if rule.)
*
* @param ptr a pointer to an array of Ts to zero
* @param n the number of Ts pointed to by ptr
*/
template <typename T>
inline constexpr void clear_mem(T* ptr, size_t n) {
   clear_bytes(ptr, sizeof(T) * n);
}

/**
* Copy memory
* @param out the destination array
* @param in the source array
* @param n the number of elements of in/out
*/
template <typename T>
inline constexpr void copy_mem(T* out, const T* in, size_t n)
   requires std::is_trivial<typename std::decay<T>::type>::value
{
   BOTAN_ASSERT_IMPLICATION(n > 0, in != nullptr && out != nullptr, "If n > 0 then args are not null");

   if(in != nullptr && out != nullptr && n > 0) {
      std::memmove(out, in, sizeof(T) * n);
   }
}

template <typename T>
inline constexpr void typecast_copy(uint8_t out[], T in[], size_t N)
   requires std::is_trivially_copyable<T>::value
{
   std::memcpy(out, in, sizeof(T) * N);
}

template <typename T>
inline constexpr void typecast_copy(T out[], const uint8_t in[], size_t N)
   requires std::is_trivial<T>::value
{
   std::memcpy(out, in, sizeof(T) * N);
}

template <typename T>
inline constexpr void typecast_copy(uint8_t out[], T in) {
   typecast_copy(out, &in, 1);
}

template <typename T>
inline constexpr void typecast_copy(T& out, const uint8_t in[])
   requires std::is_trivial<typename std::decay<T>::type>::value
{
   typecast_copy(&out, in, 1);
}

template <class To, class FromT>
inline constexpr To typecast_copy(const FromT* src) noexcept
   requires std::is_trivially_copyable<FromT>::value && std::is_trivial<To>::value
{
   To dst;
   std::memcpy(&dst, src, sizeof(To));
   return dst;
}

#if !defined(BOTAN_IS_BEGIN_BUILT)
/**
* Set memory to a fixed value
* @param ptr a pointer to an array of bytes
* @param n the number of Ts pointed to by ptr
* @param val the value to set each byte to
*/
BOTAN_DEPRECATED("This function is deprecated")

inline constexpr void set_mem(uint8_t* ptr, size_t n, uint8_t val) {
   if(n > 0) {
      std::memset(ptr, val, n);
   }
}
#endif

inline const uint8_t* cast_char_ptr_to_uint8(const char* s) {
   return reinterpret_cast<const uint8_t*>(s);
}

inline const char* cast_uint8_ptr_to_char(const uint8_t* b) {
   return reinterpret_cast<const char*>(b);
}

inline uint8_t* cast_char_ptr_to_uint8(char* s) {
   return reinterpret_cast<uint8_t*>(s);
}

inline char* cast_uint8_ptr_to_char(uint8_t* b) {
   return reinterpret_cast<char*>(b);
}

#if !defined(BOTAN_IS_BEING_BUILT)
/**
* Memory comparison, input insensitive
* @param p1 a pointer to an array
* @param p2 a pointer to another array
* @param n the number of Ts in p1 and p2
* @return true iff p1[i] == p2[i] forall i in [0...n)
*/
template <typename T>
BOTAN_DEPRECATED("This function is deprecated")
inline bool same_mem(const T* p1, const T* p2, size_t n) {
   volatile T difference = 0;

   for(size_t i = 0; i != n; ++i) {
      difference = difference | (p1[i] ^ p2[i]);
   }

   return difference == 0;
}
#endif

#if !defined(BOTAN_IS_BEING_BUILT)

template <typename T, typename Alloc>
BOTAN_DEPRECATED("The buffer_insert functions are deprecated")
size_t buffer_insert(std::vector<T, Alloc>& buf, size_t buf_offset, const T input[], size_t input_length) {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input_length, buf.size() - buf_offset);
   if(to_copy > 0) {
      copy_mem(&buf[buf_offset], input, to_copy);
   }
   return to_copy;
}

template <typename T, typename Alloc, typename Alloc2>
BOTAN_DEPRECATED("The buffer_insert functions are deprecated")
size_t buffer_insert(std::vector<T, Alloc>& buf, size_t buf_offset, const std::vector<T, Alloc2>& input) {
   BOTAN_ASSERT_NOMSG(buf_offset <= buf.size());
   const size_t to_copy = std::min(input.size(), buf.size() - buf_offset);
   if(to_copy > 0) {
      copy_mem(&buf[buf_offset], input.data(), to_copy);
   }
   return to_copy;
}

#endif

/**
* XOR arrays. Postcondition out[i] = in[i] ^ out[i] forall i = 0...length
* @param out the input/output buffer
* @param in the read-only input buffer
* @param length the length of the buffers
*/
inline void xor_buf(uint8_t out[], const uint8_t in[], size_t length) {
   const size_t blocks = length - (length % 32);

   for(size_t i = 0; i != blocks; i += 32) {
      uint64_t x[4];
      uint64_t y[4];

      typecast_copy(x, out + i, 4);
      typecast_copy(y, in + i, 4);

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(out + i, x, 4);
   }

   for(size_t i = blocks; i != length; ++i) {
      out[i] ^= in[i];
   }
}

/**
* XOR arrays. Postcondition out[i] = in[i] ^ in2[i] forall i = 0...length
* @param out the output buffer
* @param in the first input buffer
* @param in2 the second output buffer
* @param length the length of the three buffers
*/
inline void xor_buf(uint8_t out[], const uint8_t in[], const uint8_t in2[], size_t length) {
   const size_t blocks = length - (length % 32);

   for(size_t i = 0; i != blocks; i += 32) {
      uint64_t x[4];
      uint64_t y[4];

      typecast_copy(x, in + i, 4);
      typecast_copy(y, in2 + i, 4);

      x[0] ^= y[0];
      x[1] ^= y[1];
      x[2] ^= y[2];
      x[3] ^= y[3];

      typecast_copy(out + i, x, 4);
   }

   for(size_t i = blocks; i != length; ++i) {
      out[i] = in[i] ^ in2[i];
   }
}

inline void xor_buf(std::span<uint8_t> out, std::span<const uint8_t> in, size_t n) {
   xor_buf(out.data(), in.data(), n);
}

template <typename Alloc>
void xor_buf(std::vector<uint8_t, Alloc>& out, const uint8_t* in, size_t n) {
   xor_buf(out.data(), in, n);
}

template <typename Alloc, typename Alloc2>
void xor_buf(std::vector<uint8_t, Alloc>& out, const uint8_t* in, const std::vector<uint8_t, Alloc2>& in2, size_t n) {
   xor_buf(out.data(), in, in2.data(), n);
}

template <typename Alloc, typename Alloc2>
std::vector<uint8_t, Alloc>& operator^=(std::vector<uint8_t, Alloc>& out, const std::vector<uint8_t, Alloc2>& in) {
   if(out.size() < in.size()) {
      out.resize(in.size());
   }

   xor_buf(out.data(), in.data(), in.size());
   return out;
}

}  // namespace Botan

#endif
