/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_UTILS_H_
#define BOTAN_FFI_UTILS_H_

#include <botan/exceptn.h>
#include <botan/ffi.h>
#include <botan/mem_ops.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>

namespace Botan_FFI {

class BOTAN_UNSTABLE_API FFI_Error final : public Botan::Exception {
   public:
      FFI_Error(std::string_view what, int err_code) : Exception("FFI error", what), m_err_code(err_code) {}

      int error_code() const noexcept override { return m_err_code; }

      Botan::ErrorType error_type() const noexcept override { return Botan::ErrorType::InvalidArgument; }

   private:
      int m_err_code;
};

template <typename T, uint32_t MAGIC>
struct botan_struct {
   public:
      botan_struct(std::unique_ptr<T> obj) : m_magic(MAGIC), m_obj(std::move(obj)) {}

      virtual ~botan_struct() {
         m_magic = 0;
         m_obj.reset();
      }

      bool magic_ok() const { return (m_magic == MAGIC); }

      T* unsafe_get() const { return m_obj.get(); }

   private:
      uint32_t m_magic = 0;
      std::unique_ptr<T> m_obj;
};

#define BOTAN_FFI_DECLARE_STRUCT(NAME, TYPE, MAGIC)                             \
   struct NAME final : public Botan_FFI::botan_struct<TYPE, MAGIC> {            \
         explicit NAME(std::unique_ptr<TYPE> x) : botan_struct(std::move(x)) {} \
   }

#define BOTAN_FFI_DECLARE_DUMMY_STRUCT(NAME, MAGIC) \
   struct NAME final : public Botan_FFI::botan_struct<int, MAGIC> {}

// Declared in ffi.cpp
int ffi_error_exception_thrown(const char* func_name, const char* exn, int rc = BOTAN_FFI_ERROR_EXCEPTION_THROWN);

template <typename T, uint32_t M>
T& safe_get(botan_struct<T, M>* p) {
   if(!p) {
      throw FFI_Error("Null pointer argument", BOTAN_FFI_ERROR_NULL_POINTER);
   }
   if(p->magic_ok() == false) {
      throw FFI_Error("Bad magic in ffi object", BOTAN_FFI_ERROR_INVALID_OBJECT);
   }

   if(T* t = p->unsafe_get()) {
      return *t;
   }

   throw FFI_Error("Invalid object pointer", BOTAN_FFI_ERROR_INVALID_OBJECT);
}

int ffi_guard_thunk(const char* func_name, const std::function<int()>& thunk);

template <typename T, uint32_t M, typename F>
int botan_ffi_visit(botan_struct<T, M>* o, F func, const char* func_name) {
   using RetT = std::invoke_result_t<F, T&>;
   static_assert(std::is_void_v<RetT> || std::is_same_v<RetT, BOTAN_FFI_ERROR> || std::is_same_v<RetT, int>,
                 "BOTAN_FFI_DO must be used with a block that returns either nothing, int or BOTAN_FFI_ERROR");

   if(!o) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(o->magic_ok() == false) {
      return BOTAN_FFI_ERROR_INVALID_OBJECT;
   }

   T* p = o->unsafe_get();
   if(p == nullptr) {
      return BOTAN_FFI_ERROR_INVALID_OBJECT;
   }

   if constexpr(std::is_void_v<RetT>) {
      return ffi_guard_thunk(func_name, [&] {
         func(*p);
         return BOTAN_FFI_SUCCESS;
      });
   } else {
      return ffi_guard_thunk(func_name, [&] { return func(*p); });
   }
}

// TODO: C++20 introduces std::source_location which will allow to eliminate this
//       macro altogether. Instead, using code would just call the C++ function
//       that makes use of std::source_location like so:
//
//   template<typename T, uint32_t M, typename F>
//   int botan_ffi_visit(botan_struct<T, M>* obj, F func,
//                       const std::source_location sl = std::source_location::current())
//      {
//      // [...]
//      if constexpr(...)
//         {
//         return ffi_guard_thunk(sl.function_name(), [&] { return func(*p); })
//         }
//      // [...]
//      }
#define BOTAN_FFI_VISIT(obj, lambda) botan_ffi_visit(obj, lambda, __func__)

template <typename T, uint32_t M>
int ffi_delete_object(botan_struct<T, M>* obj, const char* func_name) {
   return ffi_guard_thunk(func_name, [=]() -> int {
      // ignore delete of null objects
      if(obj == nullptr) {
         return BOTAN_FFI_SUCCESS;
      }

      if(obj->magic_ok() == false) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT;
      }

      delete obj;
      return BOTAN_FFI_SUCCESS;
   });
}

#define BOTAN_FFI_CHECKED_DELETE(o) ffi_delete_object(o, __func__)

template <typename Alloc>
inline int invoke_view_callback(botan_view_bin_fn view, botan_view_ctx ctx, const std::vector<uint8_t, Alloc>& buf) {
   return view(ctx, buf.data(), buf.size());
}

inline int invoke_view_callback(botan_view_str_fn view, botan_view_ctx ctx, std::string_view str) {
   return view(ctx, str.data(), str.size() + 1);
}

struct botan_view_bounce_struct {
      uint8_t* out_ptr;
      size_t* out_len;
};

int botan_view_bin_bounce_fn(botan_view_ctx ctx, const uint8_t* buf, size_t len);
int botan_view_str_bounce_fn(botan_view_ctx ctx, const char* str, size_t len);

template <typename Fn, typename... Args>
int copy_view_bin(uint8_t out[], size_t* out_len, Fn fn, Args... args) {
   botan_view_bounce_struct ctx;
   ctx.out_ptr = out;
   ctx.out_len = out_len;
   return fn(args..., &ctx, botan_view_bin_bounce_fn);
}

template <typename Fn, typename... Args>
int copy_view_str(uint8_t out[], size_t* out_len, Fn fn, Args... args) {
   if(fn == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   botan_view_bounce_struct ctx;
   ctx.out_ptr = out;
   ctx.out_len = out_len;
   return fn(args..., &ctx, botan_view_str_bounce_fn);
}

inline int write_output(uint8_t out[], size_t* out_len, const uint8_t buf[], size_t buf_len) {
   if(out_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   const size_t avail = *out_len;
   *out_len = buf_len;

   if((avail >= buf_len) && (out != nullptr)) {
      Botan::copy_mem(out, buf, buf_len);
      return BOTAN_FFI_SUCCESS;
   } else {
      if(out != nullptr) {
         Botan::clear_mem(out, avail);
      }
      return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
   }
}

template <typename Alloc>
int write_vec_output(uint8_t out[], size_t* out_len, const std::vector<uint8_t, Alloc>& buf) {
   return write_output(out, out_len, buf.data(), buf.size());
}

inline int write_str_output(uint8_t out[], size_t* out_len, std::string_view str) {
   return write_output(out, out_len, Botan::cast_char_ptr_to_uint8(str.data()), str.size() + 1);
}

inline int write_str_output(char out[], size_t* out_len, std::string_view str) {
   return write_str_output(Botan::cast_char_ptr_to_uint8(out), out_len, str);
}

inline int write_str_output(char out[], size_t* out_len, const std::vector<uint8_t>& str_vec) {
   return write_output(Botan::cast_char_ptr_to_uint8(out), out_len, str_vec.data(), str_vec.size());
}

}  // namespace Botan_FFI

#endif
