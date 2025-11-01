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
#include <botan/internal/mem_utils.h>
#include <concepts>
#include <cstdint>
#include <exception>
#include <memory>

namespace Botan_FFI {

using Botan::any_null_pointers;

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
      explicit botan_struct(std::unique_ptr<T> obj) : m_magic(MAGIC), m_obj(std::move(obj)) {}

      virtual ~botan_struct() {
         m_magic = 0;
         m_obj.reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
      }

      botan_struct(const botan_struct& other) = delete;
      botan_struct(botan_struct&& other) = delete;
      botan_struct& operator=(const botan_struct& other) = delete;
      botan_struct& operator=(botan_struct&& other) = delete;

      bool magic_ok() const { return (m_magic == MAGIC); }

      T* unsafe_get() const { return m_obj.get(); }

   private:
      uint32_t m_magic = 0;
      std::unique_ptr<T> m_obj;
};

// NOLINTBEGIN(*-macro-usage)

#define BOTAN_FFI_DECLARE_STRUCT(NAME, TYPE, MAGIC)                             \
   struct NAME final : public Botan_FFI::botan_struct<TYPE, MAGIC> {            \
         explicit NAME(std::unique_ptr<TYPE> x) : botan_struct(std::move(x)) {} \
   }

#define BOTAN_FFI_DECLARE_DUMMY_STRUCT(NAME, MAGIC) \
   struct NAME final : public Botan_FFI::botan_struct<int, MAGIC> {}

// NOLINTEND(*-macro-usage)

// Declared in ffi.cpp
void ffi_clear_last_exception();

int ffi_error_exception_thrown(const char* func_name, const char* exn, int rc);

int ffi_error_exception_thrown(const char* func_name, const char* exn, Botan::ErrorType err);

template <typename T, uint32_t M>
T& safe_get(botan_struct<T, M>* p) {
   if(!p) {
      throw FFI_Error("Null pointer argument", BOTAN_FFI_ERROR_NULL_POINTER);
   }
   if(!p->magic_ok()) {
      throw FFI_Error("Bad magic in ffi object", BOTAN_FFI_ERROR_INVALID_OBJECT);
   }

   if(T* t = p->unsafe_get()) {
      return *t;
   }

   throw FFI_Error("Invalid object pointer", BOTAN_FFI_ERROR_INVALID_OBJECT);
}

template <std::invocable T>
int ffi_guard_thunk(const char* func_name, T thunk) {
   ffi_clear_last_exception();

   try {
      return thunk();
   } catch(std::bad_alloc&) {
      return ffi_error_exception_thrown(func_name, "bad_alloc", BOTAN_FFI_ERROR_OUT_OF_MEMORY);
   } catch(Botan_FFI::FFI_Error& e) {
      return ffi_error_exception_thrown(func_name, e.what(), e.error_code());
   } catch(Botan::Exception& e) {
      return ffi_error_exception_thrown(func_name, e.what(), e.error_type());
   } catch(std::exception& e) {
      return ffi_error_exception_thrown(func_name, e.what(), BOTAN_FFI_ERROR_EXCEPTION_THROWN);
   } catch(...) {
      return ffi_error_exception_thrown(func_name, "unknown exception", BOTAN_FFI_ERROR_EXCEPTION_THROWN);
   }
}

template <typename T, uint32_t M, typename F>
int botan_ffi_visit(botan_struct<T, M>* o, F func, const char* func_name) {
   using RetT = std::invoke_result_t<F, T&>;
   static_assert(std::is_void_v<RetT> || std::is_same_v<RetT, BOTAN_FFI_ERROR> || std::is_same_v<RetT, int>,
                 "BOTAN_FFI_DO must be used with a block that returns either nothing, int or BOTAN_FFI_ERROR");

   if(!o) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(!o->magic_ok()) {
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
// NOLINTNEXTLINE(*-macro-usage)
#define BOTAN_FFI_VISIT(obj, lambda) botan_ffi_visit(obj, lambda, __func__)

template <typename T, uint32_t M>
int ffi_delete_object(botan_struct<T, M>* obj, const char* func_name) {
   return ffi_guard_thunk(func_name, [=]() -> int {
      // ignore delete of null objects
      if(obj == nullptr) {
         return BOTAN_FFI_SUCCESS;
      }

      if(!obj->magic_ok()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT;
      }

      delete obj;  // NOLINT(*-owning-memory)
      return BOTAN_FFI_SUCCESS;
   });
}

template <typename T, typename... Args>
BOTAN_FFI_ERROR ffi_new_object(T* obj, Args&&... args) {
   // NOLINTNEXTLINE(*-owning-memory)
   *obj = new std::remove_pointer_t<T>(std::forward<Args>(args)...);
   return BOTAN_FFI_SUCCESS;
}

// NOLINTNEXTLINE(*-macro-usage)
#define BOTAN_FFI_CHECKED_DELETE(o) ffi_delete_object(o, __func__)

inline int invoke_view_callback(botan_view_bin_fn view, botan_view_ctx ctx, std::span<const uint8_t> buf) {
   if(view == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return view(ctx, buf.data(), buf.size());
}

// Should not be std::string_view as we rely on being able to NULL terminate
inline int invoke_view_callback(botan_view_str_fn view, botan_view_ctx ctx, const std::string& str) {
   if(view == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
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
   botan_view_bounce_struct ctx{out, out_len};
   return fn(args..., &ctx, botan_view_bin_bounce_fn);
}

template <typename Fn, typename... Args>
int copy_view_str(uint8_t out[], size_t* out_len, Fn fn, Args... args) {
   if(fn == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   botan_view_bounce_struct ctx{out, out_len};
   return fn(args..., &ctx, botan_view_str_bounce_fn);
}

template <std::integral T>
   requires(sizeof(T) == 1)
inline int check_and_prepare_output_space(T out[], size_t* out_len, size_t required_len) {
   if(out_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   const size_t avail = *out_len;
   *out_len = required_len;

   if(avail < required_len || out == nullptr) {
      if(out != nullptr) {
         Botan::clear_mem(out, avail);
      }
      return BOTAN_FFI_ERROR_INSUFFICIENT_BUFFER_SPACE;
   } else {
      return BOTAN_FFI_SUCCESS;
   }
}

template <std::integral T>
inline int write_output(T out[], size_t* out_len, const T buf[], size_t buf_len) {
   static_assert(sizeof(T) == 1, "T should be either uint8_t or char");

   const auto rc = check_and_prepare_output_space(out, out_len, buf_len);
   if(rc != BOTAN_FFI_SUCCESS) {
      return rc;
   }

   if(out != nullptr) {
      Botan::copy_mem(out, buf, buf_len);
   }

   return BOTAN_FFI_SUCCESS;
}

inline int write_vec_output(uint8_t out[], size_t* out_len, std::span<const uint8_t> buf) {
   return write_output<uint8_t>(out, out_len, buf.data(), buf.size());
}

inline int write_str_output(char out[], size_t* out_len, const std::string& str) {
   return write_output<char>(out, out_len, str.data(), str.size() + 1);
}

}  // namespace Botan_FFI

#endif
