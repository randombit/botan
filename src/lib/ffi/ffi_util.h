/*
* (C) 2015,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_UTILS_H_
#define BOTAN_FFI_UTILS_H_

#include <botan/exceptn.h>
#include <botan/ffi.h>
#include <botan/internal/mem_utils.h>
#include <concepts>
#include <cstdint>
#include <cstring>
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

template <typename T>
concept ffi_object_smart_pointer = requires(T& obj) {
   { obj.get() } -> std::same_as<typename T::element_type*>;
   { obj.reset() };
};

/**
 * Base class for all FFI object handles wrapped around some specific type in
 * the library. The inner type is managed by a configurable smart pointer type
 * (e.g. std::unique_ptr or std::shared_ptr).
 */
template <typename T, uint32_t MAGIC, template <typename... Args> typename PtrType>
   requires ffi_object_smart_pointer<PtrType<T>>
struct botan_ffi_obj {
   public:
      using element_type = T;
      using smart_pointer_type = PtrType<T>;

   public:
      explicit botan_ffi_obj(smart_pointer_type obj) : m_magic(MAGIC), m_obj(std::move(obj)) {}

      virtual ~botan_ffi_obj() {
         m_magic = 0;
         m_obj.reset();  // NOLINT(*-ambiguous-smartptr-reset-call)
      }

      botan_ffi_obj(const botan_ffi_obj& other) = delete;
      botan_ffi_obj(botan_ffi_obj&& other) = delete;
      botan_ffi_obj& operator=(const botan_ffi_obj& other) = delete;
      botan_ffi_obj& operator=(botan_ffi_obj&& other) = delete;

      bool magic_ok() const { return (m_magic == MAGIC); }

      /// Retrieve the raw pointer to the underlying object. May be nullptr.
      T* unsafe_get() const { return m_obj.get(); }

      /// Retrieve the smart pointer to the underlying object. May be invalid.
      smart_pointer_type& unsafe_get_sp() { return m_obj; }

      /// Retrieve the smart pointer to the underlying object. May be invalid.
      const smart_pointer_type& unsafe_get_sp() const { return m_obj; }

   private:
      uint32_t m_magic = 0;
      smart_pointer_type m_obj;
};

template <typename T>
concept ffi_object = requires(const T& obj) {
   { obj.magic_ok() } -> std::same_as<bool>;
};

// NOLINTBEGIN(*-macro-usage)

#define BOTAN_FFI_DECLARE_UNIQUE_STRUCT(NAME, TYPE, MAGIC)                             \
   struct NAME final : public Botan_FFI::botan_ffi_obj<TYPE, MAGIC, std::unique_ptr> { \
         using botan_ffi_obj::botan_ffi_obj;                                           \
   }

#define BOTAN_FFI_DECLARE_SHARED_STRUCT(NAME, TYPE, MAGIC)                             \
   struct NAME final : public Botan_FFI::botan_ffi_obj<TYPE, MAGIC, std::shared_ptr> { \
         using botan_ffi_obj::botan_ffi_obj;                                           \
   }

#define BOTAN_FFI_DECLARE_DUMMY_STRUCT(NAME, MAGIC) \
   struct NAME final : public Botan_FFI::botan_ffi_obj<int, MAGIC, std::unique_ptr> {}

// NOLINTEND(*-macro-usage)

// Declared in ffi.cpp
void ffi_clear_last_exception();

int ffi_error_exception_thrown(const char* func_name, const char* exn, int rc);

int ffi_error_exception_thrown(const char* func_name, const char* exn, Botan::ErrorType err);

/**
 * Checked access to a reference of the underlying object wrapped in the
 * FFI handle @p p.
 */
template <ffi_object T>
auto safe_get(T* p) -> typename T::element_type& {
   if(!p) {
      throw FFI_Error("Null pointer argument", BOTAN_FFI_ERROR_NULL_POINTER);
   }
   if(!p->magic_ok()) {
      throw FFI_Error("Bad magic in ffi object", BOTAN_FFI_ERROR_INVALID_OBJECT);
   }

   if(auto* t = p->unsafe_get()) {
      return *t;
   }

   throw FFI_Error("Invalid object pointer", BOTAN_FFI_ERROR_INVALID_OBJECT);
}

/**
 * Checked access to a reference of the smart pointer of the underlying object
 * wrapped in the FFI handle @p p. Note that the smart pointer is returned by
 * reference, so that the caller can copy it (if it is a std::shared_ptr).
 */
template <ffi_object T>
auto safe_get_sp(T* p) -> const typename T::smart_pointer_type& {
   if(!p) {
      throw FFI_Error("Null pointer argument", BOTAN_FFI_ERROR_NULL_POINTER);
   }
   if(!p->magic_ok()) {
      throw FFI_Error("Bad magic in ffi object", BOTAN_FFI_ERROR_INVALID_OBJECT);
   }

   auto& sp = p->unsafe_get_sp();
   if(sp == nullptr) {
      throw FFI_Error("Invalid object pointer", BOTAN_FFI_ERROR_INVALID_OBJECT);
   }

   return sp;
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

namespace detail {

template <typename T>
concept ffi_visit_result = std::is_void_v<T> || std::same_as<T, int> || std::same_as<T, BOTAN_FFI_ERROR>;

template <typename FnT, typename ArgT>
concept ffi_visitor_for = std::invocable<FnT, ArgT> && ffi_visit_result<std::invoke_result_t<FnT, ArgT>>;

}  // namespace detail

template <typename FnT, typename HandleT>
concept ffi_raw_visitor_fn = detail::ffi_visitor_for<FnT, typename HandleT::element_type&>;

template <typename FnT, typename HandleT>
concept ffi_sp_visitor_fn = detail::ffi_visitor_for<FnT, const typename HandleT::smart_pointer_type&>;

template <typename FnT, typename HandleT>
concept ffi_visitor_fn = ffi_raw_visitor_fn<FnT, HandleT> || ffi_sp_visitor_fn<FnT, HandleT>;

/**
 * Visit the underlying object wrapped in the FFI handle @p o with the visitor
 * function @p func. The visitor function can either take a reference to the
 * underlying object or a reference to the smart pointer of the underlying
 * object and must return either void, BOTAN_FFI_ERROR or int.
 *
 * Note that a visitor lambda function with a generic parameter (e.g. `auto&`)
 * will receive a reference to the underlying object, not the smart pointer.
 */
template <ffi_object HandleT, ffi_visitor_fn<HandleT> VisitorFnT>
int botan_ffi_visit(HandleT* o, VisitorFnT func, const char* func_name) {
   if(!o) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   if(!o->magic_ok()) {
      return BOTAN_FFI_ERROR_INVALID_OBJECT;
   }

   const auto& p = o->unsafe_get_sp();
   if(p == nullptr) {
      return BOTAN_FFI_ERROR_INVALID_OBJECT;
   }

   auto call_visitor = [&](auto&& ref) -> int {
      if constexpr(std::is_void_v<decltype(func(ref))>) {
         return ffi_guard_thunk(func_name, [&] {
            func(ref);
            return BOTAN_FFI_SUCCESS;
         });
      } else {
         return ffi_guard_thunk(func_name, [&] { return func(ref); });
      }
   };

   // Call the visitor either with a reference to the visitee or its inner smart
   // pointer depending on what the visitor expects. If it could handle both,
   // the reference is preferred.
   if constexpr(ffi_raw_visitor_fn<VisitorFnT, HandleT>) {
      return call_visitor(*p);
   } else {
      return call_visitor(p);
   }
}

// TODO: C++20 introduces std::source_location which will allow to eliminate this
//       macro altogether. Instead, using code would just call the C++ function
//       that makes use of std::source_location like so:
//
//   template<typename T, uint32_t M, typename F>
//   int botan_ffi_visit(botan_ffi_obj<T, M, std::unique_ptr>* obj, F func,
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

template <ffi_object T>
int ffi_delete_object(T* obj, const char* func_name) {
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
   if(obj == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
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
   if(out_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   botan_view_bounce_struct ctx{out, out_len};
   return fn(args..., &ctx, botan_view_bin_bounce_fn);
}

template <typename Fn, typename... Args>
int copy_view_str(uint8_t out[], size_t* out_len, Fn fn, Args... args) {
   if(any_null_pointers(fn, out_len)) {
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
         std::memset(out, 0, sizeof(T) * avail);
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
      std::memcpy(out, buf, sizeof(T) * buf_len);
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
