/*
* (C) 2025 Jack Lloyd
*     2025 René Meusel, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/xof.h>
#include <botan/internal/ffi_util.h>

extern "C" {

using namespace Botan_FFI;

BOTAN_FFI_DECLARE_STRUCT(botan_xof_struct, Botan::XOF, 0x0f1303a0);

int botan_xof_init(botan_xof_t* this_xof, const char* xof_name, uint32_t flags) {
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(Botan::any_null_pointers(this_xof, xof_name) || *xof_name == 0) {
         return BOTAN_FFI_ERROR_NULL_POINTER;
      }
      if(flags != 0) {
         return BOTAN_FFI_ERROR_BAD_FLAG;
      }

      auto xof = Botan::XOF::create(xof_name);
      if(xof == nullptr) {
         return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
      }

      ffi_new_object(this_xof, std::move(xof));
      return BOTAN_FFI_SUCCESS;
   });
}

// NOLINTNEXTLINE(misc-misplaced-const)
int botan_xof_copy_state(botan_xof_t* dest, const botan_xof_t this_xof) {
   return BOTAN_FFI_VISIT(this_xof, [=](const auto& src) { return ffi_new_object(dest, src.copy_state()); });
}

int botan_xof_block_size(botan_xof_t this_xof, size_t* out) {
   if(Botan::any_null_pointers(out)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
   return BOTAN_FFI_VISIT(this_xof, [=](const auto& xof) { *out = xof.block_size(); });
}

int botan_xof_name(botan_xof_t this_xof, char* name, size_t* name_len) {
   if(Botan::any_null_pointers(name_len)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(this_xof, [=](const auto& xof) { return write_str_output(name, name_len, xof.name()); });
}

int botan_xof_accepts_input(botan_xof_t this_xof) {
   return BOTAN_FFI_VISIT(this_xof, [=](const auto& xof) { return xof.accepts_input() ? 1 : 0; });
}

int botan_xof_clear(botan_xof_t this_xof) {
   return BOTAN_FFI_VISIT(this_xof, [](auto& xof) { xof.clear(); });
}

int botan_xof_update(botan_xof_t this_xof, const uint8_t* in, size_t in_len) {
   if(in_len == 0) {
      return 0;
   }

   if(Botan::any_null_pointers(in)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(this_xof, [=](auto& xof) { xof.update({in, in_len}); });
}

int botan_xof_output(botan_xof_t this_xof, uint8_t* out, size_t out_len) {
   if(out_len == 0) {
      return 0;
   }

   if(Botan::any_null_pointers(out)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }

   return BOTAN_FFI_VISIT(this_xof, [=](auto& xof) { xof.output({out, out_len}); });
}

int botan_xof_destroy(botan_xof_t xof) {
   return BOTAN_FFI_CHECKED_DELETE(xof);
}
}
