/*
* (C) 2026 Jack Lloyd
* (C) 2026 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_cert_ext.h>

namespace {
#if defined(BOTAN_HAS_X509_CERTIFICATES)

template <Botan::Cert_Extension::IPAddressBlocks::Version V>
int ip_addr_blocks_get_family(const Botan::Cert_Extension::IPAddressBlocks::IPAddressFamily& family,
                              int* present,
                              size_t* count) {
   if(!std::holds_alternative<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(family.addr_choice())) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
   const auto& choice = std::get<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(family.addr_choice());

   if(!choice.ranges().has_value()) {
      *present = 0;
   } else {
      *present = 1;
      *count = choice.ranges().value().size();
   }
   return BOTAN_FFI_SUCCESS;
}

template <Botan::Cert_Extension::IPAddressBlocks::Version V>
int ip_addr_blocks_get_address(const Botan::Cert_Extension::IPAddressBlocks::IPAddressFamily::AddrChoice& addr_choice,
                               size_t entry,
                               uint8_t min_out[],
                               uint8_t max_out[],
                               size_t* out_len) {
   if(!std::holds_alternative<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(addr_choice)) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
   const auto& choice = std::get<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(addr_choice);

   if(!choice.ranges().has_value()) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
   if(entry >= choice.ranges().value().size()) {
      return BOTAN_FFI_ERROR_OUT_OF_RANGE;
   }

   const auto& entry_ = choice.ranges().value().at(entry);

   const int ret = Botan_FFI::write_vec_output(min_out, out_len, entry_.min().value());
   if(ret != BOTAN_FFI_SUCCESS) {
      return ret;
   }
   return Botan_FFI::write_vec_output(max_out, out_len, entry_.max().value());
}
#endif
}  // namespace

extern "C" {

using namespace Botan_FFI;

// ip addr blocks ext

int botan_x509_ext_ip_addr_blocks_destroy(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ip_addr_blocks);
#else
   BOTAN_UNUSED(ip_addr_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_create_from_cert(botan_x509_ext_ip_addr_blocks_t* ip_addr_blocks,
                                                   botan_x509_cert_t cert) {
   if(Botan::any_null_pointers(ip_addr_blocks)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto* const ext =
         safe_get(cert).v3_extensions().get_extension_object_as<Botan::Cert_Extension::IPAddressBlocks>();

      if(Botan::any_null_pointers(ext)) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }
      return ffi_new_object(ip_addr_blocks,
                            std::unique_ptr<Botan::Cert_Extension::IPAddressBlocks>(
                               dynamic_cast<Botan::Cert_Extension::IPAddressBlocks*>(ext->copy().release())),
                            false);
   });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_get_counts(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks,
                                             size_t* v4_count,
                                             size_t* v6_count) {
   if(Botan::any_null_pointers(v4_count, v6_count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto& ext = safe_get(ip_addr_blocks);
      size_t v4 = 0;
      size_t v6 = 0;

      for(const auto& entry : ext.addr_blocks()) {
         if(entry.afi() == 1) {
            v4++;
         } else {
            v6++;
         }
      }
      *v4_count = v4;
      *v6_count = v6;

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ip_addr_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_get_family(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks,
                                             int ipv6,
                                             size_t i,
                                             int* has_safi,
                                             uint8_t* safi,
                                             int* present,
                                             size_t* count) {
   if(Botan::any_null_pointers(has_safi, safi, present, count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ipv6 != 0 && ipv6 != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      const auto& addr_blocks = safe_get(ip_addr_blocks).addr_blocks();

      if(i >= addr_blocks.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      }

      const auto& family = addr_blocks.at(i);
      if(family.safi().has_value()) {
         *has_safi = 1;
         *safi = family.safi().value();
      } else {
         *has_safi = 0;
      }

      if(ipv6 == 0) {
         return ip_addr_blocks_get_family<Botan::Cert_Extension::IPAddressBlocks::Version::IPv4>(
            family, present, count);
      } else {
         return ip_addr_blocks_get_family<Botan::Cert_Extension::IPAddressBlocks::Version::IPv6>(
            family, present, count);
      }
   });
#else
   BOTAN_UNUSED(ip_addr_blocks, ipv6, i);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_get_address(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks,
                                              int ipv6,
                                              size_t i,
                                              size_t entry,
                                              uint8_t min_out[],
                                              uint8_t max_out[],
                                              size_t* out_len) {
   if(out_len == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ipv6 != 0 && ipv6 != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      const auto& addr_blocks = safe_get(ip_addr_blocks).addr_blocks();

      if(i >= addr_blocks.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      }
      const auto& addr_choice = addr_blocks.at(i).addr_choice();

      if(ipv6 == 0) {
         return ip_addr_blocks_get_address<Botan::Cert_Extension::IPAddressBlocks::Version::IPv4>(
            addr_choice, entry, min_out, max_out, out_len);
      } else {
         return ip_addr_blocks_get_address<Botan::Cert_Extension::IPAddressBlocks::Version::IPv6>(
            addr_choice, entry, min_out, max_out, out_len);
      }
   });
#else
   BOTAN_UNUSED(ip_addr_blocks, ipv6, i, entry, min_out, max_out);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

// as blocks ext

int botan_x509_ext_as_blocks_destroy(botan_x509_ext_as_blocks_t as_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(as_blocks);
#else
   BOTAN_UNUSED(as_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_create_from_cert(botan_x509_ext_as_blocks_t* as_blocks, botan_x509_cert_t cert) {
   if(Botan::any_null_pointers(as_blocks)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto* const ext = safe_get(cert).v3_extensions().get_extension_object_as<Botan::Cert_Extension::ASBlocks>();

      if(Botan::any_null_pointers(ext)) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }
      return ffi_new_object(as_blocks,
                            std::unique_ptr<Botan::Cert_Extension::ASBlocks>(
                               dynamic_cast<Botan::Cert_Extension::ASBlocks*>(ext->copy().release())),
                            false);
   });
#else
   BOTAN_UNUSED(cert);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_get_info(botan_x509_ext_as_blocks_t as_blocks, int asnum, int* present, size_t* count) {
   if(Botan::any_null_pointers(present, count)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(asnum != 0 && asnum != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      const auto& blocks = safe_get(as_blocks);
      const auto& asnum_or_rdi = asnum == 1 ? blocks.as_identifiers().asnum() : blocks.as_identifiers().rdi();

      if(!asnum_or_rdi.has_value()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      const auto& ranges = asnum_or_rdi.value().ranges();

      if(!ranges.has_value()) {
         *present = 0;
         return BOTAN_FFI_SUCCESS;
      }

      *present = 1;
      *count = ranges.value().size();

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks, asnum);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_get_entry_at(
   botan_x509_ext_as_blocks_t as_blocks, int asnum, size_t i, uint32_t* min, uint32_t* max) {
   if(Botan::any_null_pointers(min, max)) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(asnum != 0 && asnum != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      const auto& blocks = safe_get(as_blocks);
      const auto& asnum_or_rdi = asnum == 1 ? blocks.as_identifiers().asnum() : blocks.as_identifiers().rdi();

      if(!asnum_or_rdi.has_value() || !asnum_or_rdi.value().ranges().has_value()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      const auto& range = asnum_or_rdi.value().ranges().value();
      if(i >= range.size()) {
         return BOTAN_FFI_ERROR_OUT_OF_RANGE;
      }

      *min = range.at(i).min();
      *max = range.at(i).max();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks, asnum, i);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
