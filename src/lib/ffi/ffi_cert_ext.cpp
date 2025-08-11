/*
* (C) 2025 Jack Lloyd
* (C) 2025 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ffi.h>

#include <botan/internal/ffi_cert.h>
#include <botan/internal/ffi_cert_ext.h>
#include <botan/internal/ffi_util.h>
#include <memory>

namespace {
template <Botan::Cert_Extension::IPAddressBlocks::Version V>
void ip_addr_blocks_ext_add_address(Botan::Cert_Extension::IPAddressBlocks& ext,
                                    const uint8_t* min,
                                    const uint8_t* max,
                                    std::optional<uint8_t> safi) {
   const size_t version_octets = static_cast<size_t>(V);

   std::array<uint8_t, version_octets> min_{};
   std::array<uint8_t, version_octets> max_{};
   std::copy(min, min + version_octets, min_.begin());
   std::copy(max, max + version_octets, max_.begin());
   ext.add_address<V>(min_, max_, safi);
}

template <Botan::Cert_Extension::IPAddressBlocks::Version V>
int ip_addr_blocks_get_family(const Botan::Cert_Extension::IPAddressBlocks::IPAddressFamily& family,
                              int* present,
                              size_t* count) {
   if(!std::holds_alternative<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(family.addr_choice())) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
   auto v4 = std::get<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(family.addr_choice());

   if(!v4.ranges().has_value()) {
      *present = 0;
   } else {
      *present = 1;
      *count = v4.ranges().value().size();
   }
   return BOTAN_FFI_SUCCESS;
}

template <Botan::Cert_Extension::IPAddressBlocks::Version V>
int ip_addr_blocks_get_address(const Botan::Cert_Extension::IPAddressBlocks::IPAddressFamily::AddrChoice& choice,
                               size_t entry,
                               uint8_t min_out[],
                               uint8_t max_out[],
                               size_t* out_len) {
   if(!std::holds_alternative<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(choice)) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }
   auto v4 = std::get<Botan::Cert_Extension::IPAddressBlocks::IPAddressChoice<V>>(choice);

   if(!v4.ranges().has_value() || entry >= v4.ranges().value().size()) {
      return BOTAN_FFI_ERROR_BAD_PARAMETER;
   }

   auto entry_ = v4.ranges().value().at(entry);

   auto ret = Botan_FFI::write_vec_output(min_out, out_len, entry_.min().value());
   if(ret != BOTAN_FFI_SUCCESS) {
      return ret;
   }
   return Botan_FFI::write_vec_output(max_out, out_len, entry_.max().value());
}

}  // namespace

extern "C" {

using namespace Botan_FFI;

int botan_x509_ext_ip_addr_blocks_destroy(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(ip_addr_blocks);
#else
   BOTAN_UNUSED(opts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_create(botan_x509_ext_ip_addr_blocks_t* ip_addr_blocks) {
   if(ip_addr_blocks == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined BOTAN_HAS_X509_CERTIFICATES
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto ext = std::make_unique<Botan::Cert_Extension::IPAddressBlocks>();
      return ffi_new_object(ip_addr_blocks, std::move(ext), true);
   });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_create_from_cert(botan_x509_ext_ip_addr_blocks_t* ip_addr_blocks,
                                                   botan_x509_cert_t cert) {
   if(ip_addr_blocks == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto* const ext =
         safe_get(cert).v3_extensions().get_extension_object_as<Botan::Cert_Extension::IPAddressBlocks>();

      if(ext == nullptr) {
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

int botan_x509_ext_ip_addr_blocks_add_ip_addr(
   botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, const uint8_t* min, const uint8_t* max, int ipv6, uint8_t* safi) {
   if(min == nullptr || max == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined BOTAN_HAS_X509_CERTIFICATES
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ipv6 != 0 && ipv6 != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      auto& ext = safe_get(ip_addr_blocks);
      if(!ip_addr_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      std::optional<uint8_t> safi_;
      if(safi != nullptr) {
         safi_ = *safi;
      }

      if(ipv6 == 0) {
         ip_addr_blocks_ext_add_address<Botan::Cert_Extension::IPAddressBlocks::Version::IPv4>(ext, min, max, safi_);
      } else {
         ip_addr_blocks_ext_add_address<Botan::Cert_Extension::IPAddressBlocks::Version::IPv6>(ext, min, max, safi_);
      }

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ip_addr_blocks, addr_length);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_restrict(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, int ipv6, uint8_t* safi) {
#if defined BOTAN_HAS_X509_CERTIFICATES
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ipv6 != 0 && ipv6 != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      auto& ext = safe_get(ip_addr_blocks);
      if(!ip_addr_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      std::optional<uint8_t> safi_;
      if(safi != nullptr) {
         safi_ = *safi;
      }

      if(ipv6 == 0) {
         ext.restrict<Botan::Cert_Extension::IPAddressBlocks::Version::IPv4>(safi_);
      } else {
         ext.restrict<Botan::Cert_Extension::IPAddressBlocks::Version::IPv6>(safi_);
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ip_addr_blocks, ipv6, safi);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_inherit(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks, int ipv6, uint8_t* safi) {
#if defined BOTAN_HAS_X509_CERTIFICATES
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ipv6 != 0 && ipv6 != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      auto& ext = safe_get(ip_addr_blocks);
      if(!ip_addr_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }

      std::optional<uint8_t> safi_;
      if(safi != nullptr) {
         safi_ = *safi;
      }

      if(ipv6 == 0) {
         ext.inherit<Botan::Cert_Extension::IPAddressBlocks::Version::IPv4>(safi_);
      } else {
         ext.inherit<Botan::Cert_Extension::IPAddressBlocks::Version::IPv6>(safi_);
      }
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(ip_addr_blocks, ipv6, safi);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_ip_addr_blocks_get_counts(botan_x509_ext_ip_addr_blocks_t ip_addr_blocks,
                                             size_t* v4_count,
                                             size_t* v6_count) {
   if(v4_count == nullptr || v6_count == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined BOTAN_HAS_X509_CERTIFICATES
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
   if(has_safi == nullptr || safi == nullptr || present == nullptr || count == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined BOTAN_HAS_X509_CERTIFICATES
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ipv6 != 0 && ipv6 != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      const auto& addr_blocks = safe_get(ip_addr_blocks).addr_blocks();

      if(i >= addr_blocks.size()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
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
   BOTAN_UNUSED(ip_addr_blocks, i, ipv6);
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
#if defined BOTAN_HAS_X509_CERTIFICATES
   return ffi_guard_thunk(__func__, [=]() -> int {
      if(ipv6 != 0 && ipv6 != 1) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      const auto& addr_blocks = safe_get(ip_addr_blocks).addr_blocks();

      if(i >= addr_blocks.size()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }
      const auto& choice = addr_blocks.at(i).addr_choice();

      if(ipv6 == 0) {
         return ip_addr_blocks_get_address<Botan::Cert_Extension::IPAddressBlocks::Version::IPv4>(
            choice, entry, min_out, max_out, out_len);
      } else {
         return ip_addr_blocks_get_address<Botan::Cert_Extension::IPAddressBlocks::Version::IPv6>(
            choice, entry, min_out, max_out, out_len);
      }
   });
#else
   BOTAN_UNUSED(ip_addr_blocks, ipv6, i, entry, min_out, max_out);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_destroy(botan_x509_ext_as_blocks_t as_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return BOTAN_FFI_CHECKED_DELETE(as_blocks);
#else
   BOTAN_UNUSED(opts);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_create(botan_x509_ext_as_blocks_t* as_blocks) {
   if(as_blocks == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined BOTAN_HAS_X509_CERTIFICATES
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto ext = std::make_unique<Botan::Cert_Extension::ASBlocks>();
      return ffi_new_object(as_blocks, std::move(ext), true);
   });
#else
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_create_from_cert(botan_x509_ext_as_blocks_t* as_blocks, botan_x509_cert_t cert) {
   if(as_blocks == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto* const ext = safe_get(cert).v3_extensions().get_extension_object_as<Botan::Cert_Extension::ASBlocks>();

      if(ext == nullptr) {
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

int botan_x509_ext_as_blocks_add_asnum(botan_x509_ext_as_blocks_t as_blocks, uint32_t min, uint32_t max) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& ext = safe_get(as_blocks);
      if(!as_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      ext.add_asnum(min, max);
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks, min, max);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_restrict_asnum(botan_x509_ext_as_blocks_t as_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& ext = safe_get(as_blocks);
      if(!as_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      ext.restrict_asnum();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_inherit_asnum(botan_x509_ext_as_blocks_t as_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& ext = safe_get(as_blocks);
      if(!as_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      ext.inherit_asnum();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_add_rdi(botan_x509_ext_as_blocks_t as_blocks, uint32_t min, uint32_t max) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& ext = safe_get(as_blocks);
      if(!as_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      ext.add_rdi(min, max);
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks, min, max);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_restrict_rdi(botan_x509_ext_as_blocks_t as_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& ext = safe_get(as_blocks);
      if(!as_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      ext.restrict_rdi();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_inherit_rdi(botan_x509_ext_as_blocks_t as_blocks) {
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      auto& ext = safe_get(as_blocks);
      if(!as_blocks->writable()) {
         return BOTAN_FFI_ERROR_INVALID_OBJECT_STATE;
      }
      ext.inherit_rdi();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_get_asnum(botan_x509_ext_as_blocks_t as_blocks, int* present, size_t* count) {
   if(present == nullptr || count == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto& asnum = safe_get(as_blocks).as_identifiers().asnum();

      if(!asnum.has_value()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      const auto& ranges = asnum.value().ranges();

      if(!ranges.has_value()) {
         *present = 0;
         return BOTAN_FFI_SUCCESS;
      }

      *present = 1;
      *count = ranges.value().size();

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_get_asnum_at(botan_x509_ext_as_blocks_t as_blocks,
                                          size_t i,
                                          uint32_t* min,
                                          uint32_t* max) {
   if(min == nullptr || max == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto& asnum = safe_get(as_blocks).as_identifiers().asnum();

      if(!asnum.has_value() || !asnum.value().ranges().has_value()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      const auto& range = asnum.value().ranges().value();
      if(i >= range.size()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      *min = range.at(i).min();
      *max = range.at(i).max();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks, i);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_get_rdi(botan_x509_ext_as_blocks_t as_blocks, int* present, size_t* count) {
   if(present == nullptr || count == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto& rdi = safe_get(as_blocks).as_identifiers().rdi();

      if(!rdi.has_value()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      const auto& ranges = rdi.value().ranges();

      if(!ranges.has_value()) {
         *present = 0;
         return BOTAN_FFI_SUCCESS;
      }

      *present = 1;
      *count = ranges.value().size();

      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}

int botan_x509_ext_as_blocks_get_rdi_at(botan_x509_ext_as_blocks_t as_blocks, size_t i, uint32_t* min, uint32_t* max) {
   if(min == nullptr || max == nullptr) {
      return BOTAN_FFI_ERROR_NULL_POINTER;
   }
#if defined(BOTAN_HAS_X509_CERTIFICATES)
   return ffi_guard_thunk(__func__, [=]() -> int {
      const auto& rdi = safe_get(as_blocks).as_identifiers().rdi();

      if(!rdi.has_value() || !rdi.value().ranges().has_value()) {
         return BOTAN_FFI_ERROR_NO_VALUE;
      }

      const auto& range = rdi.value().ranges().value();
      if(i >= range.size()) {
         return BOTAN_FFI_ERROR_BAD_PARAMETER;
      }

      *min = range.at(i).min();
      *max = range.at(i).max();
      return BOTAN_FFI_SUCCESS;
   });
#else
   BOTAN_UNUSED(as_blocks, i);
   return BOTAN_FFI_ERROR_NOT_IMPLEMENTED;
#endif
}
}
