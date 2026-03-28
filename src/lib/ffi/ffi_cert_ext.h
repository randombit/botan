/*
* (C) 2026 Jack Lloyd
* (C) 2026 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_CERT_EXT_H_
#define BOTAN_FFI_CERT_EXT_H_

#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509_ext.h>
#endif

extern "C" {

#if defined(BOTAN_HAS_X509_CERTIFICATES)

struct botan_x509_ext_ip_addr_blocks_struct final
      : public Botan_FFI::botan_struct<Botan::Cert_Extension::IPAddressBlocks, 0x3A4BA5EE> {
   public:
      explicit botan_x509_ext_ip_addr_blocks_struct(std::unique_ptr<Botan::Cert_Extension::IPAddressBlocks> obj,
                                                    bool writable) :
            botan_struct(std::move(obj)), m_writable(writable) {}

      bool writable() const { return m_writable; }

   private:
      bool m_writable;
};

struct botan_x509_ext_as_blocks_struct final
      : public Botan_FFI::botan_struct<Botan::Cert_Extension::ASBlocks, 0x26E8A3AD> {
   public:
      explicit botan_x509_ext_as_blocks_struct(std::unique_ptr<Botan::Cert_Extension::ASBlocks> obj, bool writable) :
            botan_struct(std::move(obj)), m_writable(writable) {}

      bool writable() const { return m_writable; }

   private:
      bool m_writable;
};

#endif
}

#endif
