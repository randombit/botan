/*
* (C) 2025 Jack Lloyd
* (C) 2025 Dominik Schricker
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_FFI_X509_RPKI_H_
#define BOTAN_FFI_X509_RPKI_H_

#include <botan/internal/ffi_util.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)
   #include <botan/x509_ext.h>
#endif

extern "C" {

using namespace Botan_FFI;

#if defined(BOTAN_HAS_X509_CERTIFICATES)

struct botan_x509_ext_ip_addr_blocks_struct final
      : public botan_struct<Botan::Cert_Extension::IPAddressBlocks, 0xB489828F> {
   public:
      explicit botan_x509_ext_ip_addr_blocks_struct(std::unique_ptr<Botan::Cert_Extension::IPAddressBlocks> obj,
                                                    bool writable) :
            botan_struct(std::move(obj)), m_writable(writable) {}

      bool writable() const { return m_writable; }

   private:
      bool m_writable;
};

struct botan_x509_ext_as_blocks_struct final : public botan_struct<Botan::Cert_Extension::ASBlocks, 0xA56348EC> {
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
