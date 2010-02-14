/**
* Policies Header File
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_POLICY_H__
#define BOTAN_POLICY_H__

#include <botan/x509cert.h>
#include <botan/dl_group.h>
#include <botan/tls_magic.h>
#include <vector>

namespace Botan {

/**
* Policy Base Class
*/
class BOTAN_DLL Policy
   {
   public:
      std::vector<u16bit> ciphersuites() const;
      virtual std::vector<byte> compression() const;

      virtual u16bit choose_suite(const std::vector<u16bit>&,
                                  bool, bool) const;
      virtual byte choose_compression(const std::vector<byte>&) const;

      virtual bool allow_static_rsa() const;
      virtual bool allow_edh_rsa() const;
      virtual bool allow_edh_dsa() const;
      virtual bool require_client_auth() const;

      virtual DL_Group dh_group() const;
      virtual u32bit rsa_export_keysize() const;

      virtual Version_Code min_version() const;
      virtual Version_Code pref_version() const;

      virtual bool check_cert(const std::vector<X509_Certificate>&,
                              const std::string&) const;

      virtual ~Policy() {}
   private:
      virtual std::vector<u16bit> suite_list(bool, bool, bool) const;
   };

}

#endif
