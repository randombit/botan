/*
* Policies
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_POLICY_H__
#define BOTAN_TLS_POLICY_H__

#include <botan/tls_magic.h>
#include <botan/x509cert.h>
#include <botan/dl_group.h>
#include <vector>

namespace Botan {

/**
* TLS Policy Base Class
* Inherit and overload as desired to suite local policy concerns
*/
class BOTAN_DLL TLS_Policy
   {
   public:
      std::vector<u16bit> ciphersuites() const;
      virtual std::vector<byte> compression() const;

      virtual u16bit choose_suite(const std::vector<u16bit>& client_suites,
                                  bool rsa_ok,
                                  bool dsa_ok) const;

      virtual byte choose_compression(const std::vector<byte>& client) const;

      virtual bool allow_static_rsa() const { return true; }
      virtual bool allow_edh_rsa() const { return true; }
      virtual bool allow_edh_dsa() const { return true; }
      virtual bool require_client_auth() const { return false; }

      virtual DL_Group dh_group() const;
      virtual size_t rsa_export_keysize() const { return 512; }

      /*
      * @return the minimum version that we will negotiate
      */
      virtual Version_Code min_version() const { return TLS_V10; }

      /*
      * @return the version we would prefer to negotiate
      */
      virtual Version_Code pref_version() const { return TLS_V11; }

      virtual bool check_cert(const std::vector<X509_Certificate>& cert_chain) const = 0;

      virtual ~TLS_Policy() {}
   private:
      virtual std::vector<u16bit> suite_list(bool use_rsa,
                                             bool use_edh_rsa,
                                             bool use_edh_dsa) const;
   };

}

#endif
