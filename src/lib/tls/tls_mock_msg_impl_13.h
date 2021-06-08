/*
* TLS Mock Msg Impl 13 - TODO: this file should be deleted when TLS 1.3 implementation is ready
* (C) 2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TLS_MOCK_MSG_IMPL_13_H_
#define BOTAN_TLS_MOCK_MSG_IMPL_13_H_

#include <botan/p11_x509.h>
#include <botan/internal/msg_cert_req_impl.h>
#include <botan/internal/msg_certificate_impl.h>
#include <botan/tls_algos.h>

#include <vector>
#include <string>

namespace Botan {

namespace TLS {

#include <vector>
template< typename T >
class Mock_Impl_13: public T
{
   public:
      template <typename ... Args>
      explicit Mock_Impl_13(Args&& ... args)
      : T(std::forward<Args>(args) ... )
      {
      // TODO throw std::runtime_error("Implemenation for TLSv1.3 not ready yet. You are welcome to implement it.");
      }
};

class Mock_Certificate_Impl_13 : public Certificate_Impl
{
   public:
      template <typename ... Args>
      explicit Mock_Certificate_Impl_13(Args&& ... args)
      : Certificate_Impl(std::forward<Args>(args) ... )
      {
      // TODO throw std::runtime_error("Implemenation for TLSv1.3 not ready yet. You are welcome to implement it.");
      }

      // from Certificate_Impl
      std::vector<unsigned char> serialize() const override { return {}; }
      const std::vector<Botan::X509_Certificate>& cert_chain() const override { return m_mock_cert_chain; }
      std::size_t count() const override { return {}; }
      bool empty() const override { return {}; }

   private:
      std::vector<Botan::X509_Certificate> m_mock_cert_chain;
};

class Mock_Certificate_Req_Impl_13 : public Certificate_Req_Impl
{
   public:
      template <typename ... Args>
      explicit Mock_Certificate_Req_Impl_13(Args&& ... args)
      : Certificate_Req_Impl(std::forward<Args>(args) ... )
      {
      // throw std::runtime_error("Implemenation for TLSv1.3 not ready yet. You are welcome to implement it.");
      }

      // from Certificate_Req_Impl
      std::vector<unsigned char> serialize() const override { return {}; }
      const std::vector<std::string>& acceptable_cert_types() const override { return m_acceptable_cert_types; }
      const std::vector<X509_DN>& acceptable_CAs() const override { return m_mock_acceptable_CAs; }
      const std::vector<Signature_Scheme>& signature_schemes() const override { return m_mock_signature_schemes; }

   private:
      std::vector<std::string> m_acceptable_cert_types;
      std::vector<X509_DN> m_mock_acceptable_CAs;
      std::vector<Signature_Scheme> m_mock_signature_schemes;
};

}
}


#endif
