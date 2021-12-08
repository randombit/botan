/*
* TLS Certificate Verify Message interface
* (C) 2004-2011,2015 Jack Lloyd
*     2016 Matthias Gierlings
*     2021 Elektrobit Automotive GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_MSG_CERT_VERIFY_IMPL_H_
#define BOTAN_MSG_CERT_VERIFY_IMPL_H_

#include <botan/tls_handshake_msg.h>
#include <botan/tls_algos.h>
#include <vector>

namespace Botan {

class X509_Certificate;
class RandomNumberGenerator;
class Private_Key;

namespace TLS {

class Handshake_IO;
class Handshake_State;
class Policy;

/**
* Interface of pimpl for Certificate Verify Message
*/
class Certificate_Verify_Impl : public Handshake_Message
   {
   public:
      Handshake_Type type() const override;

      /**
      * Check the signature on a certificate verify message
      * @param cert the purported certificate
      * @param state the handshake state
      * @param policy the TLS policy
      */
      virtual bool verify(const X509_Certificate& cert,
                          const Handshake_State& state,
                          const Policy& policy) const;

      Certificate_Verify_Impl(Handshake_IO& io,
                              Handshake_State& state,
                              const Policy& policy,
                              RandomNumberGenerator& rng,
                              const Private_Key* key);

      explicit Certificate_Verify_Impl(const std::vector<uint8_t>& buf);

      std::vector<uint8_t> serialize() const override;
   private:
      std::vector<uint8_t> m_signature;
      Signature_Scheme m_scheme = Signature_Scheme::NONE;
   };
}

}

#endif
