/*
* PKCS#11 X.509
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_x509.h>

#if defined(BOTAN_HAS_X509_CERTIFICATES)

namespace Botan {
namespace PKCS11 {

X509_CertificateProperties::X509_CertificateProperties(const std::vector<uint8_t>& subject, const std::vector<uint8_t>& value)
   : CertificateProperties(CertificateType::X509), m_subject(subject), m_value(value)
   {
   add_binary(AttributeType::Subject, m_subject);
   add_binary(AttributeType::Value, m_value);
   }

PKCS11_X509_Certificate::PKCS11_X509_Certificate(Session& session, ObjectHandle handle)
   : Object(session, handle), X509_Certificate(unlock(get_attribute_value(AttributeType::Value)))
   {
   }

PKCS11_X509_Certificate::PKCS11_X509_Certificate(Session& session, const X509_CertificateProperties& props)
   : Object(session, props), X509_Certificate(props.value())
   {
   }

}

}

#endif
