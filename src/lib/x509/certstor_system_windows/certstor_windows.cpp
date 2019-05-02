/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2018-2019 Patrik Fiedler, Tim Oesterreich
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_windows.h>

#include <vector>
#include <Windows.h>
#include <Wincrypt.h>

namespace Botan {

Certificate_Store_Windows::Certificate_Store_Windows()
{}

std::vector<X509_DN> Certificate_Store_Windows::all_subjects() const
{
    std::vector<X509_DN> subject_dns;
    std::vector<std::string> cert_store_names{"MY", "Root", "Trust", "CA"};
    for (auto &store_name : cert_store_names)
    {
        auto windows_cert_store = CertOpenSystemStore(0, store_name.c_str());
        if (!windows_cert_store) {
            throw Decoding_Error(
                "failed to open windows certificate store '" + store_name +
                "' to get all_subjects (Error Code: " +
                std::to_string(::GetLastError()) + ")");
        }
        PCCERT_CONTEXT cert_context = nullptr;
        while(cert_context = CertEnumCertificatesInStore(windows_cert_store, cert_context))
        {
            if (cert_context) {
                X509_Certificate cert(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
                subject_dns.push_back(cert.subject_dn());
            }
        }
    }

    return subject_dns;
}


PCCERT_CONTEXT lookup_cert_by_name(const std::string& cert_name, const std::string& cert_store_name, PCCERT_CONTEXT prevContext = nullptr)
{
    auto windows_cert_store = CertOpenSystemStore(0, cert_store_name.c_str());
    if (!windows_cert_store) {
        throw Decoding_Error(
            "failed to open windows certificate store '" + cert_store_name +
            "' to find_cert (Error Code: " +
            std::to_string(::GetLastError()) + ")");
    }

    PCCERT_CONTEXT cert_context = CertFindCertificateInStore(
                                      windows_cert_store, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                      CERT_UNICODE_IS_RDN_ATTRS_FLAG, CERT_FIND_SUBJECT_STR_A,
                                      cert_name.c_str(), prevContext);

    CertCloseStore(windows_cert_store, 0);

    return cert_context;
}

PCCERT_CONTEXT lookup_cert_by_hash_blob(const CRYPT_HASH_BLOB& hash_blob, const std::string& cert_store_name, PCCERT_CONTEXT prevContext = nullptr)
{
    auto windows_cert_store = CertOpenSystemStore(0, cert_store_name.c_str());
    if (!windows_cert_store) {
        throw Decoding_Error(
            "failed to open windows certificate store '" + cert_store_name +
            "' to find_cert (Error Code: " +
            std::to_string(::GetLastError()) + ")");
    }

    PCCERT_CONTEXT cert_context = CertFindCertificateInStore(
                                      windows_cert_store, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                                      0, CERT_FIND_KEY_IDENTIFIER,
                                      &hash_blob, prevContext);

    CertCloseStore(windows_cert_store, 0);

    return cert_context;
}

std::shared_ptr<const X509_Certificate>
Certificate_Store_Windows::find_cert(const Botan::X509_DN &          subject_dn,
                                     const std::vector<uint8_t> &key_id) const
{
    const auto certs = find_all_certs(subject_dn, key_id);
    return certs.empty() ? nullptr : certs.front();
}

bool already_contains_key_id(
    const std::vector<std::shared_ptr<const X509_Certificate>>& certs, const std::vector<uint8_t>& key_id)
{
    return std::any_of(certs.begin(), certs.end(),
    [&](std::shared_ptr<const X509_Certificate> c) {
        return c->subject_key_id() == key_id;
    });
}

std::vector<std::shared_ptr<const X509_Certificate>> Certificate_Store_Windows::find_all_certs(
            const X509_DN& subject_dn,
            const std::vector<uint8_t>& key_id) const
{
    auto common_name = subject_dn.get_attribute("CN");

    if (common_name.empty())
    {
        return {}; // certificate not found
    }

    if (common_name.size() != 1)
    {
        throw Lookup_Error("ambiguous certificate result");
    }

    const auto &cert_name = common_name[0];

    std::vector<std::shared_ptr<const X509_Certificate>> certs;
    std::vector<std::string> cert_store_names{"MY", "Root", "Trust", "CA"};
    for (auto &store_name : cert_store_names) {
        PCCERT_CONTEXT cert_context = nullptr;
        while (cert_context = lookup_cert_by_name(cert_name, store_name, cert_context)) {
            if (cert_context) {
                auto cert = std::make_shared<X509_Certificate>(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
                if (cert->subject_dn() == subject_dn &&
                        (key_id.empty() || (cert->subject_key_id() == key_id && !already_contains_key_id(certs, key_id))))
                {
                    certs.push_back(cert);
                }
            }
        }
    }

    return certs;
}

std::shared_ptr<const Botan::X509_Certificate>
Certificate_Store_Windows::find_cert_by_pubkey_sha1(
    const std::vector<uint8_t> &key_hash) const
{
    if(key_hash.size() != 20)
    {
        throw Invalid_Argument("Certificate_Store_Windows::find_cert_by_pubkey_sha1 invalid hash");
    }

    std::vector<std::string> cert_store_names{"MY", "Root", "Trust", "CA"};
    for (auto &store_name : cert_store_names) {
        auto windows_cert_store = CertOpenSystemStore(0, store_name.c_str());
        if (!windows_cert_store) {
            throw Decoding_Error(
                "failed to open windows certificate store 'CA' (Error Code: " + std::to_string(::GetLastError()) + ")");
        }

        CRYPT_HASH_BLOB blob;
        blob.cbData = static_cast<DWORD>(key_hash.size());
        blob.pbData = const_cast<BYTE*>(key_hash.data());

        auto cert_context = lookup_cert_by_hash_blob(blob, store_name);

        if (cert_context) {
            auto cert = std::make_shared<X509_Certificate>(cert_context->pbCertEncoded, cert_context->cbCertEncoded);
            CertFreeCertificateContext(cert_context);
            return cert;
        }
    }

    return nullptr;
}

std::shared_ptr<const X509_Certificate>
Certificate_Store_Windows::find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const
{
    BOTAN_UNUSED(subject_hash);
    throw Not_Implemented("Certificate_Store_Windows::find_cert_by_raw_subject_dn_sha256");
}

std::shared_ptr<const X509_CRL> Certificate_Store_Windows::find_crl_for(const X509_Certificate& subject) const
{
    BOTAN_UNUSED(subject);
    throw Not_Implemented("Certificate_Store_Windows::find_crl_for");
}
}
