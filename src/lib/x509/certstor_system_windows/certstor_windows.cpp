/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2018-2019 Patrik Fiedler, Tim Oesterreich
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_windows.h>

#include <Windows.h>
#include <Wincrypt.h>

namespace Botan {

Certificate_Store_Windows::Certificate_Store_Windows()
{}

std::vector<X509_DN> Certificate_Store_Windows::all_subjects() const
   {
   return {};
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_Windows::find_cert(const Botan::X509_DN &          subject_dn,
                                     const std::vector<uint8_t> &key_id) const
{
    auto commonName = subject_dn.get_attribute("CN");

    if (commonName.empty())
        {
        return nullptr; // certificate not found
        }

    if (commonName.size() != 1)
        {
        throw Lookup_Error("ambiguous certificate result");
        }

    const auto &certName = commonName[0];

    std::vector<std::string> certStoreNames{"MY", "Root", "Trust", "CA"};
    for (auto &storeName : certStoreNames) {
        auto windowsCertStore = CertOpenSystemStore(0, storeName.c_str());
        if (!windowsCertStore) {
            throw Decoding_Error(
                "failed to open windows certificate store '" + storeName +
                "' to find_cert (Error Code: " +
                std::to_string(::GetLastError()) + ")");
        }

        PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
            windowsCertStore, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
            CERT_UNICODE_IS_RDN_ATTRS_FLAG, CERT_FIND_SUBJECT_STR_A,
            certName.c_str(), nullptr);

        CertCloseStore(windowsCertStore, 0);

        if (pCertContext) {
            X509_Certificate cert(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded);
            CertFreeCertificateContext(pCertContext);

            if (cert.subject_dn() == subject_dn) {
                return std::shared_ptr<X509_Certificate>(&cert);
            }
        }
    }

    return nullptr;
}

std::vector<std::shared_ptr<const X509_Certificate>> Certificate_Store_Windows::find_all_certs(
         const X509_DN& subject_dn,
         const std::vector<uint8_t>& key_id) const
{
    BOTAN_UNUSED(subject_dn);
    BOTAN_UNUSED(key_id);
    return {};
}
std::shared_ptr<const Botan::X509_Certificate>
Certificate_Store_Windows::find_cert_by_pubkey_sha1(
    const std::vector<uint8_t> &key_hash) const
{
    if(key_hash.size() != 20)
      {
      throw Invalid_Argument("Flatfile_Certificate_Store::find_cert_by_pubkey_sha1 invalid hash");
      }

    // auto internalCerts = _certs.get();
    // auto lookUp        = std::find_if(
    //     internalCerts.begin(), internalCerts.end(),
    //     [&](decltype(internalCerts)::value_type value) {
    //         auto str = value->fingerprint();
    //         str.erase(std::remove(str.begin(), str.end(), ':'), str.end());
    //         return convertTo<ByteBuffer>(str) == key_hash;
    //     });
    // if (*lookUp != nullptr) {
    //     return *lookUp;
    // }

    auto windowsCertStore = CertOpenSystemStore(0, TEXT("CA"));
    if (!windowsCertStore) {
        throw Decoding_Error(
                "failed to open windows certificate store 'CA' (Error Code: " + std::to_string(::GetLastError()) + ")");
    }

    const CRYPT_HASH_BLOB blob {key_hash.size(), const_cast<BYTE*>(key_hash.data())};
    // dvault::Hash    hash = dvault::Hash::fromHex(
    //     HashAlgorithm::SHA1, reinterpret_cast<const char *>(key_hash.data()));

    // blob.pbData      = reinterpret_cast<BYTE*>(hash_data);
    // blob.cbData      = key_hash.size();
    auto certContext = CertFindCertificateInStore(
        windowsCertStore, (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING), 0,
        CERT_FIND_SHA1_HASH, &blob, nullptr);

    CertCloseStore(windowsCertStore, 0);

    if (certContext) {
        X509_Certificate cert(certContext->pbCertEncoded, certContext->cbCertEncoded);
        CertFreeCertificateContext(certContext);
        return std::shared_ptr<X509_Certificate>(&cert);
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
   return {};
   }
}
