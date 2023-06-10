/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2019-2020 René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/certstor_macos.h>

#include <botan/ber_dec.h>
#include <botan/data_src.h>
#include <botan/exceptn.h>
#include <botan/pkix_types.h>

#include <algorithm>
#include <array>

#define __ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES 0
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

namespace Botan {

namespace {

/**
 * Abstract RAII wrapper for CFTypeRef-style object handles
 * All of those xxxRef types are eventually typedefs to void*
 */
template <typename T>
class scoped_CFType {
   public:
      explicit scoped_CFType(T value) : m_value(value) {}

      scoped_CFType(const scoped_CFType<T>& rhs) = delete;

      scoped_CFType(scoped_CFType<T>&& rhs) : m_value(std::move(rhs.m_value)) { rhs.m_value = nullptr; }

      ~scoped_CFType() {
         if(m_value) {
            CFRelease(m_value);
         }
      }

      operator bool() const { return m_value != nullptr; }

      void assign(T value) {
         BOTAN_ASSERT(m_value == nullptr, "scoped_CFType was not set yet");
         m_value = value;
      }

      T& get() { return m_value; }

      const T& get() const { return m_value; }

   private:
      T m_value;
};

/**
 * Apple's DN parser "normalizes" ASN1 'PrintableString' into upper-case values
 * and strips leading, trailing as well as multiple white spaces.
 * See: opensource.apple.com/source/Security/Security-55471/sec/Security/SecCertificate.c.auto.html
 */
X509_DN normalize(const X509_DN& dn) {
   X509_DN result;

   for(const auto& rdn : dn.dn_info()) {
      // TODO: C++14 - use std::get<ASN1_String>(), resp. std::get<OID>()
      const auto oid = rdn.first;
      auto str = rdn.second;

      if(str.tagging() == ASN1_Type::PrintableString) {
         std::string normalized;
         normalized.reserve(str.value().size());
         for(const char c : str.value()) {
            if(c != ' ') {
               // store all 'normal' characters as upper case
               normalized.push_back(::toupper(c));
            } else if(!normalized.empty() && normalized.back() != ' ') {
               // remove leading and squash multiple white spaces
               normalized.push_back(c);
            }
         }

         if(normalized.back() == ' ') {
            // remove potential remaining single trailing white space char
            normalized.erase(normalized.end() - 1);
         }

         str = ASN1_String(normalized, str.tagging());
      }

      result.add_attribute(oid, str);
   }

   return result;
}

std::vector<uint8_t> normalizeAndSerialize(const X509_DN& dn) {
   return normalize(dn).DER_encode();
}

std::string to_string(const CFStringRef cfstring) {
   const char* ccstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

   if(ccstr != nullptr) {
      return std::string(ccstr);
   }

   auto utf16_pairs = CFStringGetLength(cfstring);
   auto max_utf8_bytes = CFStringGetMaximumSizeForEncoding(utf16_pairs, kCFStringEncodingUTF8);

   std::vector<char> cstr(max_utf8_bytes, '\0');
   auto result = CFStringGetCString(cfstring, cstr.data(), cstr.size(), kCFStringEncodingUTF8);

   return (result) ? std::string(cstr.data()) : std::string();
}

std::string to_string(const OSStatus status) {
   scoped_CFType<CFStringRef> eCFString(SecCopyErrorMessageString(status, nullptr));
   return to_string(eCFString.get());
}

void check_success(const OSStatus status, const std::string context) {
   if(errSecSuccess == status) {
      return;
   }

   throw Internal_Error(std::string("failed to " + context + ": " + to_string(status)));
}

template <typename T>
void check_notnull(const T& value, const std::string context) {
   if(value) {
      return;
   }

   throw Internal_Error(std::string("failed to ") + context);
}

}  // namespace

/**
 * Internal class implementation (i.e. Pimpl) to keep the required platform-
 * dependent members of Certificate_Store_MacOS contained in this compilation
 * unit.
 */
class Certificate_Store_MacOS_Impl {
   private:
      static constexpr const char* system_roots = "/System/Library/Keychains/SystemRootCertificates.keychain";
      static constexpr const char* system_keychain = "/Library/Keychains/System.keychain";

   public:
      /**
       * Wraps a list of search query parameters that are later passed into
       * Apple's certifificate store API. The class provides some convenience
       * functionality and handles the query paramenter's data lifetime.
       */
      class Query {
         public:
            Query() = default;
            ~Query() = default;
            Query(Query&& other) = default;
            Query& operator=(Query&& other) = default;

            Query(const Query& other) = delete;
            Query& operator=(const Query& other) = delete;

         public:
            void addParameter(CFStringRef key, CFTypeRef value) {
               m_keys.emplace_back(key);
               m_values.emplace_back(value);
            }

            void addParameter(CFStringRef key, std::vector<uint8_t> value) {
               const auto& data = m_data_store.emplace_back(std::move(value));

               const auto& data_ref = m_data_refs.emplace_back(
                  CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, data.data(), data.size(), kCFAllocatorNull));
               check_notnull(data_ref, "create CFDataRef of search object failed");

               addParameter(key, data_ref.get());
            }

            /**
             * Amends the user-provided search query with generic filter rules
             * for the associated system keychains and transforms it into a
             * representation that can be passed to the Apple keychain API.
             */
            scoped_CFType<CFDictionaryRef> prepare(const CFArrayRef& keychains, const SecPolicyRef& policy) {
               addParameter(kSecClass, kSecClassCertificate);
               addParameter(kSecReturnRef, kCFBooleanTrue);
               addParameter(kSecMatchLimit, kSecMatchLimitAll);
               addParameter(kSecMatchTrustedOnly, kCFBooleanTrue);
               addParameter(kSecMatchSearchList, keychains);
               addParameter(kSecMatchPolicy, policy);

               BOTAN_ASSERT_EQUAL(m_keys.size(), m_values.size(), "valid key-value pairs");

               auto query = scoped_CFType<CFDictionaryRef>(CFDictionaryCreate(kCFAllocatorDefault,
                                                                              (const void**)m_keys.data(),
                                                                              (const void**)m_values.data(),
                                                                              m_keys.size(),
                                                                              &kCFTypeDictionaryKeyCallBacks,
                                                                              &kCFTypeDictionaryValueCallBacks));
               check_notnull(query, "create search query");

               return query;
            }

         private:
            using Data = std::vector<std::vector<uint8_t>>;
            using DataRefs = std::vector<scoped_CFType<CFDataRef>>;
            using Keys = std::vector<CFStringRef>;
            using Values = std::vector<CFTypeRef>;

            Data m_data_store;     //! makes sure that data parameters are kept alive
            DataRefs m_data_refs;  //! keeps track of CFDataRef objects refering into \p m_data_store
            Keys m_keys;           //! ordered list of search parameter keys
            Values m_values;       //! ordered list of search parameter values
      };

   public:
      Certificate_Store_MacOS_Impl() :
            m_policy(SecPolicyCreateBasicX509()),
            m_system_roots(nullptr),
            m_system_chain(nullptr),
            m_keychains(nullptr) {
         BOTAN_DIAGNOSTIC_PUSH
         BOTAN_DIAGNOSTIC_IGNORE_DEPRECATED_DECLARATIONS
         // macOS 12.0 deprecates 'Custom keychain management', though the API still works.
         // Ideas for a replacement can be found in the discussion of GH #3122:
         //   https://github.com/randombit/botan/pull/3122
         check_success(SecKeychainOpen(system_roots, &m_system_roots.get()), "open system root certificates");
         check_success(SecKeychainOpen(system_keychain, &m_system_chain.get()), "open system keychain");
         BOTAN_DIAGNOSTIC_POP
         check_notnull(m_system_roots, "open system root certificate chain");
         check_notnull(m_system_chain, "open system certificate chain");

         // m_keychains is merely a convenience list view into all open keychain
         // objects. This list is required in prepareQuery().
         std::array<const void*, 2> keychains{{m_system_roots.get(), m_system_chain.get()}};

         m_keychains.assign(
            CFArrayCreate(kCFAllocatorDefault, keychains.data(), keychains.size(), &kCFTypeArrayCallBacks));
         check_notnull(m_keychains, "initialize keychain array");
      }

      std::optional<X509_Certificate> findOne(Query query) const {
         query.addParameter(kSecMatchLimit, kSecMatchLimitOne);

         scoped_CFType<CFTypeRef> result(nullptr);
         search(std::move(query), &result.get());

         if(result)
            return readCertificate(result.get());
         else
            return std::nullopt;
      }

      std::vector<X509_Certificate> findAll(Query query) const {
         query.addParameter(kSecMatchLimit, kSecMatchLimitAll);

         scoped_CFType<CFArrayRef> result(nullptr);
         search(std::move(query), (CFTypeRef*)&result.get());

         std::vector<X509_Certificate> output;

         if(result) {
            const auto count = CFArrayGetCount(result.get());
            BOTAN_ASSERT(count > 0, "certificate result list contains data");

            for(unsigned int i = 0; i < count; ++i) {
               auto cert = CFArrayGetValueAtIndex(result.get(), i);
               output.emplace_back(readCertificate(cert));
            }
         }

         return output;
      }

   protected:
      void search(Query query, CFTypeRef* result) const {
         scoped_CFType<CFDictionaryRef> fullQuery(query.prepare(keychains(), policy()));

         auto status = SecItemCopyMatching(fullQuery.get(), result);

         if(errSecItemNotFound == status) {
            return;  // no matches
         }

         check_success(status, "look up certificate");
         check_notnull(result, "look up certificate (invalid result value)");
      }

      /**
       * Convert a CFTypeRef object into a X509_Certificate
       */
      X509_Certificate readCertificate(CFTypeRef object) const {
         if(!object || CFGetTypeID(object) != SecCertificateGetTypeID()) {
            throw Internal_Error("cannot convert CFTypeRef to SecCertificateRef");
         }

         auto cert = static_cast<SecCertificateRef>(const_cast<void*>(object));

         scoped_CFType<CFDataRef> derData(SecCertificateCopyData(cert));
         check_notnull(derData, "read extracted certificate");

         const auto data = CFDataGetBytePtr(derData.get());
         const auto length = CFDataGetLength(derData.get());

         DataSource_Memory ds(data, length);
         return X509_Certificate(ds);
      }

      CFArrayRef keychains() const { return m_keychains.get(); }

      SecPolicyRef policy() const { return m_policy.get(); }

   private:
      scoped_CFType<SecPolicyRef> m_policy;
      scoped_CFType<SecKeychainRef> m_system_roots;
      scoped_CFType<SecKeychainRef> m_system_chain;
      scoped_CFType<CFArrayRef> m_keychains;
};

//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
//   Implementation of Certificate_Store interface ...
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//

Certificate_Store_MacOS::Certificate_Store_MacOS() : m_impl(std::make_shared<Certificate_Store_MacOS_Impl>()) {}

std::vector<X509_DN> Certificate_Store_MacOS::all_subjects() const {
   // Note: This fetches and parses all certificates in the trust store.
   //       Apple's API provides SecCertificateCopyNormalizedSubjectSequence
   //       which facilitates reading the certificate DN without parsing the
   //       entire certificate via X509_Certificate. However, this
   //       function applies the same DN "normalization" as stated above.
   const auto certificates = m_impl->findAll({});

   std::vector<X509_DN> output;
   std::transform(certificates.cbegin(),
                  certificates.cend(),
                  std::back_inserter(output),
                  [](const std::optional<X509_Certificate> cert) { return cert->subject_dn(); });

   return output;
}

std::optional<X509_Certificate> Certificate_Store_MacOS::find_cert(const X509_DN& subject_dn,
                                                                   const std::vector<uint8_t>& key_id) const {
   Certificate_Store_MacOS_Impl::Query query;
   query.addParameter(kSecAttrSubject, normalizeAndSerialize(subject_dn));

   if(!key_id.empty()) {
      query.addParameter(kSecAttrSubjectKeyID, key_id);
   }

   return m_impl->findOne(std::move(query));
}

std::vector<X509_Certificate> Certificate_Store_MacOS::find_all_certs(const X509_DN& subject_dn,
                                                                      const std::vector<uint8_t>& key_id) const {
   Certificate_Store_MacOS_Impl::Query query;
   query.addParameter(kSecAttrSubject, normalizeAndSerialize(subject_dn));

   if(!key_id.empty()) {
      query.addParameter(kSecAttrSubjectKeyID, key_id);
   }

   return m_impl->findAll(std::move(query));
}

std::optional<X509_Certificate> Certificate_Store_MacOS::find_cert_by_pubkey_sha1(
   const std::vector<uint8_t>& key_hash) const {
   if(key_hash.size() != 20) {
      throw Invalid_Argument("Certificate_Store_MacOS::find_cert_by_pubkey_sha1 invalid hash");
   }

   Certificate_Store_MacOS_Impl::Query query;
   query.addParameter(kSecAttrPublicKeyHash, key_hash);

   return m_impl->findOne(std::move(query));
}

std::optional<X509_Certificate> Certificate_Store_MacOS::find_cert_by_raw_subject_dn_sha256(
   const std::vector<uint8_t>& subject_hash) const {
   BOTAN_UNUSED(subject_hash);
   throw Not_Implemented("Certificate_Store_MacOS::find_cert_by_raw_subject_dn_sha256");
}

std::optional<X509_CRL> Certificate_Store_MacOS::find_crl_for(const X509_Certificate& subject) const {
   BOTAN_UNUSED(subject);
   return {};
}

}  // namespace Botan
