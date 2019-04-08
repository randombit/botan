/*
* Certificate Store
* (C) 1999-2019 Jack Lloyd
* (C) 2019      René Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/build.h>

#include <algorithm>
#include <array>

#define __ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES 0
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

#include <botan/assert.h>
#include <botan/ber_dec.h>
#include <botan/certstor_macos.h>
#include <botan/data_src.h>
#include <botan/der_enc.h>
#include <botan/exceptn.h>
#include <botan/x509_dn.h>

namespace Botan {

namespace {

/**
 * Abstract RAII wrapper for CFTypeRef-style object handles
 * All of those xxxRef types are eventually typedefs to void*
 */
template<typename T>
class scoped_CFType
   {
   public:
      explicit scoped_CFType(T value)
         : m_value(value)
         {
         }

      scoped_CFType(const scoped_CFType<T>& rhs) = delete;
      scoped_CFType(scoped_CFType<T>&& rhs) :
         m_value(std::move(rhs.m_value))
         {
         rhs.m_value = nullptr;
         }

      ~scoped_CFType()
         {
         if(m_value)
            {
            CFRelease(m_value);
            }
         }

      operator bool() const { return m_value != nullptr; }

      void assign(T value)
         {
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
X509_DN normalize(const X509_DN& dn)
   {
   X509_DN result;

   for(const auto& rdn : dn.dn_info())
      {
      // TODO: C++14 - use std::get<ASN1_String>(), resp. std::get<OID>()
      const auto oid = rdn.first;
      auto str = rdn.second;

      if(str.tagging() == ASN1_Tag::PRINTABLE_STRING)
         {
         std::string normalized;
         normalized.reserve(str.value().size());
         for(const char c : str.value())
            {
            if(c != ' ')
               {
               // store all 'normal' characters as upper case
               normalized.push_back(::toupper(c));
               }
            else if(!normalized.empty() && normalized.back() != ' ')
               {
               // remove leading and squash multiple white spaces
               normalized.push_back(c);
               }
            }

         if(normalized.back() == ' ')
            {
            // remove potential remaining single trailing white space char
            normalized.erase(normalized.end() - 1);
            }

         str = ASN1_String(normalized, str.tagging());
         }

      result.add_attribute(oid, str);
      }

   return result;
   }

std::string to_string(const CFStringRef cfstring)
   {
   const char* ccstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

   if(ccstr != nullptr)
      {
      return std::string(ccstr);
      }

   auto utf16_pairs    = CFStringGetLength(cfstring);
   auto max_utf8_bytes = CFStringGetMaximumSizeForEncoding(utf16_pairs, kCFStringEncodingUTF8);

   std::vector<char> cstr(max_utf8_bytes, '\0');
   auto result = CFStringGetCString(cfstring,
                                    cstr.data(), cstr.size(),
                                    kCFStringEncodingUTF8);

   return (result) ? std::string(cstr.data()) : std::string();
   }

std::string to_string(const OSStatus status)
   {
   scoped_CFType<CFStringRef> eCFString(
      SecCopyErrorMessageString(status, nullptr));
   return to_string(eCFString.get());
   }

void check_success(const OSStatus status, const std::string context)
   {
   if(errSecSuccess == status)
      {
      return;
      }

   throw Internal_Error(
      std::string("failed to " + context + ": " + to_string(status)));
   }

template <typename T>
void check_notnull(const scoped_CFType<T>& value, const std::string context)
   {
   if(value)
      {
      return;
      }

   throw Internal_Error(std::string("failed to ") + context);
   }

SecCertificateRef to_SecCertificateRef(CFTypeRef object)
   {
   if(!object || CFGetTypeID(object) != SecCertificateGetTypeID())
      {
      throw Internal_Error("cannot convert CFTypeRef to SecCertificateRef");
      }

   return static_cast<SecCertificateRef>(const_cast<void*>(object));
   }

/**
 * Create a CFDataRef view over some provided std::vector<uint8_t. The data is
 * not copied but the resulting CFDataRef uses the std::vector's buffer as data
 * store. Note that the CFDataRef still needs to be manually freed, hence the
 * scoped_CFType wrapper.
 */
scoped_CFType<CFDataRef> createCFDataView(const std::vector<uint8_t>& data)
   {
   return scoped_CFType<CFDataRef>(
             CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
                                         data.data(),
                                         data.size(),
                                         kCFAllocatorNull));
   }

/**
 * Convert a SecCertificateRef object into a Botan::X509_Certificate
 */
std::shared_ptr<const X509_Certificate> readCertificate(SecCertificateRef cert)
   {
   scoped_CFType<CFDataRef> derData(SecCertificateCopyData(cert));
   check_notnull(derData, "read extracted certificate");

   // TODO: factor this out into a createDataSourceView() as soon as this class
   //       gets a move-constructor
   const auto data   = CFDataGetBytePtr(derData.get());
   const auto length = CFDataGetLength(derData.get());

   DataSource_Memory ds(data, length);
   return std::make_shared<Botan::X509_Certificate>(ds);
   }

}

/**
 * Internal class implementation (i.e. Pimpl) to keep the required platform-
 * dependent members of Certificate_Store_MacOS contained in this compilation
 * unit.
 */
class Certificate_Store_MacOS_Impl
   {
   private:
      static constexpr const char* system_roots =
         "/System/Library/Keychains/SystemRootCertificates.keychain";
      static constexpr const char* system_keychain =
         "/Library/Keychains/System.keychain";

   public:
      using Query = std::vector<std::pair<CFStringRef, CFTypeRef>>;

   public:
      Certificate_Store_MacOS_Impl() :
         m_policy(SecPolicyCreateBasicX509()),
         m_system_roots(nullptr),
         m_system_chain(nullptr),
         m_keychains(nullptr)
         {
         check_success(SecKeychainOpen(system_roots, &m_system_roots.get()),
                       "open system root certificates");
         check_success(SecKeychainOpen(system_keychain, &m_system_chain.get()),
                       "open system keychain");
         check_notnull(m_system_roots, "open system root certificate chain");
         check_notnull(m_system_chain, "open system certificate chain");

         // m_keychains is merely a convenience list view into all open keychain
         // objects. This list is required in prepareQuery().
         std::array<const void*, 2> keychains{{
               m_system_roots.get(),
               m_system_chain.get()
               }};

         m_keychains.assign(
            CFArrayCreate(kCFAllocatorDefault,
                          keychains.data(),
                          keychains.size(),
                          &kCFTypeArrayCallBacks));
         check_notnull(m_keychains, "initialize keychain array");
         }

      CFArrayRef keychains() const { return m_keychains.get(); }
      SecPolicyRef policy() const { return m_policy.get(); }

      /**
       * Searches certificates in all opened system keychains. Takes an optional
       * \p query that defines filter attributes to be searched for. That query
       * is amended by generic attributes for "certificate filtering".
       *
       * \param query  a list of key-value pairs used for filtering
       * \returns      an array with the resulting certificates or nullptr if
       *               no matching certificate was found
       */
      scoped_CFType<CFArrayRef> search(Query query = Query()) const
         {
         scoped_CFType<CFDictionaryRef> fullQuery(
            prepareQuery(std::move(query)));
         check_notnull(fullQuery, "create search query");

         scoped_CFType<CFArrayRef> result(nullptr);
         auto status = SecItemCopyMatching(fullQuery.get(),
                                           (CFTypeRef*)&result.get());
         if(errSecItemNotFound == status)
            {
            return scoped_CFType<CFArrayRef>(nullptr);  // no matches
            }

         check_success(status, "look up certificate");
         check_notnull(result, "look up certificate (invalid result value)");

         return result;
         }

   protected:
      /**
       * Amends the user-provided search query with generic filter rules for
       * the associated system keychains.
       */
      scoped_CFType<CFDictionaryRef> prepareQuery(Query pairs) const
         {
         std::vector<CFStringRef> keys({kSecClass,
                                        kSecReturnRef,
                                        kSecMatchLimit,
                                        kSecMatchTrustedOnly,
                                        kSecMatchSearchList,
                                        kSecMatchPolicy});
         std::vector<CFTypeRef>   values({kSecClassCertificate,
                                          kCFBooleanTrue,
                                          kSecMatchLimitAll,
                                          kCFBooleanTrue,
                                          keychains(),
                                          policy()});
         keys.reserve(pairs.size() + keys.size());
         values.reserve(pairs.size() + values.size());

         for(const auto& pair : pairs)
            {
            keys.push_back(pair.first);
            values.push_back(pair.second);
            }

         BOTAN_ASSERT_EQUAL(keys.size(), values.size(), "valid key-value pairs");

         return scoped_CFType<CFDictionaryRef>(CFDictionaryCreate(
               kCFAllocatorDefault, (const void**)keys.data(),
               (const void**)values.data(), keys.size(),
               &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
         }

   private:
      scoped_CFType<SecPolicyRef>    m_policy;
      scoped_CFType<SecKeychainRef>  m_system_roots;
      scoped_CFType<SecKeychainRef>  m_system_chain;
      scoped_CFType<CFArrayRef>      m_keychains;
   };


Certificate_Store_MacOS::Certificate_Store_MacOS() :
   m_impl(std::make_shared<Certificate_Store_MacOS_Impl>())
   {
   }

std::vector<X509_DN> Certificate_Store_MacOS::all_subjects() const
   {
   scoped_CFType<CFArrayRef> result(m_impl->search());

   if(!result)
      {
      return {};  // not a single certificate found in the keychain
      }

   const auto count = CFArrayGetCount(result.get());
   BOTAN_ASSERT(count > 0, "subject result list contains data");

   std::vector<X509_DN> output;
   output.reserve(count);
   for(unsigned int i = 0; i < count; ++i)
      {
      // Note: Apple's API provides SecCertificateCopyNormalizedSubjectSequence
      //       which would have saved us from reading a Botan::X509_Certificate,
      //       however, this function applies the same DN "normalization" as
      //       stated above.
      auto cfCert = to_SecCertificateRef(CFArrayGetValueAtIndex(result.get(), i));
      auto cert = readCertificate(cfCert);
      output.emplace_back(cert->subject_dn());
      }

   return output;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_MacOS::find_cert(const X509_DN& subject_dn,
                                   const std::vector<uint8_t>& key_id) const
   {
   const auto certs = find_all_certs(subject_dn, key_id);

   if(certs.empty())
      {
      return nullptr;  // certificate not found
      }

   if(certs.size() != 1)
      {
      throw Lookup_Error("ambiguous certificate result");
      }

   return certs.front();
   }

std::vector<std::shared_ptr<const X509_Certificate>> Certificate_Store_MacOS::find_all_certs(
         const X509_DN& subject_dn,
         const std::vector<uint8_t>& key_id) const
   {
   std::vector<uint8_t> dn_data;
   DER_Encoder encoder(dn_data);
   normalize(subject_dn).encode_into(encoder);

   scoped_CFType<CFDataRef> dn_cfdata(createCFDataView(dn_data));
   check_notnull(dn_cfdata, "create DN search object");

   Certificate_Store_MacOS_Impl::Query query_params(
      {
         {kSecAttrSubject, dn_cfdata.get()}
      });

   scoped_CFType<CFDataRef> keyid_cfdata(createCFDataView(key_id));
   check_notnull(keyid_cfdata, "create key ID search object");
   if(!key_id.empty())
      {
      query_params.push_back({kSecAttrSubjectKeyID, keyid_cfdata.get()});
      }

   scoped_CFType<CFArrayRef> result(m_impl->search(std::move(query_params)));

   if(!result)
      {
      return {};  // no certificates found
      }

   const auto count = CFArrayGetCount(result.get());
   BOTAN_ASSERT(count > 0, "certificate result list contains data");

   std::vector<std::shared_ptr<const X509_Certificate>> output;
   output.reserve(count);
   for(unsigned int i = 0; i < count; ++i)
      {
      auto cfCert = to_SecCertificateRef(CFArrayGetValueAtIndex(result.get(), i));
      output.emplace_back(readCertificate(cfCert));
      }

   return output;
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_MacOS::find_cert_by_pubkey_sha1(const std::vector<uint8_t>& key_hash) const
   {
   if(key_hash.size() != 20)
      {
      throw Invalid_Argument("Certificate_Store_MacOS::find_cert_by_pubkey_sha1 invalid hash");
      }

   scoped_CFType<CFDataRef> key_hash_cfdata(createCFDataView(key_hash));
   check_notnull(key_hash_cfdata, "create key hash search object");

   scoped_CFType<CFArrayRef> result(m_impl->search(
      {
         {kSecAttrPublicKeyHash, key_hash_cfdata.get()},
      }));

   if(!result)
      {
      return nullptr;  // no certificate found
      }

   const auto count = CFArrayGetCount(result.get());
   BOTAN_ASSERT(count > 0, "certificate result list contains an object");

   // `count` might be greater than 1, but we'll just select the first match
   auto cfCert = to_SecCertificateRef(CFArrayGetValueAtIndex(result.get(), 0));
   return readCertificate(cfCert);
   }

std::shared_ptr<const X509_Certificate>
Certificate_Store_MacOS::find_cert_by_raw_subject_dn_sha256(const std::vector<uint8_t>& subject_hash) const
   {
   BOTAN_UNUSED(subject_hash);
   throw Not_Implemented("Certificate_Store_MacOS::find_cert_by_raw_subject_dn_sha256");
   }

std::shared_ptr<const X509_CRL> Certificate_Store_MacOS::find_crl_for(const X509_Certificate& subject) const
   {
   BOTAN_UNUSED(subject);
   return {};
   }

}
