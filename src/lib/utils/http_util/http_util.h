/*
* HTTP utilities
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_UTILS_HTTP_H_
#define BOTAN_UTILS_HTTP_H_

#include <botan/exceptn.h>
#include <botan/types.h>
#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Botan {

class URI;

namespace OS {
class Socket;
}

}  // namespace Botan

namespace Botan::HTTP {

/**
* HTTP_Error Exception
*/
class BOTAN_TEST_API HTTP_Error final : public Exception {
   public:
      explicit HTTP_Error(const std::string& msg) : Exception("HTTP error " + msg) {}

      ErrorType error_type() const noexcept override { return ErrorType::HttpError; }
};

/**
* Transparent case-insensitive comparator for HTTP field names.
* RFC 9110 5.1: "field names are case-insensitive".
*/
struct Case_Insensitive_Less final {
      using is_transparent = void;

      bool operator()(std::string_view a, std::string_view b) const {
         const auto ascii_lower = [](unsigned char c) -> unsigned char {
            return (c >= 'A' && c <= 'Z') ? static_cast<unsigned char>(c + 32) : c;
         };
         return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(), [&](char x, char y) {
            return ascii_lower(static_cast<unsigned char>(x)) < ascii_lower(static_cast<unsigned char>(y));
         });
      }
};

using Headers = std::map<std::string, std::string, Case_Insensitive_Less>;

class Response final {
   public:
      Response() : m_status_code(0), m_status_message("Uninitialized") {}

      Response(unsigned int status_code, std::string status_message, std::vector<uint8_t> body, Headers headers) :
            m_status_code(status_code),
            m_status_message(std::move(status_message)),
            m_body(std::move(body)),
            m_headers(std::move(headers)) {}

      unsigned int status_code() const { return m_status_code; }

      const std::vector<uint8_t>& body() const { return m_body; }

      const Headers& headers() const { return m_headers; }

      std::string status_message() const { return m_status_message; }

      void throw_unless_ok() const {
         if(status_code() != 200) {
            throw HTTP_Error(status_message());
         }
      }

   private:
      unsigned int m_status_code;
      std::string m_status_message;
      std::vector<uint8_t> m_body;
      Headers m_headers;
};

BOTAN_TEST_API std::ostream& operator<<(std::ostream& o, const Response& resp);

/**
* Per-request limits applied to an HTTP exchange.
*/
class RequestLimits final {
   public:
      RequestLimits() = default;

      size_t max_redirects() const { return m_max_redirects; }

      std::chrono::milliseconds timeout() const { return m_timeout; }

      std::optional<size_t> max_body_size() const { return m_max_body_size; }

      RequestLimits& set_max_redirects(size_t n) {
         m_max_redirects = n;
         return *this;
      }

      RequestLimits& set_timeout(std::chrono::milliseconds t) {
         m_timeout = t;
         return *this;
      }

      RequestLimits& set_max_body_size(size_t n) {
         m_max_body_size = n;
         return *this;
      }

   private:
      size_t m_max_redirects = 1;
      std::chrono::milliseconds m_timeout = std::chrono::milliseconds(3000);
      std::optional<size_t> m_max_body_size;
};

typedef std::function<Response(std::string_view, std::string_view, std::string_view, std::optional<size_t>)>
   http_exch_fn;

Response BOTAN_TEST_API http_sync(const http_exch_fn& fn,
                                  std::string_view verb,
                                  const URI& uri,
                                  std::string_view content_type,
                                  const std::vector<uint8_t>& body,
                                  const RequestLimits& limits);

Response http_sync(std::string_view verb,
                   const URI& uri,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   const RequestLimits& limits = {});

Response BOTAN_TEST_API GET_sync(const URI& uri, const RequestLimits& limits = {});

Response POST_sync(const URI& uri,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   const RequestLimits& limits = {});

std::string BOTAN_TEST_API url_encode(std::string_view url);

/**
* Read a complete HTTP/1.0 response from an already-connected socket and
* return the parsed Response. Enforces header- and body-size limits during
* the read. Exposed via BOTAN_TEST_API so the parser can be exercised
* against a fake socket; production code reaches it through http_transact.
*/
Response BOTAN_TEST_API read_response_from_socket(OS::Socket& socket,
                                                  std::chrono::milliseconds timeout,
                                                  std::optional<size_t> max_body_size);

}  // namespace Botan::HTTP

#endif
