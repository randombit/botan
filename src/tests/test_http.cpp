/*
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_HTTP_UTIL)
   #include <botan/uri.h>
   #include <botan/internal/http_util.h>
   #include <botan/internal/socket.h>
   #include <cstring>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_HTTP_UTIL)

namespace {

std::string body_as_string(const Botan::HTTP::Response& r) {
   return std::string(r.body().begin(), r.body().end());
}

/*
* Simple canned-response mock for the http_exch_fn test seam. Captures every
* request and returns the next queued Response in order.
*/
class MockServer final {
   public:
      explicit MockServer(std::vector<Botan::HTTP::Response> responses) : m_responses(std::move(responses)) {}

      Botan::HTTP::Response handle(std::string_view hostname,
                                   std::string_view service,
                                   std::string_view message,
                                   std::optional<size_t> max_body_size) {
         m_hostnames.emplace_back(hostname);
         m_services.emplace_back(service);
         m_messages.emplace_back(message);
         m_max_body_sizes.push_back(max_body_size);
         if(m_call_count >= m_responses.size()) {
            throw Botan::HTTP::HTTP_Error("MockServer: no canned response for call");
         }
         return m_responses[m_call_count++];
      }

      Botan::HTTP::http_exch_fn as_exch_fn() {
         return [this](std::string_view h, std::string_view s, std::string_view m, std::optional<size_t> mbs) {
            return handle(h, s, m, mbs);
         };
      }

      size_t calls() const { return m_call_count; }

      const std::string& request(size_t i) const { return m_messages.at(i); }

      const std::string& hostname(size_t i) const { return m_hostnames.at(i); }

      const std::string& service(size_t i) const { return m_services.at(i); }

      std::optional<size_t> max_body_size(size_t i) const { return m_max_body_sizes.at(i); }

   private:
      std::vector<Botan::HTTP::Response> m_responses;
      std::vector<std::string> m_hostnames;
      std::vector<std::string> m_services;
      std::vector<std::string> m_messages;
      std::vector<std::optional<size_t>> m_max_body_sizes;
      size_t m_call_count = 0;
};

/*
* A read-only fake Socket that yields canned bytes in fixed-size chunks.
* The chunk size lets tests exercise both "everything in one read" and
* "response arrives split across reads".
*/
class MockSocket final : public Botan::OS::Socket {
   public:
      MockSocket(std::string bytes, size_t chunk_size) : m_bytes(std::move(bytes)), m_chunk(chunk_size) {}

      void write(std::span<const uint8_t> /*buf*/) override {
         // Parse tests don't care about the request side.
      }

      size_t read(uint8_t* buf, size_t len) override {
         const size_t take = std::min({len, m_chunk, m_bytes.size() - m_pos});
         std::memcpy(buf, m_bytes.data() + m_pos, take);
         m_pos += take;
         return take;
      }

   private:
      std::string m_bytes;
      size_t m_chunk;
      size_t m_pos = 0;
};

// Default timeout for socket-backed parse tests. Reads return immediately,
// so this is just a generous bound to keep the deadline check happy.
inline std::chrono::milliseconds parse_test_timeout() {
   return std::chrono::seconds(30);
}

Botan::HTTP::Response parse_via_socket(std::string raw,
                                       std::optional<size_t> max_body_size = std::nullopt,
                                       size_t chunk_size = 64 * 1024) {
   MockSocket socket(std::move(raw), chunk_size);
   return Botan::HTTP::read_response_from_socket(socket, parse_test_timeout(), max_body_size);
}

Botan::HTTP::Response make_response(unsigned int status,
                                    std::string_view message = "OK",
                                    std::map<std::string, std::string> headers = {},
                                    std::string_view body = "") {
   Botan::HTTP::Headers h;
   for(auto& [k, v] : headers) {
      h.emplace(k, v);
   }
   std::vector<uint8_t> body_bytes(body.begin(), body.end());
   return Botan::HTTP::Response(status, std::string(message), std::move(body_bytes), std::move(h));
}

class HTTP_Parse_Tests final : public Test {
   private:
      static Test::Result test_minimal_response() {
         Test::Result result("HTTP response parser minimal");

         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 5\r\n"
            "\r\n"
            "hello";

         const auto resp = parse_via_socket(raw);
         result.test_u32_eq("status code", resp.status_code(), 200);
         result.test_str_eq("status message", resp.status_message(), "OK");
         result.test_str_eq("body", body_as_string(resp), "hello");
         result.test_is_true("Content-Length header", resp.headers().contains("Content-Length"));
         return result;
      }

      static Test::Result test_zero_header_response() {
         Test::Result result("HTTP response parser zero headers");

         const std::string raw = "HTTP/1.0 200 OK\r\n\r\n";

         const auto resp = parse_via_socket(raw);
         result.test_u32_eq("status code", resp.status_code(), 200);
         result.test_str_eq("status message", resp.status_message(), "OK");
         result.test_sz_eq("no headers", resp.headers().size(), 0);
         result.test_sz_eq("empty body", resp.body().size(), 0);
         return result;
      }

      static Test::Result test_non_200_status() {
         Test::Result result("HTTP response parser non-200 status");

         const std::string raw =
            "HTTP/1.0 404 Not Found\r\n"
            "Content-Length: 0\r\n"
            "\r\n";

         const auto resp = parse_via_socket(raw);
         result.test_u32_eq("status code", resp.status_code(), 404);
         result.test_str_eq("status message", resp.status_message(), "Not Found");
         result.test_sz_eq("body empty", resp.body().size(), 0);
         return result;
      }

      static Test::Result test_no_content_length_eof_terminated() {
         Test::Result result("HTTP response parser no Content-Length");

         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "body without explicit length";

         const auto resp = parse_via_socket(raw);
         result.test_u32_eq("status code", resp.status_code(), 200);
         result.test_str_eq("body", body_as_string(resp), "body without explicit length");
         return result;
      }

      static Test::Result test_case_insensitive_content_length() {
         Test::Result result("HTTP response parser case-insensitive Content-Length");

         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "content-length: 3\r\n"
            "\r\n"
            "abc";

         const auto resp = parse_via_socket(raw);
         result.test_sz_eq("body size matches", resp.body().size(), 3);
         result.test_is_true("lookup by canonical case", resp.headers().contains("Content-Length"));
         return result;
      }

      static Test::Result test_no_header_terminator() {
         Test::Result result("HTTP response parser missing terminator");
         const std::string raw = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("no header terminator", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_status_line_malformed() {
         Test::Result result("HTTP response parser malformed status");
         const std::string raw = "NotHTTP/1.0 200 OK\r\n\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("non-HTTP status line", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_status_code_out_of_range() {
         Test::Result result("HTTP response parser status code range");
         result.test_throws<Botan::HTTP::HTTP_Error>("code > 599",
                                                     [&] { (void)parse_via_socket("HTTP/1.0 9999999 X\r\n\r\n"); });
         result.test_throws<Botan::HTTP::HTTP_Error>("code < 100",
                                                     [&] { (void)parse_via_socket("HTTP/1.0 42 X\r\n\r\n"); });
         return result;
      }

      static Test::Result test_content_length_not_digits() {
         Test::Result result("HTTP response parser Content-Length must be digits");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: abc\r\n"
            "\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("non-digit Content-Length", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_transfer_encoding_rejected() {
         Test::Result result("HTTP response parser rejects Transfer-Encoding");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("Transfer-Encoding present", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_transfer_encoding_case_insensitive() {
         Test::Result result("HTTP response parser Transfer-Encoding case-insensitive");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "transfer-encoding: gzip\r\n"
            "\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("lowercase Transfer-Encoding still rejected",
                                                     [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_duplicate_header_rejected() {
         Test::Result result("HTTP response parser rejects duplicate header");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 0\r\n"
            "content-length: 0\r\n"
            "\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("case-insensitive duplicate",
                                                     [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_empty_header_name_rejected() {
         Test::Result result("HTTP response parser rejects empty name");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            ": orphan value\r\n"
            "\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("empty name", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_invalid_header_name_char_rejected() {
         Test::Result result("HTTP response parser rejects non-tchar in name");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Bad Name: value\r\n"  // space is not a tchar
            "\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("space in name", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_content_length_mismatch() {
         Test::Result result("HTTP response parser Content-Length mismatch");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 100\r\n"
            "\r\n"
            "short";
         result.test_throws<Botan::HTTP::HTTP_Error>("body shorter than CL", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_content_length_exceeds_max() {
         Test::Result result("HTTP response parser Content-Length > max");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 10000\r\n"
            "\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("CL exceeds policy", [&] { (void)parse_via_socket(raw, 1024); });
         return result;
      }

      static Test::Result test_body_without_cl_exceeds_max() {
         Test::Result result("HTTP response parser body without CL exceeds max");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "\r\n"
            "this body is more than ten bytes";
         result.test_throws<Botan::HTTP::HTTP_Error>("body exceeds policy", [&] { (void)parse_via_socket(raw, 10); });
         return result;
      }

      static Test::Result test_body_within_max() {
         Test::Result result("HTTP response parser body within max");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 4\r\n"
            "\r\n"
            "abcd";
         const auto resp = parse_via_socket(raw, 4);
         result.test_sz_eq("body size", resp.body().size(), 4);
         return result;
      }

      static Test::Result test_oversized_headers_rejected() {
         Test::Result result("HTTP response parser rejects oversized headers");
         // Build a response whose header block exceeds the 16 KB internal cap.
         std::string raw = "HTTP/1.0 200 OK\r\n";
         raw += "X-Padding: ";
         raw.append(20 * 1024, 'a');
         raw += "\r\n\r\n";
         result.test_throws<Botan::HTTP::HTTP_Error>("header section > 16 KB", [&] { (void)parse_via_socket(raw); });
         return result;
      }

      static Test::Result test_ows_variants_accepted() {
         Test::Result result("HTTP response parser accepts RFC 9110 OWS variants");

         // RFC 9110 5.5: field-line = field-name ":" OWS field-value OWS
         // OWS = *( SP / HTAB ); zero or more SP or HTAB on either side.
         struct Case {
               std::string line;
               std::string expected_value;
         };

         const std::vector<Case> cases{
            {"Content-Length:0", "0"},      // no OWS at all
            {"Content-Length: 0", "0"},     // single SP after colon (canonical)
            {"Content-Length:  0", "0"},    // two SP after colon
            {"Content-Length:\t0", "0"},    // HTAB after colon
            {"Content-Length: \t 0", "0"},  // mixed OWS after colon
            {"Content-Length: 0 ", "0"},    // trailing OWS
            {"Content-Length: 0\t", "0"},   // trailing HTAB
            {"X-Empty:", ""},               // empty value, no OWS
            {"X-Empty: ", ""},              // empty value, trailing OWS only
         };

         for(const auto& c : cases) {
            const std::string raw = "HTTP/1.0 200 OK\r\n" + c.line + "\r\n\r\n";
            try {
               const auto resp = parse_via_socket(raw);
               // Find the field name (everything before the first ':')
               const auto colon = c.line.find(':');
               const auto name = c.line.substr(0, colon);
               const auto it = resp.headers().find(name);
               if(result.test_is_true("header present: " + c.line, it != resp.headers().end())) {
                  result.test_str_eq("value trimmed for: " + c.line, it->second, c.expected_value);
               }
            } catch(const Botan::HTTP::HTTP_Error& e) {
               result.test_failure("unexpected throw on '" + c.line + "': " + e.what());
            }
         }
         return result;
      }

      static Test::Result test_byte_at_a_time_reads() {
         Test::Result result("HTTP response parser handles 1-byte-at-a-time reads");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 5\r\n"
            "Server: tiny\r\n"
            "\r\n"
            "hello";
         MockSocket socket(raw, 1);  // worst-case chunking
         const auto resp = Botan::HTTP::read_response_from_socket(socket, parse_test_timeout(), std::nullopt);
         result.test_u32_eq("status code", resp.status_code(), 200);
         result.test_str_eq("body", body_as_string(resp), "hello");
         result.test_str_eq("Server header", resp.headers().find("Server")->second, "tiny");
         return result;
      }

      static Test::Result test_header_terminator_split_across_reads() {
         Test::Result result("HTTP response parser handles header terminator split across reads");
         const std::string raw =
            "HTTP/1.0 200 OK\r\n"
            "Content-Length: 3\r\n"
            "\r\n"
            "abc";
         // Choose a chunk size that places the "\r\n\r\n" boundary across two reads.
         MockSocket socket(raw, 19);
         const auto resp = Botan::HTTP::read_response_from_socket(socket, parse_test_timeout(), std::nullopt);
         result.test_str_eq("body", body_as_string(resp), "abc");
         return result;
      }

      static Test::Result test_header_lookup_is_case_insensitive() {
         Test::Result result("HTTP::Response::headers case-insensitive lookup");
         const std::string raw =
            "HTTP/1.0 301 Moved Permanently\r\n"
            "LOCATION: http://other.example/\r\n"
            "Content-Length: 0\r\n"
            "\r\n";
         const auto resp = parse_via_socket(raw);
         result.test_is_true("find Location regardless of case",
                             resp.headers().find("Location") != resp.headers().end());
         result.test_is_true("contains Location regardless of case", resp.headers().contains("location"));
         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         return {
            test_minimal_response(),
            test_zero_header_response(),
            test_non_200_status(),
            test_no_content_length_eof_terminated(),
            test_case_insensitive_content_length(),
            test_no_header_terminator(),
            test_status_line_malformed(),
            test_status_code_out_of_range(),
            test_content_length_not_digits(),
            test_transfer_encoding_rejected(),
            test_transfer_encoding_case_insensitive(),
            test_duplicate_header_rejected(),
            test_empty_header_name_rejected(),
            test_invalid_header_name_char_rejected(),
            test_content_length_mismatch(),
            test_content_length_exceeds_max(),
            test_body_without_cl_exceeds_max(),
            test_body_within_max(),
            test_header_lookup_is_case_insensitive(),
            test_ows_variants_accepted(),
            test_oversized_headers_rejected(),
            test_byte_at_a_time_reads(),
            test_header_terminator_split_across_reads(),
         };
      }
};

BOTAN_REGISTER_TEST("http", "http_parse", HTTP_Parse_Tests);

class HTTP_Request_Tests final : public Test {
   private:
      // The first line of an HTTP message starts with "<verb> <target> HTTP/1.0\r\n".
      // Pull out the request-target so tests can assert on it.
      static std::string request_target(std::string_view message) {
         const auto sp1 = message.find(' ');
         const auto sp2 = message.find(' ', sp1 + 1);
         return std::string(message.substr(sp1 + 1, sp2 - sp1 - 1));
      }

      static std::string verb(std::string_view message) {
         const auto sp1 = message.find(' ');
         return std::string(message.substr(0, sp1));
      }

      static bool message_contains(std::string_view message, std::string_view needle) {
         return message.find(needle) != std::string_view::npos;
      }

      static Test::Result test_get_request_shape() {
         Test::Result result("HTTP::GET_sync request shape");
         MockServer mock({make_response(200, "OK", {{"Content-Length", "0"}}, "")});
         const auto uri = Botan::URI::parse("http://example.com/path/to/resource").value();

         (void)Botan::HTTP::http_sync(
            mock.as_exch_fn(), "GET", uri, "", std::vector<uint8_t>(), Botan::HTTP::RequestLimits());

         result.test_sz_eq("one call", mock.calls(), 1);
         result.test_str_eq("verb is GET", verb(mock.request(0)), "GET");
         result.test_str_eq("request-target", request_target(mock.request(0)), "/path/to/resource");
         result.test_is_true("has Host header", message_contains(mock.request(0), "Host: example.com\r\n"));
         result.test_is_true("Connection: close", message_contains(mock.request(0), "Connection: close\r\n"));
         result.test_is_false("no Content-Length", message_contains(mock.request(0), "Content-Length:"));
         result.test_str_eq("hostname passed to exch", mock.hostname(0), "example.com");
         result.test_str_eq("service is http (no port given)", mock.service(0), "http");
         return result;
      }

      static Test::Result test_post_request_shape() {
         Test::Result result("HTTP::POST_sync request shape");
         MockServer mock({make_response(200, "OK", {{"Content-Length", "2"}}, "ok")});
         const auto uri = Botan::URI::parse("http://example.com/submit").value();
         const std::vector<uint8_t> body{'h', 'i'};

         (void)Botan::HTTP::http_sync(mock.as_exch_fn(), "POST", uri, "text/plain", body, Botan::HTTP::RequestLimits());

         result.test_str_eq("verb is POST", verb(mock.request(0)), "POST");
         result.test_is_true("Content-Length: 2", message_contains(mock.request(0), "Content-Length: 2\r\n"));
         result.test_is_true("Content-Type set", message_contains(mock.request(0), "Content-Type: text/plain\r\n"));
         result.test_is_true("body appended", message_contains(mock.request(0), "\r\n\r\nhi"));
         return result;
      }

      static Test::Result test_query_in_request_target() {
         Test::Result result("HTTP request target includes query");
         MockServer mock({make_response(200)});
         const auto uri = Botan::URI::parse("http://example.com/api?id=42&n=1").value();
         (void)Botan::HTTP::http_sync(mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits());
         result.test_str_eq("query preserved", request_target(mock.request(0)), "/api?id=42&n=1");
         return result;
      }

      static Test::Result test_fragment_excluded_from_request_target() {
         Test::Result result("HTTP request target excludes fragment (RFC 9110 7.1)");
         MockServer mock({make_response(200)});
         const auto uri = Botan::URI::parse("http://example.com/page#section").value();
         (void)Botan::HTTP::http_sync(mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits());
         result.test_str_eq("no fragment in target", request_target(mock.request(0)), "/page");
         return result;
      }

      static Test::Result test_empty_path_defaults_to_slash() {
         Test::Result result("HTTP request target defaults empty path to /");
         MockServer mock({make_response(200), make_response(200)});
         const auto bare = Botan::URI::parse("http://example.com").value();
         (void)Botan::HTTP::http_sync(mock.as_exch_fn(), "GET", bare, "", {}, Botan::HTTP::RequestLimits());
         result.test_str_eq("no path => /", request_target(mock.request(0)), "/");

         const auto query_only = Botan::URI::parse("http://example.com?q=1").value();
         (void)Botan::HTTP::http_sync(mock.as_exch_fn(), "GET", query_only, "", {}, Botan::HTTP::RequestLimits());
         result.test_str_eq("no path with query => /?q=1", request_target(mock.request(1)), "/?q=1");
         return result;
      }

      static Test::Result test_ipv6_host_header_bracketed() {
         Test::Result result("HTTP Host header brackets IPv6");
         MockServer mock({make_response(200)});
         const auto uri = Botan::URI::parse("http://[::1]:8080/").value();
         (void)Botan::HTTP::http_sync(mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits());
         result.test_is_true("Host has brackets and port",
                             message_contains(mock.request(0), "Host: [0:0:0:0:0:0:0:1]:8080\r\n"));
         result.test_str_eq("service is the port", mock.service(0), "8080");
         return result;
      }

      static Test::Result test_https_scheme_rejected() {
         Test::Result result("HTTP rejects non-http scheme");
         MockServer mock({});
         const auto uri = Botan::URI::parse("https://example.com/").value();
         result.test_throws<Botan::HTTP::HTTP_Error>("https URI", [&] {
            (void)Botan::HTTP::http_sync(mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits());
         });
         result.test_sz_eq("never called", mock.calls(), 0);
         return result;
      }

      static Test::Result test_max_body_size_propagated() {
         Test::Result result("HTTP max_body_size reaches the transact callback");
         MockServer mock({make_response(200)});
         const auto uri = Botan::URI::parse("http://example.com/").value();
         (void)Botan::HTTP::http_sync(
            mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_body_size(8192));
         result.test_is_true("max_body_size present", mock.max_body_size(0).has_value());
         result.test_sz_eq("max_body_size value", *mock.max_body_size(0), 8192);
         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         return {
            test_get_request_shape(),
            test_post_request_shape(),
            test_query_in_request_target(),
            test_fragment_excluded_from_request_target(),
            test_empty_path_defaults_to_slash(),
            test_ipv6_host_header_bracketed(),
            test_https_scheme_rejected(),
            test_max_body_size_propagated(),
         };
      }
};

BOTAN_REGISTER_TEST("http", "http_request", HTTP_Request_Tests);

class HTTP_Redirect_Tests final : public Test {
   private:
      static std::string verb_of(std::string_view message) { return std::string(message.substr(0, message.find(' '))); }

      static Test::Result test_301_preserves_method_for_get() {
         Test::Result result("HTTP 301 with GET: re-issues GET to new URL");
         MockServer mock({
            make_response(301, "Moved", {{"Location", "http://other.example/new"}}),
            make_response(200, "OK", {{"Content-Length", "2"}}, "ok"),
         });
         const auto uri = Botan::URI::parse("http://example.com/old").value();
         const auto resp = Botan::HTTP::http_sync(
            mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(2));
         result.test_sz_eq("two calls", mock.calls(), 2);
         result.test_str_eq("second call is GET", verb_of(mock.request(1)), "GET");
         result.test_str_eq("hostname switched", mock.hostname(1), "other.example");
         result.test_u32_eq("final status", resp.status_code(), 200);
         return result;
      }

      static Test::Result test_303_post_downgrades_to_get() {
         Test::Result result("HTTP 303 with POST: downgrades to GET (drops body)");
         MockServer mock({
            make_response(303, "See Other", {{"Location", "http://example.com/result"}}),
            make_response(200, "OK"),
         });
         const auto uri = Botan::URI::parse("http://example.com/submit").value();
         const std::vector<uint8_t> body{'p', 'a', 'y', 'l', 'o', 'a', 'd'};

         (void)Botan::HTTP::http_sync(
            mock.as_exch_fn(), "POST", uri, "text/plain", body, Botan::HTTP::RequestLimits().set_max_redirects(1));

         result.test_sz_eq("two calls", mock.calls(), 2);
         result.test_str_eq("second call switched to GET", verb_of(mock.request(1)), "GET");
         const auto& msg = mock.request(1);
         result.test_is_false("body dropped on 303 -> GET", msg.find("\r\n\r\npayload") != std::string::npos);
         return result;
      }

      static Test::Result test_307_post_preserves_method_and_body() {
         Test::Result result("HTTP 307 with POST: preserves method and body");
         MockServer mock({
            make_response(307, "Temporary Redirect", {{"Location", "http://example.com/v2"}}),
            make_response(200, "OK", {{"Content-Length", "2"}}, "ok"),
         });
         const auto uri = Botan::URI::parse("http://example.com/submit").value();
         const std::vector<uint8_t> body{'p', 'a', 'y', 'l', 'o', 'a', 'd'};

         (void)Botan::HTTP::http_sync(mock.as_exch_fn(),
                                      "POST",
                                      uri,
                                      "application/octet-stream",
                                      body,
                                      Botan::HTTP::RequestLimits().set_max_redirects(1));

         result.test_sz_eq("two calls", mock.calls(), 2);
         result.test_str_eq("second call still POST", verb_of(mock.request(1)), "POST");
         result.test_is_true("body re-sent", mock.request(1).find("\r\n\r\npayload") != std::string::npos);
         result.test_is_true("Content-Type re-sent",
                             mock.request(1).find("Content-Type: application/octet-stream\r\n") != std::string::npos);
         return result;
      }

      static Test::Result test_308_preserves_method() {
         Test::Result result("HTTP 308: preserves method");
         MockServer mock({
            make_response(308, "Permanent Redirect", {{"Location", "http://example.com/new"}}),
            make_response(200, "OK"),
         });
         const auto uri = Botan::URI::parse("http://example.com/old").value();
         (void)Botan::HTTP::http_sync(mock.as_exch_fn(),
                                      "POST",
                                      uri,
                                      "text/plain",
                                      std::vector<uint8_t>{'x'},
                                      Botan::HTTP::RequestLimits().set_max_redirects(1));
         result.test_str_eq("second call still POST", verb_of(mock.request(1)), "POST");
         return result;
      }

      static Test::Result test_redirect_count_exceeded() {
         Test::Result result("HTTP redirect count exceeded");
         MockServer mock({
            make_response(301, "Moved", {{"Location", "http://example.com/a"}}),
            make_response(301, "Moved", {{"Location", "http://example.com/b"}}),
         });
         const auto uri = Botan::URI::parse("http://example.com/start").value();
         result.test_throws<Botan::HTTP::HTTP_Error>("exceeds redirect budget", [&] {
            (void)Botan::HTTP::http_sync(
               mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(1));
         });
         result.test_sz_eq("stopped at the second response", mock.calls(), 2);
         return result;
      }

      static Test::Result test_redirect_to_invalid_url() {
         Test::Result result("HTTP redirect to unparsable URL");
         MockServer mock({
            make_response(301, "Moved", {{"Location", "::not a url::"}}),
         });
         const auto uri = Botan::URI::parse("http://example.com/").value();
         result.test_throws<Botan::HTTP::HTTP_Error>("invalid Location", [&] {
            (void)Botan::HTTP::http_sync(
               mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(1));
         });
         return result;
      }

      static Test::Result test_redirect_to_non_http_rejected() {
         Test::Result result("HTTP redirect to non-http scheme rejected");
         MockServer mock({
            make_response(301, "Moved", {{"Location", "https://example.com/"}}),
         });
         const auto uri = Botan::URI::parse("http://example.com/").value();
         result.test_throws<Botan::HTTP::HTTP_Error>("https Location", [&] {
            (void)Botan::HTTP::http_sync(
               mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(1));
         });
         return result;
      }

      static Test::Result test_path_absolute_location_resolved() {
         Test::Result result("HTTP path-absolute Location resolved against request URI");
         MockServer mock({
            make_response(301, "Moved", {{"Location", "/v2/resource?id=1"}}),
            make_response(200, "OK"),
         });
         const auto uri = Botan::URI::parse("http://example.com:8080/v1/old").value();
         (void)Botan::HTTP::http_sync(
            mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(1));
         result.test_sz_eq("two calls", mock.calls(), 2);
         result.test_str_eq("same authority retained", mock.hostname(1), "example.com");
         result.test_str_eq("same port retained", mock.service(1), "8080");
         result.test_is_true("request-target uses Location path+query",
                             mock.request(1).find("GET /v2/resource?id=1 HTTP/1.0\r\n") != std::string::npos);
         return result;
      }

      static Test::Result test_network_path_location_rejected() {
         Test::Result result("HTTP network-path Location (//host/p) rejected");
         MockServer mock({
            make_response(301, "Moved", {{"Location", "//evil.example/new"}}),
         });
         const auto uri = Botan::URI::parse("http://example.com/").value();
         result.test_throws<Botan::HTTP::HTTP_Error>("// prefix not resolved", [&] {
            (void)Botan::HTTP::http_sync(
               mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(1));
         });
         return result;
      }

      static Test::Result test_userinfo_not_forwarded_on_redirect() {
         Test::Result result("HTTP path-absolute redirect strips userinfo");
         MockServer mock({
            make_response(301, "Moved", {{"Location", "/elsewhere"}}),
            make_response(200, "OK"),
         });
         const auto uri = Botan::URI::parse("http://user:pass@example.com/start").value();
         (void)Botan::HTTP::http_sync(
            mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(1));
         result.test_sz_eq("two calls", mock.calls(), 2);
         result.test_is_false("no userinfo in second Host header",
                              mock.request(1).find("user:pass") != std::string::npos);
         result.test_is_true("plain Host header on redirect",
                             mock.request(1).find("Host: example.com\r\n") != std::string::npos);
         return result;
      }

      static Test::Result test_redirect_without_location_returned() {
         Test::Result result("HTTP 3xx without Location returned to caller");
         MockServer mock({make_response(301, "Moved")});
         const auto uri = Botan::URI::parse("http://example.com/").value();
         const auto resp = Botan::HTTP::http_sync(
            mock.as_exch_fn(), "GET", uri, "", {}, Botan::HTTP::RequestLimits().set_max_redirects(1));
         result.test_sz_eq("one call only", mock.calls(), 1);
         result.test_u32_eq("status passed through", resp.status_code(), 301);
         return result;
      }

   public:
      std::vector<Test::Result> run() override {
         return {
            test_301_preserves_method_for_get(),
            test_303_post_downgrades_to_get(),
            test_307_post_preserves_method_and_body(),
            test_308_preserves_method(),
            test_redirect_count_exceeded(),
            test_redirect_to_invalid_url(),
            test_redirect_to_non_http_rejected(),
            test_path_absolute_location_resolved(),
            test_network_path_location_rejected(),
            test_userinfo_not_forwarded_on_redirect(),
            test_redirect_without_location_returned(),
         };
      }
};

BOTAN_REGISTER_TEST("http", "http_redirect", HTTP_Redirect_Tests);

class HTTP_URL_Encode_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("HTTP::url_encode");

         result.test_str_eq("alpha-numeric passes through", Botan::HTTP::url_encode("hello123"), "hello123");
         result.test_str_eq("unreserved passes through", Botan::HTTP::url_encode("a-b_c.d~e"), "a-b_c.d~e");
         result.test_str_eq("space encoded", Botan::HTTP::url_encode("a b"), "a%20b");
         result.test_str_eq("slash encoded", Botan::HTTP::url_encode("/"), "%2F");
         result.test_str_eq("high-bit byte encodes to two hex digits", Botan::HTTP::url_encode("\xff"), "%FF");
         result.test_str_eq("empty input", Botan::HTTP::url_encode(""), "");

         return {result};
      }
};

BOTAN_REGISTER_TEST("http", "http_url_encode", HTTP_URL_Encode_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
