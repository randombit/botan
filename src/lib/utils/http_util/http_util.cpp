/*
* HTTP 1.0 client
* (C) 2013,2016,2026 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/http_util.h>

#include <botan/mem_ops.h>
#include <botan/uri.h>
#include <botan/internal/charset.h>
#include <botan/internal/fmt.h>
#include <botan/internal/mem_utils.h>
#include <botan/internal/parsing.h>
#include <botan/internal/socket.h>
#include <limits>
#include <sstream>

namespace Botan::HTTP {

namespace {

constexpr size_t MaxHeaderBytes = 16 * 1024;

struct Parsed_Head {
      unsigned int status_code;
      std::string status_message;
      Headers headers;
};

Parsed_Head parse_status_and_headers(std::string_view block) {
   const auto first_eol = block.find("\r\n");
   const auto status_line_end = (first_eol == std::string_view::npos) ? block.size() : first_eol;
   if(status_line_end == 0) {
      throw HTTP_Error("No status line");
   }

   std::stringstream ss{std::string(block.substr(0, status_line_end))};
   std::string http_version;
   unsigned int status_code = 0;
   ss >> http_version >> status_code;
   std::string status_message;
   std::getline(ss, status_message);
   if(!status_message.empty() && status_message.front() == ' ') {
      status_message.erase(0, 1);
   }

   if(!ss || !http_version.starts_with("HTTP/")) {
      throw HTTP_Error("Not an HTTP response");
   }

   // RFC 9110 Section 15: "All valid status codes are within the range of 100 to 599, inclusive."
   if(status_code < 100 || status_code > 599) {
      throw HTTP_Error(fmt("Invalid HTTP status code {}", status_code));
   }

   // RFC 9110 5.6.2 tchar
   constexpr auto is_tchar = CharacterValidityTable::alpha_numeric_plus("!#$%&'*+-.^_`|~");
   // RFC 9110 5.6.3 OWS = *( SP / HTAB )
   constexpr auto is_ows = [](char c) { return c == ' ' || c == '\t'; };

   Headers headers;
   size_t pos = (first_eol == std::string_view::npos) ? block.size() : first_eol + 2;
   while(pos < block.size()) {
      const auto eol = block.find("\r\n", pos);
      const auto line_end = (eol == std::string_view::npos) ? block.size() : eol;
      const auto line = block.substr(pos, line_end - pos);

      // RFC 9110 5.5: field-line = field-name ":" OWS field-value OWS
      const auto sep = line.find(':');
      if(sep == std::string_view::npos || sep == 0) {
         throw HTTP_Error(fmt("Invalid HTTP header '{}'", line));
      }

      const auto name = line.substr(0, sep);
      if(!std::all_of(name.begin(), name.end(), is_tchar)) {
         throw HTTP_Error(fmt("Invalid HTTP header name '{}'", name));
      }

      auto value = line.substr(sep + 1);
      while(!value.empty() && is_ows(value.front())) {
         value.remove_prefix(1);
      }
      while(!value.empty() && is_ows(value.back())) {
         value.remove_suffix(1);
      }

      auto [it, inserted] = headers.emplace(std::string(name), std::string(value));
      if(!inserted) {
         throw HTTP_Error(fmt("Duplicate HTTP header '{}'", it->first));
      }

      if(eol == std::string_view::npos) {
         break;
      }
      pos = eol + 2;
   }

   return {status_code, std::move(status_message), std::move(headers)};
}

/*
* Post-header validation shared by the streaming reader and the in-memory
* parser. Rejects Transfer-Encoding outright (we only speak HTTP/1.0) and
* enforces Content-Length against max_body_size. Returns the parsed
* Content-Length on success, if present.
*/
std::optional<size_t> validate_response_headers(const Headers& headers, std::optional<size_t> max_body_size) {
   // RFC 9112 6.1: "A server MUST NOT send a response containing Transfer-Encoding
   // unless the corresponding request indicates HTTP/1.1 (or later minor revisions)."
   if(headers.contains("Transfer-Encoding")) {
      throw HTTP_Error("Server sent Transfer-Encoding header in response to HTTP/1.0 request");
   }

   std::optional<size_t> content_length;
   if(auto it = headers.find("Content-Length"); it != headers.end()) {
      // RFC 9110 8.6: Content-Length = 1*DIGIT
      const auto& cl = it->second;
      if(cl.empty() || !std::all_of(cl.begin(), cl.end(), [](unsigned char c) { return c >= '0' && c <= '9'; })) {
         throw HTTP_Error(fmt("Invalid Content-Length value '{}'", cl));
      }
      try {
         content_length = to_u32bit(cl);
      } catch(const Invalid_Argument& e) {
         throw HTTP_Error(fmt("Invalid Content-Length value '{}': {}", cl, e.what()));
      }
   }

   if(content_length && max_body_size && *content_length > *max_body_size) {
      throw HTTP_Error(fmt("Content-Length {} exceeds maximum body size {}", *content_length, *max_body_size));
   }

   return content_length;
}

/*
* Connect to a host, write the request, then delegate to
* read_response_from_socket. Body- and header-size caps are enforced
* there; this just owns the socket lifecycle.
*/
Response http_transact(std::string_view hostname,
                       std::string_view service,
                       std::string_view message,
                       std::chrono::milliseconds timeout,
                       std::optional<size_t> max_body_size) {
   std::unique_ptr<OS::Socket> socket;
   try {
      socket = OS::open_socket(hostname, service, timeout);
      if(!socket) {
         throw Not_Implemented("No socket support enabled in build");
      }
   } catch(std::exception& e) {
      throw HTTP_Error(fmt("HTTP connection to {} failed: {}", hostname, e.what()));
   }

   socket->write(as_span_of_bytes(message));
   return read_response_from_socket(*socket, timeout, max_body_size);
}

void check_no_crlf_nul(std::string_view field, std::string_view value) {
   for(const char c : value) {
      if(c == '\r' || c == '\n' || c == '\0') {
         throw HTTP_Error(fmt("Invalid character in HTTP {}", field));
      }
   }
}

/*
* Resolve a Location header value against the request URI per RFC 9110 10.2.2.
* Handles two cases: an absolute URI, or a path-absolute reference (begins
* with '/' but not '//') which is composed against the request URI's scheme
* and authority. Other relative forms (network-path "//host/p", protocol-
* relative, dot-segments) are rejected.
*/
std::optional<URI> resolve_location(const URI& base, std::string_view location) {
   if(auto absolute = URI::parse(location)) {
      return absolute;
   }
   if(location.starts_with("/") && !location.starts_with("//")) {
      const std::string composed = base.scheme() + "://" + base.authority().original_input() + std::string(location);
      return URI::parse(composed);
   }
   return std::nullopt;
}

}  // namespace

Response read_response_from_socket(OS::Socket& socket,
                                   std::chrono::milliseconds timeout,
                                   std::optional<size_t> max_body_size) {
   const auto start_time = std::chrono::system_clock::now();
   const auto deadline_exceeded = [&] { return std::chrono::system_clock::now() - start_time > timeout; };

   if(deadline_exceeded()) {
      throw HTTP_Error("Timeout before reading response");
   }

   std::string buf;
   std::vector<uint8_t> chunk(DefaultBufferSize);
   size_t header_end = std::string::npos;

   while(header_end == std::string::npos) {
      const size_t got = socket.read(chunk.data(), chunk.size());
      if(got == 0) {
         throw HTTP_Error("Server closed connection before headers complete");
      }
      if(deadline_exceeded()) {
         throw HTTP_Error("Timeout while reading headers");
      }
      buf.append(cast_uint8_ptr_to_char(chunk.data()), got);
      header_end = buf.find("\r\n\r\n");
      if(header_end == std::string::npos && buf.size() > MaxHeaderBytes) {
         throw HTTP_Error("HTTP headers exceed maximum size");
      }
   }

   // Same cap re-checked once the terminator is found, since the terminator
   // can arrive in the chunk that crosses the limit.
   if(header_end > MaxHeaderBytes) {
      throw HTTP_Error("HTTP headers exceed maximum size");
   }

   auto parsed = parse_status_and_headers(std::string_view(buf).substr(0, header_end));
   const auto content_length = validate_response_headers(parsed.headers, max_body_size);

   const size_t body_cap = std::min(max_body_size.value_or(std::numeric_limits<size_t>::max()),
                                    content_length.value_or(std::numeric_limits<size_t>::max()));

   std::vector<uint8_t> body;
   if(content_length) {
      body.reserve(*content_length);
   }
   const size_t body_start = header_end + 4;
   if(body_start < buf.size()) {
      const size_t spill = buf.size() - body_start;
      if(spill > body_cap) {
         throw HTTP_Error("Response body exceeds maximum size");
      }
      body.insert(body.end(),
                  reinterpret_cast<const uint8_t*>(buf.data() + body_start),
                  reinterpret_cast<const uint8_t*>(buf.data() + buf.size()));
   }

   while(!content_length || body.size() < *content_length) {
      const size_t got = socket.read(chunk.data(), chunk.size());
      if(got == 0) {
         break;
      }
      if(deadline_exceeded()) {
         throw HTTP_Error("Timeout while reading body");
      }
      if(body.size() + got > body_cap) {
         throw HTTP_Error("Response body exceeds maximum size");
      }
      body.insert(body.end(), chunk.data(), chunk.data() + got);
   }

   if(content_length && body.size() != *content_length) {
      throw HTTP_Error(fmt("Content-Length disagreement, header says {} got {}", *content_length, body.size()));
   }

   return Response(parsed.status_code, std::move(parsed.status_message), std::move(body), std::move(parsed.headers));
}

std::string url_encode(std::string_view in) {
   constexpr auto needs_url_encoding = CharacterValidityTable::alpha_numeric_plus("-_.~").invert();
   constexpr std::string_view hex_digits = "0123456789ABCDEF";

   std::string out;
   out.reserve(in.size());
   for(const char c : in) {
      if(needs_url_encoding(c)) {
         const auto byte = static_cast<uint8_t>(c);
         out += '%';
         out += hex_digits[byte >> 4];
         out += hex_digits[byte & 0x0F];
      } else {
         out += c;
      }
   }
   return out;
}

std::ostream& operator<<(std::ostream& o, const Response& resp) {
   o << "HTTP " << resp.status_code() << " " << resp.status_message() << "\n";
   for(const auto& h : resp.headers()) {
      o << "Header '" << h.first << "' = '" << h.second << "'\n";
   }
   o << "Body " << std::to_string(resp.body().size()) << " bytes:\n";
   o.write(cast_uint8_ptr_to_char(resp.body().data()), resp.body().size());
   return o;
}

Response http_sync(const http_exch_fn& http_transact,
                   std::string_view verb,
                   const URI& uri,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   const RequestLimits& limits) {
   if(uri.scheme() != "http") {
      throw HTTP_Error(fmt("Cannot initiate HTTP request to URI with scheme of '{}'", uri.scheme()));
   }

   check_no_crlf_nul("verb", verb);
   check_no_crlf_nul("content type", content_type);

   const std::string hostname = uri.host_to_string();
   const std::string service = uri.port().has_value() ? std::to_string(*uri.port()) : uri.scheme();

   // RFC 9112 3.2.1: request-target origin-form is "absolute-path [ '?' query ]".
   // If the URI has an empty path, the client MUST send "/". Fragment is
   // excluded from the request-target per RFC 9110 7.1.
   std::string loc = uri.path().empty() ? "/" : uri.path();
   if(const auto& q = uri.query()) {
      loc += '?';
      loc += *q;
   }

   const std::string host_header = [&]() -> std::string {
      const std::string h = (uri.host_kind() == URI::HostKind::IPv6) ? "[" + hostname + "]" : hostname;
      return uri.port().has_value() ? h + ":" + std::to_string(*uri.port()) : h;
   }();

   std::ostringstream outbuf;

   outbuf << verb << " " << loc << " HTTP/1.0\r\n";
   outbuf << "Host: " << host_header << "\r\n";

   if(verb == "GET") {
      outbuf << "Accept: */*\r\n";
      outbuf << "Cache-Control: no-cache\r\n";
   } else if(verb == "POST") {
      outbuf << "Content-Length: " << body.size() << "\r\n";
   }

   if(!content_type.empty()) {
      outbuf << "Content-Type: " << content_type << "\r\n";
   }
   outbuf << "Connection: close\r\n\r\n";
   outbuf.write(cast_uint8_ptr_to_char(body.data()), body.size());

   Response resp = http_transact(hostname, service, outbuf.str(), limits.max_body_size());

   const auto sc = resp.status_code();
   const bool is_redirect = (sc == 301 || sc == 302 || sc == 303 || sc == 307 || sc == 308);
   if(is_redirect) {
      const auto loc_it = resp.headers().find("Location");
      if(loc_it != resp.headers().end()) {
         if(limits.max_redirects() == 0) {
            throw HTTP_Error("HTTP redirection count exceeded");
         }
         auto redir = resolve_location(uri, loc_it->second);
         if(!redir) {
            throw HTTP_Error("HTTP redirected to invalid URL");
         }
         RequestLimits next = limits;
         next.set_max_redirects(limits.max_redirects() - 1);

         // 303 (RFC 9110 15.4.4) re-issues as GET; 301/302/307/308 preserve the
         // original method and content. The POST->GET downgrade allowed for
         // 301/302 by RFC 9110 15.4.2/3 exists for browser form-submission
         // legacy and would silently drop the request body, which is wrong here.
         //
         // The recursion goes through the same http_exch_fn so a test seam (or
         // any caller wrapping the network layer) sees every hop.
         if(sc == 303) {
            return http_sync(http_transact, "GET", *redir, "", std::vector<uint8_t>(), next);
         } else {
            return http_sync(http_transact, verb, *redir, content_type, body, next);
         }
      }
   }

   return resp;
}

Response http_sync(std::string_view verb,
                   const URI& uri,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   const RequestLimits& limits) {
   auto transact_with_timeout =
      [timeout = limits.timeout()](
         std::string_view hostname, std::string_view service, std::string_view message, std::optional<size_t> mbs) {
         return http_transact(hostname, service, message, timeout, mbs);
      };

   return http_sync(transact_with_timeout, verb, uri, content_type, body, limits);
}

Response GET_sync(const URI& uri, const RequestLimits& limits) {
   return http_sync("GET", uri, "", std::vector<uint8_t>(), limits);
}

Response POST_sync(const URI& uri,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   const RequestLimits& limits) {
   return http_sync("POST", uri, content_type, body, limits);
}

}  // namespace Botan::HTTP
