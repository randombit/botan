/*
* Sketchy HTTP client
* (C) 2013,2016 Jack Lloyd
*     2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/http_util.h>

#include <botan/hex.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>
#include <botan/internal/socket.h>
#include <botan/internal/stl_util.h>
#include <sstream>

namespace Botan::HTTP {

namespace {

/*
* Connect to a host, write some bytes, then read until the server
* closes the socket.
*/
std::string http_transact(std::string_view hostname,
                          std::string_view service,
                          std::string_view message,
                          std::chrono::milliseconds timeout) {
   std::unique_ptr<OS::Socket> socket;

   const std::chrono::system_clock::time_point start_time = std::chrono::system_clock::now();

   try {
      socket = OS::open_socket(hostname, service, timeout);
      if(!socket) {
         throw Not_Implemented("No socket support enabled in build");
      }
   } catch(std::exception& e) {
      throw HTTP_Error(fmt("HTTP connection to {} failed: {}", hostname, e.what()));
   }

   // Blocks until entire message has been written
   socket->write(cast_char_ptr_to_uint8(message.data()), message.size());

   if(std::chrono::system_clock::now() - start_time > timeout) {
      throw HTTP_Error("Timeout during writing message body");
   }

   std::ostringstream oss;
   std::vector<uint8_t> buf(BOTAN_DEFAULT_BUFFER_SIZE);
   while(true) {
      const size_t got = socket->read(buf.data(), buf.size());
      if(got == 0) {  // EOF
         break;
      }

      if(std::chrono::system_clock::now() - start_time > timeout) {
         throw HTTP_Error("Timeout while reading message body");
      }

      oss.write(cast_uint8_ptr_to_char(buf.data()), static_cast<std::streamsize>(got));
   }

   return oss.str();
}

bool needs_url_encoding(char c) {
   if(c >= 'A' && c <= 'Z') {
      return false;
   }
   if(c >= 'a' && c <= 'z') {
      return false;
   }
   if(c >= '0' && c <= '9') {
      return false;
   }
   if(c == '-' || c == '_' || c == '.' || c == '~') {
      return false;
   }
   return true;
}

}  // namespace

std::string url_encode(std::string_view in) {
   std::ostringstream out;

   for(auto c : in) {
      if(needs_url_encoding(c)) {
         out << '%' << hex_encode(cast_char_ptr_to_uint8(&c), 1);
      } else {
         out << c;
      }
   }

   return out.str();
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
                   std::string_view url,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   size_t allowable_redirects) {
   if(url.empty()) {
      throw HTTP_Error("URL empty");
   }

   const auto protocol_host_sep = url.find("://");
   if(protocol_host_sep == std::string::npos) {
      throw HTTP_Error(fmt("Invalid URL '{}'", url));
   }

   const auto host_loc_sep = url.find('/', protocol_host_sep + 3);

   std::string hostname, loc, service;

   if(host_loc_sep == std::string::npos) {
      hostname = url.substr(protocol_host_sep + 3, std::string::npos);
      loc = "/";
   } else {
      hostname = url.substr(protocol_host_sep + 3, host_loc_sep - protocol_host_sep - 3);
      loc = url.substr(host_loc_sep, std::string::npos);
   }

   const auto port_sep = hostname.find(':');
   if(port_sep == std::string::npos) {
      service = "http";
      // hostname not modified
   } else {
      service = hostname.substr(port_sep + 1, std::string::npos);
      hostname = hostname.substr(0, port_sep);
   }

   std::ostringstream outbuf;

   outbuf << verb << " " << loc << " HTTP/1.0\r\n";
   outbuf << "Host: " << hostname << "\r\n";

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

   std::istringstream io(http_transact(hostname, service, outbuf.str()));

   std::string line1;
   std::getline(io, line1);
   if(!io || line1.empty()) {
      throw HTTP_Error("No response");
   }

   std::stringstream response_stream(line1);
   std::string http_version;
   unsigned int status_code;
   std::string status_message;

   response_stream >> http_version >> status_code;

   std::getline(response_stream, status_message);

   if(!response_stream || http_version.substr(0, 5) != "HTTP/") {
      throw HTTP_Error("Not an HTTP response");
   }

   std::map<std::string, std::string> headers;
   std::string header_line;
   while(std::getline(io, header_line) && header_line != "\r") {
      auto sep = header_line.find(": ");
      if(sep == std::string::npos || sep > header_line.size() - 2) {
         throw HTTP_Error(fmt("Invalid HTTP header '{}'", header_line));
      }
      const std::string key = header_line.substr(0, sep);

      if(sep + 2 < header_line.size() - 1) {
         const std::string val = header_line.substr(sep + 2, (header_line.size() - 1) - (sep + 2));
         headers[key] = val;
      }
   }

   if(status_code == 301 && headers.contains("Location")) {
      if(allowable_redirects == 0) {
         throw HTTP_Error("HTTP redirection count exceeded");
      }
      return GET_sync(headers["Location"], allowable_redirects - 1);
   }

   std::vector<uint8_t> resp_body;
   std::vector<uint8_t> buf(4096);
   while(io.good()) {
      io.read(cast_uint8_ptr_to_char(buf.data()), buf.size());
      const size_t got = static_cast<size_t>(io.gcount());
      resp_body.insert(resp_body.end(), buf.data(), &buf[got]);
   }

   auto cl_hdr = headers.find("Content-Length");
   if(cl_hdr != headers.end()) {
      const std::string header_size = cl_hdr->second;
      if(resp_body.size() != to_u32bit(header_size)) {
         throw HTTP_Error(fmt("Content-Length disagreement, header says {} got {}", header_size, resp_body.size()));
      }
   }

   return Response(status_code, status_message, resp_body, headers);
}

Response http_sync(std::string_view verb,
                   std::string_view url,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   size_t allowable_redirects,
                   std::chrono::milliseconds timeout) {
   auto transact_with_timeout = [timeout](
                                   std::string_view hostname, std::string_view service, std::string_view message) {
      return http_transact(hostname, service, message, timeout);
   };

   return http_sync(transact_with_timeout, verb, url, content_type, body, allowable_redirects);
}

Response GET_sync(std::string_view url, size_t allowable_redirects, std::chrono::milliseconds timeout) {
   return http_sync("GET", url, "", std::vector<uint8_t>(), allowable_redirects, timeout);
}

Response POST_sync(std::string_view url,
                   std::string_view content_type,
                   const std::vector<uint8_t>& body,
                   size_t allowable_redirects,
                   std::chrono::milliseconds timeout) {
   return http_sync("POST", url, content_type, body, allowable_redirects, timeout);
}

}  // namespace Botan::HTTP
