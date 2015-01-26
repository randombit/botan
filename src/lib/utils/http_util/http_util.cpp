/*
* Sketchy HTTP client
* (C) 2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/http_util.h>
#include <botan/parsing.h>
#include <botan/hex.h>
#include <botan/internal/stl_util.h>
#include <sstream>

#if defined(BOTAN_HAS_BOOST_ASIO)
#include <boost/asio.hpp>
#endif

namespace Botan {

namespace HTTP {

#if defined(BOTAN_HAS_BOOST_ASIO)
std::string http_transact_asio(const std::string& hostname,
                               const std::string& message)
   {
   using namespace boost::asio::ip;

   boost::asio::ip::tcp::iostream tcp;

   tcp.connect(hostname, "http");

   if(!tcp)
      throw std::runtime_error("HTTP connection to " + hostname + " failed");

   tcp << message;
   tcp.flush();

   std::ostringstream oss;
   oss << tcp.rdbuf();

   return oss.str();
   }
#endif

std::string http_transact_fail(const std::string& hostname,
                               const std::string&)
   {
   throw std::runtime_error("Cannot connect to " + hostname +
                            ": network code disabled in build");
   }

std::string url_encode(const std::string& in)
   {
   std::ostringstream out;

   for(auto c : in)
      {
      if(c >= 'A' && c <= 'Z')
         out << c;
      else if(c >= 'a' && c <= 'z')
         out << c;
      else if(c >= '0' && c <= '9')
         out << c;
      else if(c == '-' || c == '_' || c == '.' || c == '~')
         out << c;
      else
         out << '%' << hex_encode(reinterpret_cast<byte*>(&c), 1);
      }

   return out.str();
   }

std::ostream& operator<<(std::ostream& o, const Response& resp)
   {
   o << "HTTP " << resp.status_code() << " " << resp.status_message() << "\n";
   for(auto h : resp.headers())
      o << "Header '" << h.first << "' = '" << h.second << "'\n";
   o << "Body " << std::to_string(resp.body().size()) << " bytes:\n";
   o.write(reinterpret_cast<const char*>(&resp.body()[0]), resp.body().size());
   return o;
   }

Response http_sync(http_exch_fn http_transact,
                   const std::string& verb,
                   const std::string& url,
                   const std::string& content_type,
                   const std::vector<byte>& body,
                   size_t allowable_redirects)
   {
   const auto protocol_host_sep = url.find("://");
   if(protocol_host_sep == std::string::npos)
      throw std::runtime_error("Invalid URL " + url);
   const std::string protocol = url.substr(0, protocol_host_sep);

   const auto host_loc_sep = url.find('/', protocol_host_sep + 3);

   std::string hostname, loc;

   if(host_loc_sep == std::string::npos)
      {
      hostname = url.substr(protocol_host_sep + 3, std::string::npos);
      loc = "/";
      }
   else
      {
      hostname = url.substr(protocol_host_sep + 3, host_loc_sep-protocol_host_sep-3);
      loc = url.substr(host_loc_sep, std::string::npos);
      }

   std::ostringstream outbuf;

   outbuf << verb << " " << loc << " HTTP/1.0\r\n";
   outbuf << "Host: " << hostname << "\r\n";

   if(verb == "GET")
      {
      outbuf << "Accept: */*\r\n";
      outbuf << "Cache-Control: no-cache\r\n";
      }
   else if(verb == "POST")
      outbuf << "Content-Length: " << body.size() << "\r\n";

   if(content_type != "")
      outbuf << "Content-Type: " << content_type << "\r\n";
   outbuf << "Connection: close\r\n\r\n";
   outbuf.write(reinterpret_cast<const char*>(body.data()), body.size());

   std::istringstream io(http_transact(hostname, outbuf.str()));

   std::string line1;
   std::getline(io, line1);
   if(!io || line1.empty())
      throw std::runtime_error("No response");

   std::stringstream response_stream(line1);
   std::string http_version;
   unsigned int status_code;
   std::string status_message;

   response_stream >> http_version >> status_code;

   std::getline(response_stream, status_message);

   if(!response_stream || http_version.substr(0,5) != "HTTP/")
      throw std::runtime_error("Not an HTTP response");

   std::map<std::string, std::string> headers;
   std::string header_line;
   while (std::getline(io, header_line) && header_line != "\r")
      {
      auto sep = header_line.find(": ");
      if(sep == std::string::npos || sep > header_line.size() - 2)
         throw std::runtime_error("Invalid HTTP header " + header_line);
      const std::string key = header_line.substr(0, sep);

      if(sep + 2 < header_line.size() - 1)
         {
         const std::string val = header_line.substr(sep + 2, (header_line.size() - 1) - (sep + 2));
         headers[key] = val;
         }
      }

   if(status_code == 301 && headers.count("Location"))
      {
      if(allowable_redirects == 0)
         throw std::runtime_error("HTTP redirection count exceeded");
      return GET_sync(headers["Location"], allowable_redirects - 1);
      }

   std::vector<byte> resp_body;
   std::vector<byte> buf(4096);
   while(io.good())
      {
      io.read(reinterpret_cast<char*>(buf.data()), buf.size());
      resp_body.insert(resp_body.end(), buf.data(), &buf[io.gcount()]);
      }

   const std::string header_size = search_map(headers, std::string("Content-Length"));

   if(header_size != "")
      {
      if(resp_body.size() != to_u32bit(header_size))
         throw std::runtime_error("Content-Length disagreement, header says " +
                                  header_size + " got " + std::to_string(resp_body.size()));
      }

   return Response(status_code, status_message, resp_body, headers);
   }

Response http_sync(const std::string& verb,
                   const std::string& url,
                   const std::string& content_type,
                   const std::vector<byte>& body,
                   size_t allowable_redirects)
   {
   return http_sync(
#if defined(BOTAN_HAS_BOOST_ASIO)
      http_transact_asio,
#else
      http_transact_fail,
#endif
      verb,
      url,
      content_type,
      body,
      allowable_redirects);
   }

Response GET_sync(const std::string& url, size_t allowable_redirects)
   {
   return http_sync("GET", url, "", std::vector<byte>(), allowable_redirects);
   }

Response POST_sync(const std::string& url,
                   const std::string& content_type,
                   const std::vector<byte>& body,
                   size_t allowable_redirects)
   {
   return http_sync("POST", url, content_type, body, allowable_redirects);
   }

std::future<Response> GET_async(const std::string& url, size_t allowable_redirects)
   {
   return std::async(std::launch::async, GET_sync, url, allowable_redirects);
   }

}

}
