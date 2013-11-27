/*
* HTTP GET function
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/http_get.h>
#include <botan/parsing.h>
#include <boost/asio.hpp>

namespace Botan {

http_response sync_http_get(const std::string& url, std::chrono::milliseconds timeout)
   {
   using namespace boost::asio::ip;

   const auto protocol_host_sep = url.find("://");
   const auto host_loc_sep = url.find('/', protocol_host_sep + 3);

   if(protocol_host_sep == std::string::npos || host_loc_sep == std::string::npos)
      throw std::runtime_error("Invalid URL " + url);

   const std::string protocol = url.substr(0, protocol_host_sep);
   const std::string hostname = url.substr(protocol_host_sep+3, host_loc_sep-protocol_host_sep-3);
   const std::string loc = url.substr(host_loc_sep, std::string::npos);

   if(protocol != "http")
      throw std::runtime_error("Unsupported protocol " + protocol);

   tcp::iostream sock;

   if(timeout.count())
      sock.expires_from_now(boost::posix_time::milliseconds(timeout.count()));

   sock.connect(hostname, protocol);
   if(!sock)
      throw std::runtime_error("Connection to " + hostname + " / " + protocol + " failed");

   sock << "GET " << loc << " HTTP/1.0\r\n";
   sock << "Host: " << hostname << "\r\n";
   sock << "Accept: */*\r\n";
   sock << "Cache-Control: no-cache\r\n";
   sock << "Connection: close\r\n\r\n";
   sock.flush();

   std::string line1;
   std::getline(sock, line1);
   if(!sock)
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
   while (std::getline(sock, header_line) && header_line != "\r")
      {
      auto sep = header_line.find(": ");
      if(sep == std::string::npos || sep > header_line.size() - 2)
         throw std::runtime_error("Invalid HTTP header " + header_line);
      const std::string key = header_line.substr(0, sep);
      const std::string val = header_line.substr(sep + 2, std::string::npos);
      headers[key] = val;
      }

   if(status_code == 301 && headers.count("Location"))
      return sync_http_get(headers["Location"], timeout);

   std::vector<byte> body;
   std::vector<byte> buf(4096);
   while(sock.good())
      {
      sock.read(reinterpret_cast<char*>(&buf[0]), buf.size());
      body.insert(body.end(), &buf[0], &buf[sock.gcount()]);
      }

   return http_response { status_code, body, headers };
   }

std::future<http_response> async_http_get(const std::string& url)
   {
   return std::async(std::launch::async, sync_http_get, url, std::chrono::seconds(3));
   }

}
