/*
* (C) 2019 Nuno Goncalves <nunojpg@gmail.com>
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/uri.h>

#include <botan/exceptn.h>
#include <botan/internal/fmt.h>
#include <regex>

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS)
   #include <arpa/inet.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
#elif defined(BOTAN_TARGET_OS_HAS_WINSOCK2)
   #include <ws2tcpip.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_SOCKETS) || defined(BOTAN_TARGET_OS_HAS_WINSOCK2)

namespace {

constexpr bool isdigit(char ch)
   {
   return ch >= '0' && ch <= '9';
   }

bool isDomain(std::string_view domain)
   {
   std::string domain_str(domain);
   std::regex re(
      R"(^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$)");
   std::cmatch m;
   return std::regex_match(domain_str.c_str(), m, re);
   }

bool isIPv4(std::string_view ip)
   {
   std::string ip_str(ip);
   sockaddr_storage inaddr;
   return !!inet_pton(AF_INET, ip_str.c_str(), &inaddr);
   }

bool isIPv6(std::string_view ip)
   {
   std::string ip_str(ip);
   sockaddr_storage in6addr;
   return !!inet_pton(AF_INET6, ip_str.c_str(), &in6addr);
   }

}

namespace Botan {

URI URI::from_domain(std::string_view uri)
   {
   uint32_t port = 0;
   const auto port_pos = uri.find(':');
   if(port_pos != std::string::npos)
      {
      for(char c : uri.substr(port_pos+1))
         {
         if(!isdigit(c))
            { throw Invalid_Argument(fmt("URI::from_domain invalid port field in {}", uri)); }
         port = port*10 + (c - '0');
         if(port > 65535)
            { throw Invalid_Argument(fmt("URI::from_domain invalid port field in {}", uri)); }
         }
      }
   const auto domain = uri.substr(0, port_pos);
   if(isIPv4(domain))
      throw Invalid_Argument("URI::from_domain domain name should not be IP address");
   if(!isDomain(domain))
      throw Invalid_Argument("URI::from_domain domain name not valid");

   return URI(Type::Domain, domain, uint16_t(port));
   }

URI URI::from_ipv4(std::string_view uri)
   {
   uint32_t port = 0;
   const auto port_pos = uri.find(':');
   if(port_pos != std::string::npos)
      {
      for(char c : uri.substr(port_pos+1))
         {
         if(!isdigit(c))
            { throw Invalid_Argument("invalid"); }
         port = port*10 + c - '0';
         if(port > 65535)
            { throw Invalid_Argument("invalid"); }
         }
      }
   const auto ip = uri.substr(0, port_pos);
   if(!isIPv4(ip))
      { throw Invalid_Argument("invalid"); }
   return { Type::IPv4, ip, uint16_t(port) };
   }

URI URI::from_ipv6(std::string_view uri)
   {
   uint32_t port = 0;
   const auto port_pos = uri.find(']');
   const bool with_braces = (port_pos != std::string::npos);
   if((uri[0]=='[') != with_braces)
      { throw Invalid_Argument("invalid"); }

   if(with_braces && (uri.size() > port_pos + 1))
      {
      if(uri[port_pos+1]!=':')
         { throw Invalid_Argument("invalid"); }
      for(char c : uri.substr(port_pos+2))
         {
         if(!isdigit(c))
            { throw Invalid_Argument("invalid"); }
         port = port*10 + c - '0';
         if(port > 65535)
            { throw Invalid_Argument("invalid"); }
         }
      }
   const auto ip = uri.substr((with_braces ? 1 : 0), port_pos - with_braces);
   if(!isIPv6(ip))
      { throw Invalid_Argument("invalid"); }
   return { Type::IPv6, ip, uint16_t(port) };
   }

URI URI::from_any(std::string_view uri)
   {
   bool colon_seen = false;
   bool non_number = false;
   if(uri[0]=='[')
      { return URI::from_ipv6(uri); }
   for(auto c : uri)
      {
      if(c == ':')
         {
         if(colon_seen) //seen two ':'
            { return URI::from_ipv6(uri); }
         colon_seen = true;
         }
      else if(!isdigit(c) && c !=  '.')
         {
         non_number=true;
         }
      }
   if(!non_number)
      {
      if(isIPv4(uri.substr(0, uri.find(':'))))
         {
         return from_ipv4(uri);
         }
      }
   return from_domain(uri);
   }

std::string URI::to_string() const
   {
   if(m_port != 0)
      {
      if(m_type == Type::IPv6)
         { return "[" + m_host + "]:" + std::to_string(m_port); }
      return m_host + ":" + std::to_string(m_port);
      }
   return m_host;
   }

}

#else

namespace Botan {

URI URI::from_domain(std::string_view) {throw Not_Implemented("No socket support enabled in build");}
URI URI::from_ipv4(std::string_view) {throw Not_Implemented("No socket support enabled in build");}
URI URI::from_ipv6(std::string_view) {throw Not_Implemented("No socket support enabled in build");}
URI URI::from_any(std::string_view) {throw Not_Implemented("No socket support enabled in build");}

}

#endif
