/*
* HTTP GET function
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/types.h>
#include <future>
#include <vector>
#include <map>
#include <chrono>
#include <string>

#ifndef BOTAN_UTILS_URLGET_H__
#define BOTAN_UTILS_URLGET_H__

namespace Botan {

struct http_response
   {
   unsigned int status_code;
   std::vector<byte> body;
   std::map<std::string, std::string> headers;
   };

BOTAN_DLL http_response sync_http_get(const std::string& url,
                                      std::chrono::milliseconds timeout);

BOTAN_DLL std::future<http_response> BOTAN_DLL async_http_get(const std::string& url);

}

#endif
