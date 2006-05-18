/*************************************************
* Configuration Handling Header File             *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_POLICY_CONF_H__
#define BOTAN_POLICY_CONF_H__

#include <botan/types.h>
#include <botan/enums.h>
#include <string>
#include <vector>

namespace Botan {

class Library_State;

namespace Config {

/*************************************************
* Load a configuration file                      *
*************************************************/
void load(const std::string&);
void load(const std::string&, Library_State&);

/*************************************************
* Set an option                                  *
*************************************************/
void set(const std::string&, const std::string&, bool = true);

/*************************************************
* Get the value of some option                   *
*************************************************/
std::vector<std::string> get_list(const std::string&);
std::string              get_string(const std::string&);
u32bit                   get_u32bit(const std::string&);
u32bit                   get_time(const std::string&);
bool                     get_bool(const std::string&);

/*************************************************
* Choose the signature format for a PK algorithm *
*************************************************/
void choose_sig_format(const std::string&, std::string&, Signature_Format&);
void choose_sig_format(const std::string&, std::string&, std::string&,
                       Signature_Format&);

}

}

#endif
