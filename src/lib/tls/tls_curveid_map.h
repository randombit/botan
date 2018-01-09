/*
* TLS global curveid map for custom curves
* (C) 2018 Tobias Niemann
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef TLS_CURVEID_MAP_H
#define TLS_CURVEID_MAP_H

#include <string>

namespace Botan {

namespace TLS {

namespace CurveIDS{

/**
* Register custom CurveID to name
* @param name the name of the curve to register
* @param curveid the TLS curve identifier
*/
void add_curveid(const std::string name, const uint16_t curveid);
      
/**
* Lookup a custom curve id
* @param curveid the custom TLS curve identifier to lookup
* @return name associated with this TLS curve identifier or empty string if not found
*/
std::string lookup(const uint16_t curveid);
      
/**
* Lookup a custom curve name
* @param name the name to lookup
* @return TLS curve identifier associated with name or 0 if not found
*/
uint16_t lookup(const std::string name);
    
}
}
}
#endif

