/*
* Pipe I/O for Unix
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_PIPE_UNIXFD_H__
#define BOTAN_PIPE_UNIXFD_H__

#include <botan/pipe.h>

namespace Botan {

/*
* Unix I/O Operators for Pipe
*/
int operator<<(int, Pipe&);
int operator>>(int, Pipe&);

}

#endif
