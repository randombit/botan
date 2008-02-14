/*************************************************
* Pipe I/O for Unix Header File                  *
* (C) 1999-2008 The Botan Project                *
*************************************************/

#ifndef BOTAN_EXT_PIPE_UNIXFD_H__
#define BOTAN_EXT_PIPE_UNIXFD_H__

#include <botan/pipe.h>

namespace Botan {

/*************************************************
* Unix I/O Operators for Pipe                    *
*************************************************/
int operator<<(int, Pipe&);
int operator>>(int, Pipe&);

}

#endif
