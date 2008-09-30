/*************************************************
* Pipe I/O for Unix Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PIPE_UNIXFD_H__
#define BOTAN_PIPE_UNIXFD_H__

#include <botan/pipe.h>

namespace Botan {

/*************************************************
* Unix I/O Operators for Pipe                    *
*************************************************/
int operator<<(int, Pipe&);
int operator>>(int, Pipe&);

}

#endif
