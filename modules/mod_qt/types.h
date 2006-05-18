/*************************************************
* Low Level Types Header File                    *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_TYPES_H__
#define BOTAN_TYPES_H__

#include <qglobal.h>

namespace Botan {

typedef Q_UINT8 byte;
typedef Q_UINT16 u16bit;
typedef Q_UINT32 u32bit;
typedef Q_UINT64 u64bit;

typedef Q_INT32 s32bit;
}

namespace Botan_types {

typedef Botan::byte byte;
typedef Botan::u32bit u32bit;

}

#endif
