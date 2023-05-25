/*
* (C) 1999-2009,2016,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_win32.h>

#define NOMINMAX 1
#define _WINSOCKAPI_  // stop windows.h including winsock.h
#include <windows.h>

namespace Botan {

size_t Win32_EntropySource::poll(RandomNumberGenerator& rng) {
   rng.add_entropy_T(::GetTickCount());
   rng.add_entropy_T(::GetMessagePos());
   rng.add_entropy_T(::GetMessageTime());
   rng.add_entropy_T(::GetInputState());

   rng.add_entropy_T(::GetCurrentProcessId());
   rng.add_entropy_T(::GetCurrentThreadId());

   SYSTEM_INFO sys_info;
   ::GetSystemInfo(&sys_info);
   rng.add_entropy_T(sys_info);

   MEMORYSTATUSEX mem_info;
   ::GlobalMemoryStatusEx(&mem_info);
   rng.add_entropy_T(mem_info);

   POINT point;
   ::GetCursorPos(&point);
   rng.add_entropy_T(point);

   ::GetCaretPos(&point);
   rng.add_entropy_T(point);

   /*
   Potential other sources to investigate

   GetProductInfo
   GetComputerNameExA
   GetSystemFirmwareTable
   GetVersionExA
   GetProcessorSystemCycleTime
   GetProcessHandleCount(GetCurrentProcess())
   GetThreadTimes(GetCurrentThread())
   QueryThreadCycleTime
   QueryIdleProcessorCycleTime
   QueryUnbiasedInterruptTime
   */

   // We assume all of the above is basically junk
   return 0;
}

}  // namespace Botan
