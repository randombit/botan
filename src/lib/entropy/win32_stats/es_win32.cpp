/*
* (C) 1999-2009,2016,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_win32.h>

#include <botan/rng.h>

#define NOMINMAX 1
#define _WINSOCKAPI_  // stop windows.h including winsock.h
#include <windows.h>

namespace Botan {

void Win32_EntropySource::gather(Entropy_Accumulator& acc) {
   // We assume all of the below is basically junk, so none of it is credited
   acc.add_T(::GetTickCount(), 0);
   acc.add_T(::GetMessagePos(), 0);
   acc.add_T(::GetMessageTime(), 0);
   acc.add_T(::GetInputState(), 0);

   acc.add_T(::GetCurrentProcessId(), 0);
   acc.add_T(::GetCurrentThreadId(), 0);

   SYSTEM_INFO sys_info{};
   ::GetSystemInfo(&sys_info);  // no return value
   acc.add_T(sys_info, 0);

   MEMORYSTATUSEX mem_info{};
   mem_info.dwLength = sizeof(mem_info);
   if(::GlobalMemoryStatusEx(&mem_info) != 0) {
      acc.add_T(mem_info, 0);
   }

   POINT point{};
   if(::GetCursorPos(&point) != 0) {
      acc.add_T(point, 0);
   }

   if(::GetCaretPos(&point) != 0) {
      acc.add_T(point, 0);
   }

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
}

}  // namespace Botan
