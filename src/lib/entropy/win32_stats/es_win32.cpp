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

size_t Win32_EntropySource::poll(RandomNumberGenerator& rng) {
   // We assume all of the below is basically junk, so none of it is credited
   constexpr Entropy_Estimate uncounted(Entropy_Estimate::Bits(0));

   rng.add_entropy_T(::GetTickCount(), uncounted);
   rng.add_entropy_T(::GetMessagePos(), uncounted);
   rng.add_entropy_T(::GetMessageTime(), uncounted);
   rng.add_entropy_T(::GetInputState(), uncounted);

   rng.add_entropy_T(::GetCurrentProcessId(), uncounted);
   rng.add_entropy_T(::GetCurrentThreadId(), uncounted);

   SYSTEM_INFO sys_info{};
   ::GetSystemInfo(&sys_info);  // no return value
   rng.add_entropy_T(sys_info, uncounted);

   MEMORYSTATUSEX mem_info{};
   mem_info.dwLength = sizeof(mem_info);
   if(::GlobalMemoryStatusEx(&mem_info) != 0) {
      rng.add_entropy_T(mem_info, uncounted);
   }

   POINT point{};
   if(::GetCursorPos(&point) != 0) {
      rng.add_entropy_T(point, uncounted);
   }

   if(::GetCaretPos(&point) != 0) {
      rng.add_entropy_T(point, uncounted);
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

   // We assume all of the above is basically junk
   return 0;
}

}  // namespace Botan
