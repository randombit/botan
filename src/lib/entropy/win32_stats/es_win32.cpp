/*
* Win32 EntropySource
* (C) 1999-2009,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_win32.h>

#define NOMINMAX 1
#define _WINSOCKAPI_ // stop windows.h including winsock.h
#include <windows.h>
#include <tlhelp32.h>

namespace Botan {

/**
* Win32 poll using stats functions including Tooltip32
*/
size_t Win32_EntropySource::poll(RandomNumberGenerator& rng)
   {
   /*
   First query a bunch of basic statistical stuff
   */
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
   Now use the Tooltip library to iterate through various objects on
   the system, including processes, threads, and heap objects.
   */

   HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
   size_t bits = 0;

#define TOOLHELP32_ITER(DATA_TYPE, FUNC_FIRST, FUNC_NEXT)        \
   if(bits < 256)                                                \
      {                                                          \
      DATA_TYPE info;                                            \
      info.dwSize = sizeof(DATA_TYPE);                           \
      if(FUNC_FIRST(snapshot, &info))                            \
         {                                                       \
         do                                                      \
            {                                                    \
            rng.add_entropy_T(info);                             \
            bits += 4;                                           \
            } while(FUNC_NEXT(snapshot, &info));                 \
         }                                                       \
      }

   TOOLHELP32_ITER(MODULEENTRY32, ::Module32First, ::Module32Next);
   TOOLHELP32_ITER(PROCESSENTRY32, ::Process32First, ::Process32Next);
   TOOLHELP32_ITER(THREADENTRY32, ::Thread32First, ::Thread32Next);

#undef TOOLHELP32_ITER

   if(bits <= 256)
      {
      HEAPLIST32 heap_list;
      heap_list.dwSize = sizeof(HEAPLIST32);

      if(::Heap32ListFirst(snapshot, &heap_list))
         {
         do
            {
            rng.add_entropy_T(heap_list);

            HEAPENTRY32 heap_entry;
            heap_entry.dwSize = sizeof(HEAPENTRY32);
            if(::Heap32First(&heap_entry,
                             heap_list.th32ProcessID,
                             heap_list.th32HeapID))
               {
               do
                  {
                  rng.add_entropy_T(heap_entry);
                  bits += 4;
                  } while(::Heap32Next(&heap_entry));
               }

            if(bits >= 256)
               break;

            } while(::Heap32ListNext(snapshot, &heap_list));
         }
      }

   ::CloseHandle(snapshot);

   return bits;
   }

}
