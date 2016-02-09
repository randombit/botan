/*
* Win32 EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/es_win32.h>
#include <windows.h>
#include <tlhelp32.h>

namespace Botan {

/**
* Win32 poll using stats functions including Tooltip32
*/
void Win32_EntropySource::poll(Entropy_Accumulator& accum)
   {
   /*
   First query a bunch of basic statistical stuff, though
   don't count it for much in terms of contributed entropy.
   */
   accum.add(GetTickCount(), BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);
   accum.add(GetMessagePos(), BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);
   accum.add(GetMessageTime(), BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);
   accum.add(GetInputState(), BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);

   accum.add(GetCurrentProcessId(), BOTAN_ENTROPY_ESTIMATE_STATIC_SYSTEM_DATA);
   accum.add(GetCurrentThreadId(), BOTAN_ENTROPY_ESTIMATE_STATIC_SYSTEM_DATA);

   SYSTEM_INFO sys_info;
   GetSystemInfo(&sys_info);
   accum.add(sys_info, BOTAN_ENTROPY_ESTIMATE_STATIC_SYSTEM_DATA);

   MEMORYSTATUSEX mem_info;
   GlobalMemoryStatusEx(&mem_info);
   accum.add(mem_info, BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);

   POINT point;
   GetCursorPos(&point);
   accum.add(point, BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);

   GetCaretPos(&point);
   accum.add(point, BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);

   /*
   Now use the Tooltip library to iterate throug various objects on
   the system, including processes, threads, and heap objects.
   */

   HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

#define TOOLHELP32_ITER(DATA_TYPE, FUNC_FIRST, FUNC_NEXT)        \
   if(!accum.polling_finished())                                 \
      {                                                          \
      DATA_TYPE info;                                            \
      info.dwSize = sizeof(DATA_TYPE);                           \
      if(FUNC_FIRST(snapshot, &info))                            \
         {                                                       \
         do                                                      \
            {                                                    \
            accum.add(info, BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA); \
            } while(FUNC_NEXT(snapshot, &info));                 \
         }                                                       \
      }

   TOOLHELP32_ITER(MODULEENTRY32, Module32First, Module32Next);
   TOOLHELP32_ITER(PROCESSENTRY32, Process32First, Process32Next);
   TOOLHELP32_ITER(THREADENTRY32, Thread32First, Thread32Next);

#undef TOOLHELP32_ITER

   if(!accum.polling_finished())
      {
      size_t heap_lists_found = 0;
      HEAPLIST32 heap_list;
      heap_list.dwSize = sizeof(HEAPLIST32);

      const size_t HEAP_LISTS_MAX = 32;
      const size_t HEAP_OBJS_PER_LIST = 128;

      if(Heap32ListFirst(snapshot, &heap_list))
         {
         do
            {
            accum.add(heap_list, BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);

            if(++heap_lists_found > HEAP_LISTS_MAX)
               break;

            size_t heap_objs_found = 0;
            HEAPENTRY32 heap_entry;
            heap_entry.dwSize = sizeof(HEAPENTRY32);
            if(Heap32First(&heap_entry, heap_list.th32ProcessID,
                           heap_list.th32HeapID))
               {
               do
                  {
                  if(heap_objs_found++ > HEAP_OBJS_PER_LIST)
                     break;
                  accum.add(heap_entry, BOTAN_ENTROPY_ESTIMATE_SYSTEM_DATA);
                  } while(Heap32Next(&heap_entry));
               }

            if(accum.polling_finished())
               break;

            } while(Heap32ListNext(snapshot, &heap_list));
         }
      }

   CloseHandle(snapshot);
   }

}
