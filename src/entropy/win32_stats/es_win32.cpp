/**
* Win32 EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/es_win32.h>
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
   accum.add(GetTickCount(), 0);
   accum.add(GetMessagePos(), 0);
   accum.add(GetMessageTime(), 0);
   accum.add(GetInputState(), 0);
   accum.add(GetCurrentProcessId(), 0);
   accum.add(GetCurrentThreadId(), 0);

   SYSTEM_INFO sys_info;
   GetSystemInfo(&sys_info);
   accum.add(sys_info, 1);

   MEMORYSTATUS mem_info;
   GlobalMemoryStatus(&mem_info);
   accum.add(mem_info, 1);

   POINT point;
   GetCursorPos(&point);
   accum.add(point, 1);

   GetCaretPos(&point);
   accum.add(point, 1);

   LARGE_INTEGER perf_counter;
   QueryPerformanceCounter(&perf_counter);
   accum.add(perf_counter, 0);

   /*
   Now use the Tooltip library to iterate throug various objects on
   the system, including processes, threads, and heap objects.
   */

   HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

#define TOOLHELP32_ITER(DATA_TYPE, FUNC_FIRST, FUNC_NEXT) \
   if(!accum.polling_goal_achieved())                     \
      {                                                   \
      DATA_TYPE info;                                     \
      info.dwSize = sizeof(DATA_TYPE);                    \
      if(FUNC_FIRST(snapshot, &info))                     \
         {                                                \
         do                                               \
            {                                             \
            accum.add(info, 1);                           \
            } while(FUNC_NEXT(snapshot, &info));          \
         }                                                \
      }

   TOOLHELP32_ITER(MODULEENTRY32, Module32First, Module32Next);
   TOOLHELP32_ITER(PROCESSENTRY32, Process32First, Process32Next);
   TOOLHELP32_ITER(THREADENTRY32, Thread32First, Thread32Next);

#undef TOOLHELP32_ITER

   if(!accum.polling_goal_achieved())
      {
      u32bit heap_lists_found = 0;
      HEAPLIST32 heap_list;
      heap_list.dwSize = sizeof(HEAPLIST32);

      const u32bit HEAP_LISTS_MAX = 32;
      const u32bit HEAP_OBJS_PER_LIST = 128;

      if(Heap32ListFirst(snapshot, &heap_list))
         {
         do
            {
            accum.add(heap_list, 1);

            if(++heap_lists_found > HEAP_LISTS_MAX)
               break;

            u32bit heap_objs_found = 0;
            HEAPENTRY32 heap_entry;
            heap_entry.dwSize = sizeof(HEAPENTRY32);
            if(Heap32First(&heap_entry, heap_list.th32ProcessID,
                           heap_list.th32HeapID))
               {
               do
                  {
                  if(heap_objs_found++ > HEAP_OBJS_PER_LIST)
                     break;
                  accum.add(heap_entry, 1);
                  } while(Heap32Next(&heap_entry));
               }

            if(accum.polling_goal_achieved())
               break;

            } while(Heap32ListNext(snapshot, &heap_list));
         }
      }

   CloseHandle(snapshot);
   }

}
