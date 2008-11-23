/**
* Win32 EntropySource Source File
* (C) 1999-2008 Jack Lloyd
*/

#include <botan/es_win32.h>
#include <botan/xor_buf.h>
#include <windows.h>
#include <tlhelp32.h>

namespace Botan {

/**
* Win32 slow poll using Tooltip32
*/
u32bit Win32_EntropySource::slow_poll(byte buf[], u32bit length)
   {
   if(length == 0)
      return 0;

   const u32bit MAX_ITEMS = length / 4;

   u32bit buf_i = 0;

   HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);

#define TOOLHELP32_ITER(DATA_TYPE, FUNC_FIRST, FUNC_NEXT) \
   {                                                      \
   u32bit items = 0;                                      \
   DATA_TYPE info;                                        \
   info.dwSize = sizeof(DATA_TYPE);                       \
   if(FUNC_FIRST(snapshot, &info))                        \
      {                                                   \
      do                                                  \
         {                                                \
         if(items++ > MAX_ITEMS) break;                   \
         buf_i = xor_into_buf(buf, buf_i, length, info);  \
         } while(FUNC_NEXT(snapshot, &info));             \
      }                                                   \
   }

   TOOLHELP32_ITER(MODULEENTRY32, Module32First, Module32Next);
   TOOLHELP32_ITER(PROCESSENTRY32, Process32First, Process32Next);
   TOOLHELP32_ITER(THREADENTRY32, Thread32First, Thread32Next);

#undef TOOLHELP32_ITER

   u32bit heap_lists_found = 0;
   HEAPLIST32 heap_list;
   heap_list.dwSize = sizeof(HEAPLIST32);

   const u32bit HEAP_LISTS_MAX = 32;
   const u32bit HEAP_OBJS_PER_LIST = 128;
   if(Heap32ListFirst(snapshot, &heap_list))
      {
      do
         {
         buf_i = xor_into_buf(buf, buf_i, length, heap_list);

         if(heap_lists_found++ > HEAP_LISTS_MAX)
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
               buf_i = xor_into_buf(buf, buf_i, length, heap_entry);
               } while(Heap32Next(&heap_entry));
            }
         } while(Heap32ListNext(snapshot, &heap_list));
      }

   CloseHandle(snapshot);

   return length;
   }

/**
* Win32 fast poll
*/
u32bit Win32_EntropySource::fast_poll(byte buf[], u32bit length)
   {
   if(length == 0)
      return 0;
   length = std::min<u32bit>(length, 32);

   u32bit buf_i = 0;

   u32bit stats[] = {
      GetTickCount(),
      GetMessagePos(),
      GetMessageTime(),
      GetInputState(),
      GetCurrentProcessId(),
      GetCurrentThreadId()
   };

   for(u32bit i = 0; i != sizeof(stats) / sizeof(stats[0]); ++i)
      buf_i = xor_into_buf(buf, buf_i, length, stats[i]);

   SYSTEM_INFO sys_info;
   GetSystemInfo(&sys_info);
   buf_i = xor_into_buf(buf, buf_i, length, sys_info);

   MEMORYSTATUS mem_info;
   GlobalMemoryStatus(&mem_info);
   buf_i = xor_into_buf(buf, buf_i, length, mem_info);

   POINT point;
   GetCursorPos(&point);
   buf_i = xor_into_buf(buf, buf_i, length, point);

   GetCaretPos(&point);
   buf_i = xor_into_buf(buf, buf_i, length, point);

   LARGE_INTEGER perf_counter;
   QueryPerformanceCounter(&perf_counter);
   buf_i = xor_into_buf(buf, buf_i, length, perf_counter);

   return length;
   }

}
