/*************************************************
* Win32 EntropySource Source File                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#include <botan/es_win32.h>
#include <windows.h>
#include <tlhelp32.h>

namespace Botan {

/*************************************************
* Win32 Slow Poll                                *
*************************************************/
void Win32_EntropySource::do_slow_poll()
   {
   const u32bit MAX_ITEMS = 256;

   do_fast_poll();

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
         add_bytes(&info, sizeof(info));                  \
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
         add_bytes(&heap_list, sizeof(HEAPLIST32));

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
               add_bytes(&heap_entry, sizeof(HEAPENTRY32));
               } while(Heap32Next(&heap_entry));
            }
         } while(Heap32ListNext(snapshot, &heap_list));
      }

   CloseHandle(snapshot);
   }

/*************************************************
* Win32 Fast Poll                                *
*************************************************/
void Win32_EntropySource::do_fast_poll()
   {
   add_bytes(GetTickCount());
   add_bytes(GetMessagePos());
   add_bytes(GetMessageTime());
   add_bytes(GetInputState());
   add_bytes(GetCurrentProcessId());
   add_bytes(GetCurrentThreadId());

   SYSTEM_INFO sys_info;
   GetSystemInfo(&sys_info);
   add_bytes(&sys_info, sizeof(sys_info));

   MEMORYSTATUS mem_info;
   GlobalMemoryStatus(&mem_info);
   add_bytes(&mem_info, sizeof(mem_info));

   POINT point;
   GetCursorPos(&point);
   add_bytes(&point, sizeof(point));
   GetCaretPos(&point);
   add_bytes(&point, sizeof(point));
   }

}
