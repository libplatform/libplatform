#include <platform/platform.h>
#include "platform_internal.h"

#ifdef WIN64

//
// Win32 data structures. Define these here to avoid windows.h include
//

extern "C" {

// LLP64 model: WORD is 16 bit, DWORD is 32, LONG is 32, LONGLONG is 64, etc.

typedef platform::u16 WORD;
typedef platform::u32 DWORD;
typedef platform::u32 ULONG;
typedef platform::i32 LONG;
typedef void* PVOID;

typedef struct _LIST_ENTRY* PLIST_ENTRY;

typedef struct _LIST_ENTRY
{
     PLIST_ENTRY Flink;
     PLIST_ENTRY Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _RTL_CRITICAL_SECTION* PRTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
     WORD Type;
     WORD CreatorBackTraceIndex;
     PRTL_CRITICAL_SECTION CriticalSection;
     LIST_ENTRY ProcessLocksList;
     ULONG EntryCount;
     ULONG ContentionCount;
     ULONG Flags;
     WORD CreatorBackTraceIndexHigh;
     WORD SpareUSHORT;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION
{
     PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
     LONG LockCount;
     LONG RecursionCount;
     PVOID OwningThread;
     PVOID LockSemaphore;
     ULONG SpinCount;
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

typedef RTL_CRITICAL_SECTION CRITICAL_SECTION;

//
// Win32 function pointers. We load these rather than linking directly
// so that the platform library can stay ELF64.
//

typedef void (__stdcall *InitializeCriticalSectionProc)(CRITICAL_SECTION*);
InitializeCriticalSectionProc InitializeCriticalSection;
typedef void (__stdcall *InitializeCriticalSectionAndSpinCountProc)(CRITICAL_SECTION*,DWORD);
InitializeCriticalSectionAndSpinCountProc InitializeCriticalSectionAndSpinCount;

} // extern "C"

namespace platform {


error_return<ssize_t> file_write(file fd, const i8* buffer, size_t size)
{

}

error_return<ssize_t> file_read(file fd, i8* buffer, size_t size)
{

}

error_return<void> file_close(file& fd)
{

}

error_return<file> file_open(const path& p, u32 _flags, u32 _mode)
{

}

//
// Thread Local Storage (TLS)
//

tls_key::tls_key(tls_key::destroy d)
    : m_key(FlsAlloc(d))
{

}

// sizeof() must be 16
struct mutex_priv {
    thread owner;
    SRWLOCK lock;
};

mutex::mutex()
{
    InitializeCriticalSection((CRITICAL_SECTION*)&priv);
}

struct condition_variable_priv {
    CONDITION_VARIBLE cond;
};

error condition_variable::notify_one() noexcept
{

}

error condition_variable::notify_all() noexcept
{

}

error condition_variable::wait(mutex& locked_mutex) noexcept
{

}

unsigned _hardware_concurrency() noexcept
{
}

} // platform

#endif
