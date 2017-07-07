#include <platform/platform.h>
#include "platform_internal.h"

extern "C" int __cxa_atexit(void (*)(void*), void*, void*)
{
    return 0;
}

namespace platform {

static unsigned ncpus = _hardware_concurrency();

unsigned hardware_concurrency() noexcept
{
    return ncpus;
}

void _init_tls(thread_priv& th)
{
    th.tls[tls_slot_self] = th.tls;
    th.tls[tls_slot_thread] = &th;
}

thread_key key_map[THREAD_MAX_KEYS];

extern "C" {

// main thread
static thread_priv main_thread;

__attribute__((noreturn)) void _platform_init(
        void* raw_args, int (*main)(int,char**,char**),
        const structors_array& array)
{
    _init_tls(main_thread);
    _set_tls(main_thread.tls);

    // run initializers
    init_fn* init = array.init_array;
    while (*++init) {
        (*init)();
    }

    // layout is
    // raw[0] -> int argc
    // raw[1] -> argv[0]
    // raw[argc+1] -> 0x0
    // raw[argc+2] -> envp[0]
    // raw[envp_end] -> 0x0
    void** raw = (void**)raw_args;

    i32 argc = (i32)(uintptr_t)raw[0];
    char** argv = (char**)raw + 1;
    char** envp = (char**)raw + argc + 2;

    _exit((*main)(argc, argv, envp));
}

void* __tls_get_addr()
{
     return 0;
}

} // extern C
} // platform
