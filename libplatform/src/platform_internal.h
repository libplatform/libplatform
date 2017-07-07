#pragma once

#include <platform/platform.h>
#include <atomic>

namespace platform {

#define inline_func __attribute__((always_inline)) inline

/// Exit a thread or process
__attribute__((noreturn)) __attribute__((always_inline))
void _exit(i32 status);


enum thread_state : u32 {
    thread_state_joined,            ///< Thread is done running
    thread_state_not_joined,        ///< Thread is not yet joined (process is still active)
};

constexpr size_t stack_size = 8192 * 1024; // 8M

enum {
    tls_slot_self = 0, // required by kernel
    tls_slot_thread,  // the thread_priv*

    platform_tls_slots, // must be last
};

#define THREAD_MAX_KEYS 128

struct alignas(sizeof(void*)) thread_key {
    std::atomic<i32> seq{0};
    i32 pad;
    void (*destructor)(void*){0};
};

struct alignas(sizeof(void*)) thread_data {
    i32 seq{0}, pad;
    void* data;
};

// dynamic tls keys
extern thread_key key_map[THREAD_MAX_KEYS];

struct thread_priv {
    i32 tid;
    std::atomic<thread_state> state;

    void* mem_base;
    size_t mem_size;

    void* stack_top, *stack_base;
    size_t stack_size;

    void *(*user_func)(void*);
    void *user_param;

    thread_data key_data[THREAD_MAX_KEYS];

    void* tls[platform_tls_slots];
};

void _set_tls(void* tls);
void _init_tls(thread_priv& th);

template <typename Error>
inline void convert_error(i64 raw, error_return<void,Error>& e)
{
    if (raw < 0) {
        e.error = error_unknown;
    }
}

template <typename Return, typename Error>
inline void convert_error(i64 raw, error_return<Return,Error>& e)
{
    if (raw < 0) {
        e.error = error_unknown;
        e.assign(Return());
    } else {
        e.assign(Return(raw));
    }
}

inline_func error_return<ssize_t>
validate_file_write(file fd, const i8* buffer, size_t size)
{
    error_return<ssize_t> ret;
    if (!fd || (size > 0 && !buffer)) {
        ret.error = error_invalid_arguments;
        return ret;
    }

    // if no size, we're done
    if (size == 0) {
        ret.ret = 0;
        return ret;
    }

    return ret;
}

inline_func error_return<ssize_t>
validate_file_read(file fd, i8* buffer, size_t size)
{
    error_return<ssize_t> ret;

    // if fd is invalid or size > 0 and no buffer, arguments are invalid
    if (!fd || (size > 0 && !buffer)) {
        ret.error = error_invalid_arguments;
        return ret;
    }

    return ret;
}

inline_func error_return<file>
validate_file_open(const path& p, u32 flags)
{
    error_return<file> ret;
    if (!p) {
        ret.error = error_invalid_arguments;
    }

    if (p.str[0] != '/') {
        ret.error = error_path_not_absolute;
    }

    if (ret.error) return ret;

    // validate flags, looking for error combinations
    if (!(flags & file_flag_write)) {
        if ((flags & (file_flag_append | file_flag_create))) {
            ret.error = error_invalid_arguments;
        }
    }

    return ret;
}

unsigned _hardware_concurrency() noexcept;

} // platform

//
// Program Initialization and ELF64 ABI
//

typedef void (*init_fn)(void);

struct structors_array {
    init_fn* preinit_array;
    init_fn* init_array;
    init_fn* fini_array;
};

extern "C" __attribute__((noreturn))
void _platform_init(void* raw_args,
                    int (*main)(int,char**,char**),
                    const structors_array& array);

extern "C" int __cxa_atexit(void (*)(void*), void*, void*);

