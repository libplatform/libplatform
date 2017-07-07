#define package public
#include <platform/platform.h>
#include "platform_internal.h"
#include <atomic>
#include <c/libc.h>

#ifdef LINUX64

namespace platform {

enum : i32 {
    sys_read                   = 0,
    sys_write                  = 1,
    sys_open                   = 2,
    sys_close                  = 3,
    sys_mmap                   = 9,
    sys_munmap                 = 11,
    sys_clone                  = 56,
    sys_exit                   = 60,
    sys_arch_prctl             = 158,
    sys_futex                  = 202,
    sys_clock_gettime          = 228,
    sys_clock_nanosleep        = 230,
};

enum : u32 {
    O_RDONLY    = 00000000,
    O_WRONLY    = 00000001,
    O_RDWR      = 00000002,
    O_CREAT     = 00000100,
    O_EXCL      = 00000200,
    O_NOCTTY    = 00000400,
    O_TRUNC     = 00001000,
};

enum : u32 {
    S_IRWXU     = 00700,
    S_IRUSR     = 00400,
    S_IWUSR     = 00200,
    S_IXUSR     = 00100,
    S_IRWXG     = 00070,
    S_IRGRP     = 00040,
    S_IWGRP     = 00020,
    S_IXGRP     = 00010,
    S_IRWXO     = 00007,
    S_IROTH     = 00004,
    S_IWOTH     = 00002,
    S_IXOTH     = 00001,
};

enum : u32 {
    PROT_NONE         = 0x0,             /* page can not be accessed */
    PROT_READ         = 0x1,             /* page can be read */
    PROT_WRITE        = 0x2,             /* page can be written */
    PROT_EXEC         = 0x4,             /* page can be executed */
    PROT_SEM          = 0x8,             /* page may be used for atomic ops */

    MAP_SHARED        = 0x01,            /* Share changes */
    MAP_PRIVATE       = 0x02,            /* Changes are private */
    MAP_TYPE          = 0x0f,            /* Mask for type of mapping */
    MAP_FIXED         = 0x10,            /* Interpret addr exactly */
    MAP_ANONYMOUS     = 0x20,            /* don't use a file */
    MAP_GROWSDOWN     = 0x0100,          /* mprotect flag: extend change to start of growsdown vma */

    MAP_UNINITIALIZED = 0x4000000,       /* For anonymous mmap, memory could be uninitialized */
};

enum : u32 {
    CLONE_VM                = 0x00000100,     /* set if VM shared between processes */
    CLONE_FS                = 0x00000200,     /* set if fs info shared between processes */
    CLONE_FILES             = 0x00000400,     /* set if open files shared between processes */
    CLONE_SIGHAND           = 0x00000800,     /* set if signal handlers and blocked signals shared */
    CLONE_PTRACE            = 0x00002000,     /* set if we want to let tracing continue on the child too */
    CLONE_VFORK             = 0x00004000,     /* set if the parent wants the child to wake it up on mm_release */
    CLONE_PARENT            = 0x00008000,     /* set if we want to have the same parent as the cloner */
    CLONE_THREAD            = 0x00010000,     /* Same thread group? */
    CLONE_NEWNS             = 0x00020000,     /* New mount namespace group */
    CLONE_SYSVSEM           = 0x00040000,     /* share system V SEM_UNDO semantics */
    CLONE_SETTLS            = 0x00080000,     /* create a new TLS for the child */
    CLONE_PARENT_SETTID     = 0x00100000,     /* set the TID in the parent */
    CLONE_CHILD_CLEARTID    = 0x00200000,     /* clear the TID in the child */
    CLONE_DETACHED          = 0x00400000,     /* Unused, ignored */
    CLONE_UNTRACED          = 0x00800000,     /* set if the tracing process can't force CLONE_PTRACE on this clone */
    CLONE_CHILD_SETTID      = 0x01000000,     /* set the TID in the child */
    CLONE_NEWCGROUP         = 0x02000000,     /* New cgroup namespace */
    CLONE_NEWUTS            = 0x04000000,     /* New utsname namespace */
    CLONE_NEWIPC            = 0x08000000,     /* New ipc namespace */
    CLONE_NEWUSER           = 0x10000000,     /* New user namespace */
    CLONE_NEWPID            = 0x20000000,     /* New pid namespace */
    CLONE_NEWNET            = 0x40000000,     /* New network namespace */
    CLONE_IO                = 0x80000000,     /* Clone io context */
};

enum : u32 {
    FUTEX_WAIT              = 0,
    FUTEX_WAKE              = 1,
    FUTEX_PRIVATE_FLAG      = 128,
};

enum : u32 {
    ARCH_SET_FS             = 0x1002,
};

enum : u32 {
    CLOCK_REALTIME          = 0,
    CLOCK_MONOTONIC         = 1,
};

enum : u32 {
    EPERM       = 1,    /* Operation not permitted */
    ENOENT      = 2,    /* No such file or directory */
    ESRCH       = 3,    /* No such process */
    EINTR       = 4,    /* Interrupted system call */
    EIO         = 5,    /* I/O error */
    ENXIO       = 6,    /* No such device or address */
    E2BIG       = 7,    /* Argument list too long */
    ENOEXEC     = 8,    /* Exec format error */
    EBADF       = 9,    /* Bad file number */
    ECHILD      = 10,   /* No child processes */
    EAGAIN      = 11,   /* Try again */
    ENOMEM      = 12,   /* Out of memory */
    EACCES      = 13,   /* Permission denied */
    EFAULT      = 14,   /* Bad address */
    ENOTBLK     = 15,   /* Block device required */
    EBUSY       = 16,   /* Device or resource busy */
    EEXIST      = 17,   /* File exists */
    EXDEV       = 18,   /* Cross-device link */
    ENODEV      = 19,   /* No such device */
    ENOTDIR     = 20,   /* Not a directory */
    EISDIR      = 21,   /* Is a directory */
    EINVAL      = 22,   /* Invalid argument */
    ENFILE      = 23,   /* File table overflow */
    EMFILE      = 24,   /* Too many open files */
    ENOTTY      = 25,   /* Not a typewriter */
    ETXTBSY     = 26,   /* Text file busy */
    EFBIG       = 27,   /* File too large */
    ENOSPC      = 28,   /* No space left on device */
    ESPIPE      = 29,   /* Illegal seek */
    EROFS       = 30,   /* Read-only file system */
    EMLINK      = 31,   /* Too many links */
    EPIPE       = 32,   /* Broken pipe */
    EDOM        = 33,   /* Math argument out of domain of func */
    ERANGE      = 34,   /* Math result not representable */
};

error convert_error(i64 raw)
{
    // convert unix/syscall errors into our error values
    return error_unknown;
}

template <typename R, typename A0>
__attribute__((always_inline)) R syscall(u32 call, A0&& a0)
{
    R ret;
    asm volatile("syscall\n":"=a"(ret):"a"(call), "D"(a0) : "rcx", "r11");
    return ret;
}
template <typename R, typename A0, typename A1>
__attribute__((always_inline)) R syscall(u32 call, A0&& a0, A1&& a1)
{
    R ret;
    asm volatile("syscall\n":"=a"(ret):"a"(call), "D"(a0), "S"(a1) : "rcx", "r11");
    return ret;
}
template <typename R, typename A0, typename A1, typename A2>
__attribute__((always_inline)) R syscall(u32 call, A0&& a0, A1&& a1, A2&& a2)
{
    R ret;
    asm volatile("syscall\n":"=a"(ret):"a"(call), "D"(a0), "S"(a1), "d"(a2) : "rcx", "r11");
    return ret;
}
template <typename R, typename A0, typename A1, typename A2, typename A3>
__attribute__((always_inline)) R syscall(u32 call, A0&& a0, A1&& a1, A2&& a2, A3&& a3)
{
    R ret;
    const register A3 _a3 asm("r10") = a3;
    asm volatile("syscall\n":"=a"(ret):"a"(call), "D"(a0), "S"(a1), "d"(a2), "g"(_a3) : "rcx", "r11");
    return ret;
}
template <typename R, typename A0, typename A1, typename A2, typename A3, typename A4>
__attribute__((always_inline)) R syscall(u32 call, A0&& a0, A1&& a1, A2&& a2, A3&& a3, A4&& a4)
{
    R ret;
    const register A3 _a3 asm("r10") = a3;
    const register A4 _a4 asm("r8") = a4;
    asm volatile("syscall\n":"=a"(ret):"a"(call), "D"(a0), "S"(a1), "d"(a2), "g"(_a3), "g"(_a4) : "rcx", "r11");
    return ret;
}
template <typename R, typename A0, typename A1, typename A2, typename A3, typename A4, typename A5>
__attribute__((always_inline)) R syscall(u32 call, A0&& a0, A1&& a1, A2&& a2, A3&& a3, A4&& a4, A5&& a5)
{
    R ret;
    const register A3 _a3 asm("r10") = a3;
    const register A4 _a4 asm("r8") = a4;
    const register A5 _a5 asm("r9") = a5;
    asm volatile("syscall\n":"=a"(ret):"a"(call), "D"(a0), "S"(a1), "d"(a2), "g"(_a3), "g"(_a4), "g"(_a5) : "rcx", "r11");
    return ret;
}

__attribute__((noreturn)) __attribute__((always_inline))
void _exit(i32 status)
{
    asm volatile("syscall\n" "hlt"::"a"(sys_exit), "D"(status) : "rcx", "r11");

    // silence warning about noreturn function returning
    __builtin_unreachable();
}


//
// IO
//

error_return<ssize_t> file_write(file fd, const i8* buffer, size_t size)
{
    error_return<ssize_t> ret = validate_file_write(fd, buffer, size);
    if (!ret) return ret;
    convert_error(syscall<ssize_t>(sys_write, fd.fd, buffer, size), ret);
    return ret;
}

error_return<ssize_t> file_read(file fd, i8* buffer, size_t size)
{
    error_return<ssize_t> ret = validate_file_read(fd, buffer, size);
    if (!ret) return ret;

    // if no size, we're done
    if (size == 0) {
        ret.ret = 0;
        return ret;
    }

    convert_error(syscall<ssize_t>(sys_read, fd.fd, buffer, size), ret);
    return ret;
}

error_return<void> file_close(file& fd)
{
    error_return<void> ret;
    convert_error(syscall<i64>(sys_close, fd.fd), ret);
    fd = file();
    return ret;
}

error_return<file> file_open(const path& p, u32 _flags, u32 _mode)
{
    error_return<file> ret = validate_file_open(p, _flags);
    if (!ret) return ret;

    // convert flags
    u32 flags = 0;
    if ((_flags & file_flag_write)) {
        flags |= O_WRONLY;
        if ((_flags & file_flag_read)) { flags |= O_RDWR; }
        if (!(_flags & file_flag_append)) { flags |= O_TRUNC; }
    }
    if ((_flags & file_flag_create)) { flags |= O_CREAT; }

    // convert mode
    u16 mode = 0;
    if ((_mode & file_mode_default)) {
        // 0x775
        mode = S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH;
    }

    convert_error(syscall<i64>(sys_open, p.str, flags, mode), ret);
    return ret;
}

//
// Memory
//

error_return<void*> memory_map(const void* addr, size_t size, u32 _flags, const file& _file, size_t _off)
{
    error_return<void*> ret;

    // convert input arguments
    i32 prot = PROT_NONE;
    i32 flags = 0;
    i64 fd = -1;
    u64 off = 0;
    if ((_flags & memory_flags_read)) prot |= PROT_READ;
    if ((_flags & memory_flags_write)) prot |= PROT_WRITE;
    if ((_flags & memory_flags_execute)) prot |= PROT_EXEC;
    if ((_flags & memory_flags_growsdown)) flags |= MAP_GROWSDOWN;
    if ((_flags & memory_flags_anonymous)) flags |= MAP_ANONYMOUS;
    if ((_flags & memory_flags_private)) flags |= MAP_PRIVATE;
    if ((_flags & memory_flags_shared)) flags |= MAP_SHARED;
    if (!(_flags & memory_flags_anonymous) && _file) {
        fd = _file.fd;
        off = _off;
    }

    convert_error(syscall<i64>(sys_mmap, addr, size, prot, flags, fd, off), ret);
    return ret;
}

error_return<void> memory_unmap(const void* addr, size_t size)
{
    error_return<void> ret;
    if (!addr || !size) {
        ret.error = error_invalid_arguments;
        return ret;
    }

    convert_error(syscall<i64>(sys_munmap, addr, size), ret);
    return ret;
}

//
// Time
//

struct timespec {
    i64 sec;
    i64 nano;
};

error_return<nanoseconds> clock_gettime(clock_id c)
{
    error_return<nanoseconds> ret;

    if (c != clock_id_realtime) {
        return error_invalid_arguments;
    }

    // @todo use VDSO for this otherwise it's slow!!!

    timespec ts;
    convert_error(syscall<i32>(sys_clock_gettime, CLOCK_REALTIME, &ts), ret);
    ret.ret = ts.sec * u64(1000000000) + ts.nano;
    return ret;
}

//
// Threads
//

inline_func
i32 _sys_futex(volatile i32* futex, u32 value, u32 op)
{
    return syscall<i32>(sys_futex, futex, op | FUTEX_PRIVATE_FLAG, value, 0, 0, 0);
}

inline_func
i32 _sys_futex(std::atomic<i32>& futex, u32 value, u32 op)
{
    return _sys_futex((volatile i32*)&futex, value, op);
}

extern "C" {

__attribute__((noreturn))
void __thread_start(void* p)
{
    thread_priv* priv = (thread_priv*)p;

    if (priv->user_func) {
        (*priv->user_func)(priv->user_param);
    }

    // the kernel should do this with CLONE_CHILD_CLEARTID, but it doesn't seem
    // to work all the time
    priv->tid = 0;
    _sys_futex(&priv->tid, INT32_MAX, FUTEX_WAKE);

    _exit(0);
}

} // extern "C"

void _set_tls(void* tls)
{
    asm volatile(
         "syscall"
         :
         :"a"(sys_arch_prctl),
          "D"(ARCH_SET_FS),
          "S"(tls)
         :"memory", "cc", "r11", "cx"
    );
}

error_return<thread> thread_create(void *(*func)(void*), void* param, u32)
{
    error_return<thread> ret;

    // create thread_priv structure
    error_return<void*> priv_mem = memory_map(0, sizeof(thread_priv),
                                              memory_flags_anonymous | memory_flags_rw |
                                              memory_flags_private, file(), 0);
    if (!priv_mem) {
        ret.error = error_nomem;
        return ret;
    }

    thread_priv* priv = (thread_priv*)priv_mem.ret;

    // create stack
    const u32 stack_flags = memory_flags_anonymous |
                      memory_flags_private | memory_flags_rw |
                      memory_flags_execute | memory_flags_growsdown;
    error_return<void*> mem = memory_map(0, stack_size, stack_flags, file(), 0);
    if (!mem) {
        ret.error = error_nomem;
        return ret;
    }

    priv->mem_base = priv_mem.ret;
    priv->mem_size = sizeof(thread_priv);
    priv->stack_base = mem.ret;
    priv->stack_size = stack_size;
    priv->stack_top = (char *)priv->stack_base + stack_size - sizeof(func);
    priv->stack_top = (void*)((uintptr_t)priv->stack_top & ~0xf); // align to 16 bytes
    priv->user_func = func;
    priv->user_param = param;
    priv->state = thread_state_not_joined;

    _init_tls(*priv);

    // put a pointer to priv at the top of the child stack
    *((void**)priv->stack_top) = priv;

    // clone the thread process
    const u32 clone_flags = CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID |
                            CLONE_FS | CLONE_THREAD | CLONE_SIGHAND |
                            CLONE_VM | CLONE_FILES | CLONE_SETTLS;
    syscall<i64>(sys_clone, clone_flags, priv->stack_top, &priv->tid, &priv->tid, &priv->tls);

    // can't store result on the parent stack as this isn't visible to the child
    i64 r;
    asm volatile(
        "cmp $0, %%rax\n"
        "jg .L_parent\n"
        ".L_child:\n"
        "popq %%rdi\n"
        "call __thread_start\n"
        ".L_parent:\n"
        "movq %%rax, %[ret]\n"
        :[ret] "=r"(r)
        :[sys_exit] "i"(sys_exit)
        :"rdi","rax"
    );

    // the child halted above so we're the parent now
    if (r < 0) {
        // error in parent, do some cleanup
        memory_unmap(priv->mem_base, priv->mem_size);
        priv = 0;
        ret.error = error_nomem;
    } else if (r > 0) {
        // success
        ret.ret.id = (uintptr_t)priv;
    }

    return ret;
}

error_return<void> thread_join(thread& th)
{
    error_return<void> ret;

    thread_priv* priv = (thread_priv*)th.id;
    if (!priv) {
        ret.error = error_invalid_arguments;
        return ret;
    }

    if (thread_self().id == th.id) {
        // deadlock
        ret.error = error_deadlock;
        return ret;
    }

    // we want to be the thread that swaps from not_joined to joined
    thread_state state = thread_state_not_joined;
    while (state == thread_state_not_joined) {
        if (priv->state.compare_exchange_weak(state, thread_state_joined)) break;
    }

    if (state != thread_state_not_joined) {
        // someone else got there first
        ret.error = error_invalid_arguments;
        return ret;
    }

    // wait on the futex until the thread exits
    volatile i32* tidptr = &priv->tid;
    i32 tid = *tidptr;
    while (*tidptr != 0) {
        _sys_futex(tidptr, tid, FUTEX_WAIT);
    }

    // @todo thread cleanup (TL dtors, etc.)

    // thread is done
    memory_unmap(priv->mem_base, priv->mem_size);
    th.id = 0;

    return ret;
}

inline_func thread_priv* _get_thread_self()
{
    thread_priv* priv;
    asm volatile ("movq %%fs:%c1,%0" :"=r"(priv) : "i"(sizeof(void*) * tls_slot_thread));
    return priv;
}

thread thread_self()
{
    thread th;
    th.id = (uintptr_t)_get_thread_self();
    return th;
}

error thread_sleep(nanoseconds ns)
{
    timespec ts;
    ts.sec = ns / u64(1000000000);
    ts.nano = ns % u64(1000000000);

    timespec remain;
    remain.nano = remain.sec = 1;

    i32 err;
    while (remain.nano || remain.sec) {
        err = syscall<i64>(sys_clock_nanosleep, CLOCK_MONOTONIC, 0, &ts, &remain);
        if (err == EINTR) continue;
        break;
    }

    return convert_error(err);
}

unsigned _hardware_concurrency() noexcept
{
    // On linux this info is in /sys/devices/system/cpu/online
    file f = file_open("/sys/devices/system/cpu/online", file_flag_read, file_mode_default);
    if (!f) return 0;

    // @todo need some info on how big this could possibly be...
    char buf[8192];
    unsigned cpus = 0;

    do {
        size_t read = file_read(f, buf, sizeof(buf)).ret;
        if (!read) break;

        // data looks like "0,2,4-7"
        // https://www.mjmwired.net/kernel/Documentation/cputopology.txt

        const char* first = buf;
        const char* last = first + read;

        for (; first != last; ) {
            if (!libc::isdigit(*first)) {
                ++first;
                continue;
            }

            // parse the digit
            unsigned cpu1 = 0;
            auto res = libc::from_chars(first, last, cpu1);
            if (res.ec) break;
            first = res.ptr;

            if (first == last) break;
            if (*first == ',') {
                // we parsed a single cpu entry
                ++cpus;
            } else if (*first == '-') {
                // we're parsing a range
                unsigned cpu2 = 0;
                auto res = libc::from_chars(++first, last, cpu2);
                if (res.ec) break;
                first = res.ptr;

                cpus += (cpu2 - cpu1) + 1;
            } else {
                // invalid
                break;
            }
        }
    } while (1);

    file_close(f);

    return cpus;
}

//
// Thread Local Storage (TLS)
//

error_return<tls_key> thread_key_create(void (*func)(void*)) noexcept
{
    for (unsigned i = 0; i < THREAD_MAX_KEYS; ++i) {
        thread_key& key = key_map[i];
        i32 seq = key.seq;
        if (seq & 0x1) continue;
        if (key.seq.compare_exchange_strong(seq, seq + 1)) {
            // we're the first to use this key
            key.destructor = func;
            return {error_none, tls_key(i)};
        }
    }

    // no keys available
    return error_nomem;
}

error thread_key_delete(tls_key& key) noexcept
{
    if (key.key < 0 || key.key >= THREAD_MAX_KEYS) return error_invalid_arguments;

    // increase sequence number, toggling the in use bit
    thread_key& k = key_map[key.key];
    k.destructor = 0;
    ++k.seq;

    return error_none;
}

error_return<void*> thread_get_specific(const tls_key& key) noexcept
{
    if ((u32)key.key >= THREAD_MAX_KEYS) return error_invalid_arguments;
    i32 seq = key_map[key.key].seq.load(std::memory_order_relaxed);
    if (!(seq & 0x1)) return error_invalid_arguments;

    thread_priv* priv = _get_thread_self();
    thread_data* data = &priv->key_data[key.key];
    if (data->seq == seq) {
        return {error_none, data->data};
    }

    // the key was modified since the data was last set
    data->data = nullptr;
    return error_invalid_arguments;
}

error thread_set_specific(const tls_key& key, const void* param) noexcept
{
    if ((u32)key.key >= THREAD_MAX_KEYS) return error_invalid_arguments;
    i32 seq = key_map[key.key].seq.load(std::memory_order_relaxed);
    if (!(seq & 0x1)) return error_invalid_arguments;

    thread_priv* priv = _get_thread_self();
    auto& data = priv->key_data[key.key];
    data.seq = seq;
    data.data = const_cast<void*>(param);

    return error_none;
}

//
// Locks
//

struct mutex_priv {
    thread owner;
    std::atomic<i32> futex;
    std::atomic<i32> recursive;
    i32 flags;
};

enum mutex_state : i32 {
    mutex_unlocked = 0,
    mutex_locked,
    mutex_locked_contended,
};

inline_func error
_mutex_lock(mutex_priv& priv, bool try_only)
{
    const thread& th = thread_self();

    // check for deadlock
    if (!(priv.flags & mutex_flag_recursive) && th == priv.owner) {
        return error_deadlock;
    }

    // try to take the lock uncontended
    i32 state = mutex_unlocked;
    if (!priv.futex.compare_exchange_strong(state, mutex_locked)) {
        // contended lock

        // if recursive and owned by this thread, we already have the lock
        if ((priv.flags & mutex_flag_recursive) && th == priv.owner) {
            // if overflow, return false if try_lock or error_overflow
            ++priv.recursive;
            return error_none;
        }

        if (try_only) {
            // lock was held
            return error_unheld;
        }

        // now sleep until we can swap the state from unlocked to locked_contended
        while (priv.futex.exchange(mutex_locked_contended,
                                   std::memory_order_acquire) != mutex_unlocked) {
            // slow path
            _sys_futex(priv.futex, mutex_locked_contended, FUTEX_WAIT);
        }
    }

    // track this so we can determine deadlock
    priv.owner.id = th.id;

    return error_none;
}

inline_func error _mutex_unlock(mutex_priv& priv)
{
    const thread& th = thread_self();

    if (th != priv.owner) return error_unheld;

    // handle recursive
    if ((priv.flags & mutex_flag_recursive) && priv.recursive) {
        --priv.recursive;

        // need more unlocks to balance before really unlocking
        return error_none;
    }

    // reset ownership
    priv.owner.id = 0;

    // wake other waiters if the lock was contentded
    if (priv.futex.exchange(mutex_unlocked,
                            std::memory_order_release) == mutex_locked_contended) {
        _sys_futex(priv.futex, 1, FUTEX_WAKE);
    }

    return error_none;
}

mutex::~mutex() { }

bool mutex::set_flags(u32 flags)
{
    if (try_lock()) {
        ((mutex_priv&)priv).flags = flags;
        unlock();
        return true;
    }
    return false;
}

error mutex::lock()
{
    return _mutex_lock((mutex_priv&)priv, false);
}

bool mutex::try_lock()
{
    return _mutex_lock((mutex_priv&)priv, true) == error_none;
}

error mutex::unlock()
{
    return _mutex_unlock((mutex_priv&)priv);
}

struct condition_variable_priv {
    std::atomic<i32> futex;
};

error condition_variable::notify_one() noexcept
{
    condition_variable_priv& p = (condition_variable_priv&)priv;
    p.futex++;
    return convert_error(_sys_futex(p.futex, 1, FUTEX_WAKE));
}

error condition_variable::notify_all() noexcept
{
    condition_variable_priv& p = (condition_variable_priv&)priv;
    p.futex++;
    return convert_error(_sys_futex(p.futex, INT32_MAX, FUTEX_WAKE));
}

error condition_variable::wait(mutex& locked_mutex, nanoseconds dur) noexcept
{
    condition_variable_priv& p = (condition_variable_priv&)priv;

    // add us as a waiter
    i32 f = p.futex.load(std::memory_order_relaxed);

    // unlock + wait
    locked_mutex.unlock();
    _sys_futex(p.futex, f, FUTEX_WAIT);

    // reacquire and wakeup
    return locked_mutex.lock();
}

} // platform

#endif // LINUX64
