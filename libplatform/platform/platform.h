#pragma once

#include <platform/types.h>

// liblatform interface
// guarantees:
// 1. MT safe for all routines
// 2. No globals (ie, for errno)
// 3. Requires thread local storage
// 4. Minimal API for accessing OS-dependent resources
// 5. All functionality works identially across platforms (no platform specific
//    functionality, flags, modes, etc.)

/// This is to deny access to internal state externally (by those using
/// libplatform), while allowing access internally (within libplatform)
#ifndef package
#define package protected
#endif

namespace platform {

//
// IO
//

enum file_flags : u32 {
    file_flag_read    = 0x1,
    file_flag_write   = 0x2,
    file_flag_rw      = 0x3,
    file_flag_create  = 0x4,
    file_flag_append  = 0x8,
};

enum file_mode : u32 {
    file_mode_default = 0x1,
};

enum : size_t {
    max_path_length = 1024,
};

constexpr file file_stdin(0);
constexpr file file_stdout(1);
constexpr file file_stderr(2);

/** Open or create a file at path
 *
 * Path must be absolute (begin with /)
 */
error_return<file> file_open(const path& path, u32 flags, u32 mode);

/// Close an open file descriptor. file is invalid upon successful return
error_return<void> file_close(file& fd);

/// Read from an open file
///
/// @param fd[in] The file to write to.
/// @param buffer[in] Pointer to data to write
/// @param size[in] Length of data to write (in bytes)
/// @returns error_none if successful
///          error_invalid_arguments if fd is invalid, or size > 0 and buffer is 0
error_return<ssize_t> file_read(file fd, i8* buffer, size_t size);

/// Write to an open file
error_return<ssize_t> file_write(file fd, const i8* buffer, size_t size);

//
// Memory
//

enum memory_flags_t : u32 {
    memory_flags_read      = 0x1,  ///< Memory may be read
    memory_flags_write     = 0x2,  ///< Memory may be written
    memory_flags_rw        = 0x3,  ///< Memory may be read and written
    memory_flags_execute   = 0x4,  ///< Memory may be executed
    memory_flags_growsdown = 0x8,  ///< Memory grows down (such as a stack)

    memory_flags_shared    = 0x10, ///< Memory may be shared between processes
    memory_flags_private   = 0x20, ///< Memory is private to this process
    memory_flags_anonymous = 0x40, ///< Memory is anonymous (not backed by file)
};

/** Obtain additional process memory
 *
 * This is a kernel allocation and increases available heap; it does not
 * allocate memory on the heap */
error_return<void*> memory_map(const void* addr, size_t size, u32 flags,
                               const file& _file, size_t _off);

/** Return process memory */
error_return<void> memory_unmap(const void* addr, size_t size);

//
// Time
//

typedef u64 nanoseconds;

enum clock_id : u32 {
    clock_id_realtime,
};

error_return<nanoseconds> clock_gettime(clock_id c = clock_id_realtime);

//
// Threads
//

/// thread_id is just an integer
typedef uintptr_t thread_id;

/** A thread handle */
struct thread {
    /// An inactive thread
    constexpr thread() : id(0) {}

#ifdef LIBPLATFORM_INCLUDED_BY_LIBCPP
    constexpr thread(thread_id i) : id(i) {}
#endif

    /// threads are not copyable
    constexpr thread(const thread&) = delete;
    thread& operator=(const thread&) = delete;

    /// but are movable
    constexpr thread(thread&&) = default;
    thread& operator=(thread&&) = default;

    /// Returns true if an active, non-detached thread
    explicit operator bool() const { return id != 0; }

    bool detached() const;

    /// Return true if active and not detached
    bool joinable() const;

    /// Join the thread or return an error if detached or not active
    error join();

    /// Detach the thread or return an error if already detacted, not active,
    /// or an error occurred during detach.
    /// @post thread is not active or error returned
    error detach();

    bool operator==(const thread& th) const { return id == th.id; }
    bool operator!=(const thread& th) const { return id != th.id; }

    thread_id get_id() const { return id; }

package:
    thread_id id;
};

/// Detach a new thread and execute func(param) in it
error_return<thread> thread_create(void *(*func)(void*), void* param, u32 flags);

/// Block until thread @a th returns
error_return<void> thread_join(thread& th);

/// Get the current thread
thread thread_self();

/// Sleep the current thread
error thread_sleep(nanoseconds ns);

/// Yield execution of the current thread
error thread_yield();

/// Number of hardware execution devices available
unsigned hardware_concurrency() noexcept;

//
// Thread Local Storage (TLS)
//

/** A tls key, used to get/set thread-specific data */
class tls_key {
package:
    i32 key;
    tls_key(i32 k) : key(k) {}

public:
    tls_key() : key(-1) {}

    explicit operator bool() const { return key >= 0; }
};

/// Returns a new thread-specific key or an error
error_return<tls_key> thread_key_create(void (*func)(void*)) noexcept;

/// Deletes a thread-specific key. Destructors for data stored by the key
/// are not called.
error thread_key_delete(tls_key& key) noexcept;

/// Get a thread-specific value for the specified key. @returns an error
/// if the key is not valid.
error_return<void*> thread_get_specific(const tls_key& key) noexcept;

/// Set a thread-specific value for the specified key, returning an error
/// if the key isn't valid
error thread_set_specific(const tls_key& key, const void* param) noexcept;

//
// Locks
//

enum mutex_flag : u32 {
    mutex_flag_normal    = 0x0,
    mutex_flag_recursive = 0x1,
};

/** A normal or recursive mutex */
class mutex {
package:
    alignas(sizeof(void*)) u32 priv[5];

public:
    // for std::mutex, this must be constexpr
    constexpr mutex(u32 flags = mutex_flag_normal) noexcept
        : priv{0,0,0,0,flags} {}
    ~mutex();

    // mutexes are non-copyable and non-movable
    mutex(const mutex&) = delete;
    mutex(mutex&&) = delete;
    mutex& operator=(const mutex&) = delete;
    mutex& operator=(mutex&&) = delete;

    /// behavior can be changed after construction, but only if the mutex is not
    /// locked. Attempts to update flags and returns true if they were updated
    /// and false if the mutex was locked.
    bool set_flags(u32 flags);

    error lock();
    bool try_lock();
    error unlock();
};

/** Condition variable */
class condition_variable {
package:
    alignas(sizeof(void*)) u32 priv[2];

public:
    // for std::condition_variable, this must be constexpr
    constexpr condition_variable() noexcept : priv{0,0} {}

    // condition variables are non-copyable and non-movable
    condition_variable(const condition_variable&) = delete;
    condition_variable(condition_variable&&) = delete;
    condition_variable& operator=(const condition_variable&) = delete;
    condition_variable& operator=(condition_variable&&) = delete;

    error notify_one() noexcept;
    error notify_all() noexcept;
    error wait(mutex& locked_mutex, nanoseconds dur = 0) noexcept;
};

} // platform
