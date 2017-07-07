#pragma once
#include <type_traits>
#include <cstdint>
#include <atomic>

namespace platform {

// Basic primitive types, definitions for LP-64
typedef char i8;
typedef unsigned char u8;
typedef short i16;
typedef unsigned short u16;
typedef int i32;
typedef unsigned int u32;
typedef long long i64;
typedef unsigned long long u64;
using std::size_t;
typedef i64 ssize_t;
using std::uintptr_t;

/** Error codes from platform functions */
enum error {
    error_none               = 0,

    error_unimplemented      = 1,   ///< The requested feature has not been implemented
    error_invalid_arguments  = 2,   ///< The arguments were invalid
    error_nomem              = 10,  ///< There was no memory available

    // synchronization
    error_deadlock           = 100, ///< Thread joining on itself or locking held mutex
    error_unheld             = 101, ///< Unheld Mutex unlock

    // paths
    error_path_not_absolute  = 200, ///< An absolute path was expected, but not provided

    // catch all
    error_unknown,
};

template <class Return, class Error>
struct error_data
{
    Return ret;
    Error error = error_none;

    constexpr error_data() = default;
    constexpr error_data(Error e) : error(e) {}
    constexpr error_data(Error e, Return r) : error(e), ret(r) {}

    template <typename U = void,
              typename = typename std::enable_if<std::is_move_constructible<Return>::value ||
                                                 std::is_copy_constructible<Return>::value,U>::type>
    operator Return() const { return ret; }
    template <typename U = void,
              typename = typename std::enable_if<std::is_move_constructible<Return>::value,U>::type>
    operator Return&&() { return (Return&&)ret; }
    void assign(Return r) { ret = r; }
};

template <class Error>
struct error_data<void,Error>
{
    constexpr error_data() = default;
    constexpr error_data(Error e) : error(e) {}
    Error error = error_none;
    void assign(...) {}
};

/** Encapsulates a return value and an error code
 *
 * @code
 * error_return<> ret = my_platform_function();
 * if (!ret) {
 *     [handle error]...
 * }
 */
template <class Return = i64, class Error = i64>
struct error_return : public error_data<Return,Error> {

    constexpr error_return() = default;
    constexpr error_return(Error e) : error_data<Return,Error>(e) {}
    constexpr error_return(Error e, Return r) : error_data<Return,Error>(e, r) {}

    /// Returns true if no error
    explicit operator bool() const { return this->error == error_none; }

    /// Returns true if error
    bool operator!() const { return this->error != error_none; }
};

template <class Error>
struct error_return<void,Error> : public error_data<void,Error> {

    constexpr error_return() = default;
    constexpr error_return(Error e) : error_data<void,Error>(e) {}

    /// Returns true if no error
    explicit operator bool() const { return this->error == error_none; }

    /// Returns true if error
    bool operator!() const { return this->error != error_none; }
};

/** A file handle */
struct file {
    /// An empty file handle
    constexpr file() : fd(static_cast<uintptr_t>(-1)) {}

    /// Create a file handle with an underlying platform representation
    constexpr file(uintptr_t f) : fd(f) {}

    /// Returns true if not empty
    explicit operator bool() const { return ssize_t(fd) >= 0; }

    uintptr_t fd;
};

/** A filesystem path
 *
 * Separator is always '/'. String is utf8, null terminated, and must be absolute.
 */
struct path {
    /// An empty path
    constexpr path() : str(0) {}

    /// Path with absolute utf8 string
    constexpr path(const i8* s) : str(s) {}

    /// Returns true if not empty
    explicit operator bool() const { return str != nullptr; }

    const i8* str;
};

} // platform
