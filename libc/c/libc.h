#pragma once

#include <type_traits>
#include <platform/platform.h>
#include <limits>

//
// This is a C++ implementation of the C standard library, for use when using C
// features with a C++ compiler.
//

namespace libc {

//
// Types
//

using platform::i8;
using platform::u8;
using platform::i16;
using platform::u16;
using platform::i32;
using platform::u32;
using platform::i64;
using platform::u64;
using platform::size_t;

//
// Data classification
//

inline int isdigit(int ch) { return ch >= '0' && ch <= '9'; }


//
// Number <-> String conversions
//

struct to_chars_result {
    char* ptr;
    int error;
};

enum chars_format : u32 {
    chars_format_scientific = 0x1,
    chars_format_fixed      = 0x2,
    chars_format_hex        = 0x4,
    chars_format_general = chars_format_fixed | chars_format_scientific,
};

template <typename T>
typename std::enable_if<std::is_integral<T>::value,to_chars_result>::type
to_chars(char* first, char* last, T value, int base = 10)
{
    // @todo buf size needs to be larger for base < 10
    // u64 max is 18446744073709551615 = 20 digits
    u8 buf[20];
    u32 i = sizeof(buf)-1;
    do {
        buf[i--] = value % base + '0';
        value /= 10;
    } while (value > 0);

    // negative sign
    if (std::is_signed<T>::value && value < 0) {
        buf[i--] = '-';
    }

    for (; i < sizeof(buf);) {
        *first++ = buf[++i];
        if (first == last) {
            return {last, 1};
        }
    }

    return {first, 0};
}

template <typename T>
typename std::enable_if<std::is_floating_point<T>::value,to_chars_result>::type
to_chars(char* first, char* last, T value, chars_format fmt = chars_format_general, int precision = 6);


struct from_chars_result {
    const char* ptr;
    int ec;
};

template <typename T>
typename std::enable_if<std::is_integral<T>::value,from_chars_result>::type
from_chars(const char* first, const char* last, T& value, int base = 10)
{
    u64 val = 0;

    bool neg = false;
    if (*first == '-') {
        ++first;
        if (std::is_unsigned<T>::value) {
            return {first, 1};
        }
        neg = true;
    }

    do {
        int t = *first - '0';
        if (t < 0 || t >= base) {
            // hit a non-digit
            break;
        }

        val *= base;
        val += t;
        if (val > std::numeric_limits<T>::max()) {
            return {first, 1};
        }
    } while (++first != last);

    if (neg) {
        value = -T(val);
    } else {
        value = T(val);
    }

    return {first, 0};
}

inline size_t strlen(const i8* buffer)
{
    size_t s = 0;
    while (*buffer++ != '\0') { ++s; }
    return s;
}

template <typename T>
typename std::enable_if<std::is_integral<T>::value, size_t>::type
format_number(T num, char* dst, size_t s)
{
    // u64 max is 18446744073709551615 = 20 digits
    u8 buf[30];
    int i = 29;
    buf[i--] = '\0';
    do {
        buf[i--] = num % 10 + '0';
        num /= 10;
    } while (num > 0);
    size_t count = 29 - i;
    for (; i < 30;) {
        *dst++ = buf[++i];
    }
    return count;
}

} // libc

extern "C" {

void* memcpy(void* dst, const void* src, platform::size_t n);

}
