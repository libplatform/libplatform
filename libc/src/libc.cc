#include <c/libc.h>

namespace libc {

} // libc

void* memcpy(void* dst, const void* src, platform::size_t n)
{
    // slowest ever!
    platform::i8* d = (platform::i8*)dst;
    const platform::i8* s = (platform::i8*)src;
    for (platform::size_t i = 0; i < n; ++i) {
        *d++ = *s++;
    }

    return dst;
}
