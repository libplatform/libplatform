#include <platform/platform.h>
#include "platform_internal.h"

namespace platform {

#ifdef APPLE64

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

mutex::mutex()
{

}

unsigned _hardware_concurrency() noexcept
{
    return 0;
}

#endif

} // platform
