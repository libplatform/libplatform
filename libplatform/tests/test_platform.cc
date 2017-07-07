#include <platform/platform.h>
#include <c/libc.h>
#include <atomic>

using namespace platform;
using namespace libc;

bool test_files()
{
    path p("/tmp/derp");

    file file = file_open(p, file_flag_write | file_flag_create, file_mode_default);
    if (!file) {
        const char msg[] = "Unable to write to temp file";
        file_write(file_stderr, msg, sizeof(msg) - 1);
        return false;
    } else {
        const char msg[] = "Here's some data in a file!";
        file_write(file, msg, sizeof(msg) - 1);
        file_close(file);

        // then lets try to read it
        char dst[100];
        file = file_open(p, file_flag_read, file_mode_default);
        if (!file) {
            const char msg[] = "Unable to write to temp file";
            file_write(file_stderr, msg, sizeof(msg) - 1);
            return false;
        } else {
            ssize_t len = file_read(file, dst, sizeof(dst));
            file_write(file_stdout, dst, len);
            file_write(file_stdout, "\n", 1);
        }
    }

    return true;
}

bool test_mmap()
{
    size_t size = 1024 * 1024; // 1M
    void* mymemory = memory_map(0, size, memory_flags_rw | memory_flags_anonymous |
                                memory_flags_private, file(), 0);
    if (!mymemory) {
        const char msg[] = "Unable to allocate!";
        file_write(file_stderr, msg, sizeof(msg) - 1);
        return false;
    }

    int* ints = static_cast<int*>(mymemory);
    ints[0] = 50;

    // ensure we can unmap it
    if (!memory_unmap(mymemory, size)) {
        const char msg[] = "Unable to unmap!";
        file_write(file_stderr, msg, sizeof(msg) - 1);
        return false;
    }

    return true;
}

const char tmsg[] = "Hello from a thread!\n";

void* mythread(void* param)
{
    const char* msg = (const char *)param;
    file_write(file_stderr, msg, strlen(msg));
    return 0;
}

bool test_threads()
{
    thread th = thread_create(mythread, (void *)tmsg, 0);
    if (!thread_join(th)) {
        const char msg[] = "Failed to join thread";
        file_write(file_stderr, msg, sizeof(msg) - 1);
    }

    return true;
}

int mut_counter = 0;
mutex mut;

void* mutex_thread(void*)
{
    for (int i = 0; i < 200000; ++i) {
        mut.lock();
        mut_counter++;
        mut.unlock();
    }
    return 0;
}

void test_mutex()
{
    const int tc = 4;
    thread threads[tc];
    for (int i = 0; i < tc; ++i) {
        threads[i] = thread_create(mutex_thread, 0, 0);
    }

    for (int i = 0; i < tc; ++i) {
        thread_join(threads[i]);
    }

    const char msg[] = "Test mutex got: ";
    file_write(file_stderr, msg, sizeof(msg) - 1);

    char buf[100];
    format_number(mut_counter, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = '\n';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));
}

int rec_mut_counter = 0;
mutex rec_mut(mutex_flag_recursive);

void* rec_mutex_thread(void*)
{
    for (int i = 0; i < 200; ++i) {
        rec_mut.lock();
        if (rec_mut.lock()) {
            rec_mut.unlock();
            break;
        }
        rec_mut_counter++;
        rec_mut.unlock();
        rec_mut.unlock();
    }
    return 0;
}

void test_recursive_mutex()
{
    const int tc = 4;
    thread threads[tc];
    for (int i = 0; i < tc; ++i) {
        threads[i] = thread_create(rec_mutex_thread, 0, 0);
    }

    for (int i = 0; i < tc; ++i) {
        thread_join(threads[i]);
    }

    // rec_mut_counter == 800

    char buf[100];
    format_number(rec_mut_counter, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = '\n';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));
}

mutex queue_mutex, queue_mutex2;
condition_variable queue_cond, queue_cond2;
int queue[1024];
unsigned queue_index = 0;
bool stop = false;
int dequeued = 0;
std::atomic_bool dequeue_running(false);

void* dequeue_thread(void*)
{
    while (!stop) {
        queue_mutex.lock();
        dequeue_running = true;
        while (!stop && queue_index == 0) {
            queue_cond.wait(queue_mutex);
        }
        if (stop) {
            queue_mutex.unlock();
            break;
        }

        // fake a dequeue
        if (queue[--queue_index] == 0) {
            dequeued++;
        }

        queue_mutex.unlock();

        queue_mutex2.lock();
        queue_cond2.notify_one();
        queue_mutex2.unlock();
    }

    const char msg[] = "Dequeued should be 1024: ";
    file_write(file_stderr, msg, sizeof(msg) - 1);

    char buf[100];
    format_number(dequeued, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = '\n';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));
    return 0;
}

void test_condition_variable()
{
    thread th = thread_create(dequeue_thread, 0, 0);

    while (!dequeue_running) {}

    int enqueued = 0;
    while (enqueued < 1024) {
        queue_mutex.lock();
        queue[queue_index] = queue_index;
        queue_index++;
        ++enqueued;
        queue_mutex.unlock();
        queue_cond.notify_one();

        queue_mutex2.lock();
        while (queue_index != 0) {
            queue_cond2.wait(queue_mutex2);
        }
        queue_mutex2.unlock();
    }

    stop = true;
    queue_cond.notify_all();

    thread_join(th);
}

void test_time()
{
    nanoseconds ns = clock_gettime();

    const char msg[] = "Current time is: ";
    file_write(file_stderr, msg, sizeof(msg) - 1);

    char buf[100];
    format_number(ns, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = '\n';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));

    nanoseconds start = clock_gettime();

    // sleep for 1ms
    thread_sleep(1000000);

    nanoseconds dur = clock_gettime() - start;

    const char msg2[] = "Slept for : ";
    file_write(file_stderr, msg2, sizeof(msg2) - 1);
    format_number(dur, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = '\n';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));
}

void test_hardware_concurrency()
{
    unsigned cpus = hardware_concurrency();

    char buf[100];
    const char msg2[] = "CPUs should be 8 : ";
    file_write(file_stderr, msg2, sizeof(msg2) - 1);
    format_number(cpus, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = '\n';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));
}

mutex tls_mutex;
condition_variable tls_cond;
std::atomic<i32> tls_counter{0};

void* tls_thread(void* param)
{
    tls_key& k = *(tls_key*)param;

    thread_id self = thread_self().get_id();
    thread_set_specific(k, (void*)self);

    thread_id value = (thread_id)thread_get_specific(k).ret;

    // get all the threads here
    tls_mutex.lock();
    ++tls_counter;
    tls_cond.notify_all();
    while (tls_counter != 4) {
        tls_cond.wait(tls_mutex);
    }
    tls_mutex.unlock();

    value = (thread_id)thread_get_specific(k).ret;

    tls_mutex.lock();
    char buf[100];
    const char msg2[] = "Thread set, got: ";
    file_write(file_stderr, msg2, sizeof(msg2) - 1);
    format_number(self, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = ',';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));
    format_number(value, buf, sizeof(buf));
    file_write(file_stderr, buf, strlen(buf));
    buf[0] = '\n';
    buf[1] = 0;
    file_write(file_stderr, buf, strlen(buf));
    tls_mutex.unlock();
    return 0;
}

void test_tls()
{
    tls_key key = thread_key_create(nullptr);
    thread th[4];
    for (unsigned i = 0; i < 4; ++i) {
        th[i] = thread_create(tls_thread, (void*)&key, 0);
    }

    for (unsigned i = 0; i < 4; ++i) {
        thread_join(th[i]);
    }

    thread_key_delete(key);
}

void* stress_thread(void* param)
{
    for (int i = 0; i < 10000 * (int)(uintptr_t)param; ++i) {
        mut.lock();
        mut_counter++;
        mut.unlock();
    }
    return 0;
}

void thread_stresser()
{
    const int tc = 10;
    thread threads[tc];
    for (int k = 0; k < 10; ++k) {
        for (int i = 0; i < tc; ++i) {
            threads[i] = thread_create(stress_thread, (void*)(uintptr_t)i, 0);
        }
        for (int i = 0; i < tc; ++i) {
            thread_join(threads[i]);
        }
    }
}

int main(int argc, char *argv[], char* envp[])
{
    (void)argc;
    (void)argv;
    (void)envp;

    test_mutex();
    test_files();
    test_mmap();
    test_threads();
    test_recursive_mutex();
    test_condition_variable();
    test_time();
    test_hardware_concurrency();
    test_tls();
    thread_stresser();
    return 5;
}
