/*
 * Copyright (C) 2012 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "platform_internal.h"

extern "C" {

//__attribute__((__section__(".preinit_array")))
//void (*__PREINIT_ARRAY__)(void) = (void (*)(void)) -1;
__attribute__((__section__(".init_array"))) static void (*__INIT_ARRAY__)(void);
__attribute__((__section__(".fini_array"))) static void (*__FINI_ARRAY__)(void);

__attribute__((section (".bss"))) void *__dso_handle = (void *) 0;

// forward declare main
int main(int,char**,char**);

__attribute__((visibility("hidden")))
__attribute__((used)) static void _start_main(void* raw_args) {
    structors_array array;
//    array.preinit_array = &__PREINIT_ARRAY__;
    array.init_array = &__INIT_ARRAY__;
    array.fini_array = &__FINI_ARRAY__;
    _platform_init(raw_args, &main, array);
}

} // extern "C"

#define PRE ".text; .global _start; .type _start,%function; _start:"
#define POST "; .size _start, .-_start"

#if defined(__aarch64__)
__asm__(PRE "mov x0,sp; b _start_main" POST);
#elif defined(__arm__)
__asm__(PRE "mov r0,sp; b _start_main" POST);
#elif defined(__i386__)
__asm__(PRE "movl %esp,%eax; andl $~0xf,%esp; pushl %eax; calll _start_main" POST);
#elif defined(__x86_64__)
__asm__(PRE "movq %rsp,%rdi; andq $~0xf,%rsp; callq _start_main" POST);
#else
#error unsupported architecture
#endif

#undef PRE
#undef POST
