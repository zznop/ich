/**
 * utils.c
 *
 * Copyright (C) 2020 zznop, zznop0x90@gmail.com
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "utils.h"

#define LOG_BUF_SIZE (256)

void info(const char *fmt, ...)
{
    va_list ap;
    char buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    fprintf(stdout, "\033[1;34m[*]\033[0m %s\n", buf);
}

void err(const char *fmt, ...)
{
    va_list ap;
    char buf[LOG_BUF_SIZE];

    va_start(ap, fmt);
    vsnprintf(buf, LOG_BUF_SIZE, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\033[1;31m[!]\033[0m %s\n", buf);
}
