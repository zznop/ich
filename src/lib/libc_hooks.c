/**
 * libc_hooks.c
 *
 * Copyright (C) 2020 zznop, zznop0x90@gmail.com
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

////////////////////////////// PREPROCESSOR //////////////////////////////

#define TAG_VAL 0x4943484943484943
#define BUG() __asm__ volatile(".int 0xdeadc0de");
#define FAIL() BUG()

#define info(fmt, ...) {                  \
    if (_printf_real) {                   \
        _printf_real(fmt, ##__VA_ARGS__); \
    }                                     \
}

#define LOAD_SYM(sym, type, name) {         \
    if (!sym) {                             \
        sym = (type)dlsym(RTLD_NEXT, name); \
        if (!sym)                           \
            FAIL();                         \
    }                                       \
}

////////////////////////////// TYPES /////////////////////////////////////

typedef uint64_t tag_t;
typedef void *(*malloc_t)(size_t size);
typedef void *(*calloc_t)(size_t num, size_t size);
typedef void *(*realloc_t)(void *ptr, size_t new_size);
typedef void (*free_t)(void *ptr);
typedef void *(*memcpy_t)(void *destination, const void *source, size_t num);
typedef char *(*strcpy_t)(char *destination, const char *source);
typedef char *(*strncpy_t)(char *dest, const char *src, size_t n);
typedef int (*printf_t)(const char * format, ...);
typedef int (*pthread_mutex_lock_t)(pthread_mutex_t *mutex);
typedef int (*pthread_mutex_unlock_t)(pthread_mutex_t *mutex);
typedef void *(*memset_t)(void *s, int c, size_t n);

struct alloc_info {
    void *base;
    size_t size;
    struct alloc_info* next;
};

////////////////////////////// GLOBALS ///////////////////////////////////

static malloc_t _malloc_real = NULL;
static calloc_t _calloc_real = NULL;
static free_t _free_real = NULL;
static printf_t _printf_real = NULL;
static pthread_mutex_lock_t _pthread_mutex_lock_real = NULL;
static pthread_mutex_unlock_t _pthread_mutex_unlock_real = NULL;

static struct alloc_info *_tagged_allocs = NULL;
static pthread_mutex_t _lock;
static uint8_t _dlsym_tmp_buffer[8192];

////////////////////////// END GLOBALS ///////////////////////////////////

/**
 * Load symbols (if not loaded already)
 */
static void load_symbols()
{
    LOAD_SYM(_malloc_real, malloc_t, "malloc");
    LOAD_SYM(_calloc_real, calloc_t, "calloc");
    LOAD_SYM(_free_real, free_t, "free");
    LOAD_SYM(_printf_real, printf_t, "printf");
    LOAD_SYM(_pthread_mutex_lock_real, pthread_mutex_lock_t, "pthread_mutex_lock");
    LOAD_SYM(_pthread_mutex_unlock_real, pthread_mutex_unlock_t, "pthread_mutex_unlock");
}

/**
 * Library constructor that runs immediately after the shared object is loaded
 */
void __attribute__((constructor)) init(void)
{
    load_symbols();
}

/**
 * Lookup if an allocation is tagged, or not. This is used to determine whether
 * or not we need to fix the allocation base address before free.
 *
 * @param ptr Base of the allocation
 * @return 1 if allocation is tagged, 0 if not
 */
static int is_tagged_allocation(void *ptr)
{
    struct alloc_info *curr;
    curr = _tagged_allocs;
    while (curr != NULL) {
        if (curr->base == ptr)
            return 1;

        curr = curr->next;
    }
    return 0;
}

/**
 * Push a tagged allocation to the end of the linked list
 *
 * @param alloc Allocation information
 */
static void push_alloc(struct alloc_info *alloc)
{
    struct alloc_info *curr;

    _pthread_mutex_lock_real(&_lock);
    if (!_tagged_allocs) {
        _tagged_allocs = alloc;
        goto out;
    }

    curr = _tagged_allocs;
    while (curr->next != NULL)
        curr = curr->next;

    curr->next = alloc;
out:
   _pthread_mutex_unlock_real(&_lock);
}

/**
 * Remove a free'd allocation from the tagged allocation list
 *
 * @param ptr Base address of allocation
 */
static void pop_alloc(void *ptr)
{
    struct alloc_info *curr, *prev;
    _pthread_mutex_lock_real(&_lock);
    curr = _tagged_allocs;
    while (curr != NULL) {
        if (curr->base != ptr)
            goto next;

        /* First alloc in list? */
        if (curr == _tagged_allocs) {
            if (curr->next  != NULL)
                _tagged_allocs = curr->next;
            else
                _tagged_allocs = NULL;

            _free_real(curr);
            break;
        }

        prev->next = curr->next;
        _free_real(curr);
        break;
next:
        prev = curr;
        curr = curr->next;
    }
   _pthread_mutex_unlock_real(&_lock);
}

/**
 * Check if any tags have been modified. If they have, crash the process.
 *
 */
static void check_tagged_allocs(const char *hook)
{
    struct alloc_info *curr;

    _pthread_mutex_lock_real(&_lock);
    curr = _tagged_allocs;
    while (curr != NULL) {
        if ((uint64_t)(*(uint64_t *)curr->base) != TAG_VAL) {
            info("\n-------------------- ICH BUGCHECK --------------------\n")
            info("Bug Type    : Heap Buffer Underflow\n");
            info("Alloc. Base : %llx\n", curr->base - sizeof(TAG_VAL));
            info("Alloc. Size : %u\n\n", curr->size - sizeof(TAG_VAL) * 2);
            info("Filter      : %s\n", hook)
            info("------------------------------------------------------\n\n")
            BUG();
        }

        if ((uint64_t)(*(uint64_t *)(curr->base + curr->size - sizeof(TAG_VAL)) != TAG_VAL)) {
            info("\n-------------------- ICH BUGCHECK --------------------\n")
            info("Bug Type    : Heap Buffer Overflow\n");
            info("Alloc. Base : %llx\n", curr->base - sizeof(TAG_VAL));
            info("Alloc. Size : %u\n", curr->size - sizeof(TAG_VAL) * 2);
            info("Filter      : %s\n", hook)
            info("------------------------------------------------------\n\b")
            BUG();
        }
        curr = curr->next;
    }
   _pthread_mutex_unlock_real(&_lock);
}

/**
 *  libc:strcpy hook for OOB write detection
 */
char *strcpy(char *destination, const char *source)
{
    char *ret;
    strcpy_t strcpy_real = NULL;

    load_symbols();
    LOAD_SYM(strcpy_real, strcpy_t, "strcpy");
    ret = strcpy_real(destination, source);
    check_tagged_allocs("strcpy");
    return ret;
}

/**
 *  libc:strncpy hook for OOB write detection
 */
char *strncpy(char *dest, const char *src, size_t n)
{
    char *ret;
    strncpy_t strncpy_real = NULL;

    load_symbols();
    LOAD_SYM(strncpy_real, strncpy_t, "strncpy");
    ret = strncpy_real(dest, src, n);
    check_tagged_allocs("strncpy");
    return ret;
}

/**
 *  libc:memcpy hook for OOB write detection
 */
void *memcpy (void *destination, const void *source, size_t num)
{
    void *ret;
    memcpy_t memcpy_real = NULL;

    load_symbols();
    LOAD_SYM(memcpy_real, memcpy_t, "memcpy");
    ret = memcpy_real(destination, source, num);
    check_tagged_allocs("memcpy");
    return ret;
}

/**
 * libc:memset hook for OOB write detection
 */
void *memset(void *s, int c, size_t n)
{
    void *ret;
    memset_t memset_real = NULL;

    load_symbols();
    LOAD_SYM(memset_real, memset_t, "memset");
    ret = memset_real(s, c, n);
    check_tagged_allocs("memset");
    return ret;
}

/**
 * libc:free hook for OOB write detection
 */
void free(void *ptr)
{
    load_symbols();
    check_tagged_allocs("free");
    if (!_free_real)
        return;

    if (is_tagged_allocation(ptr - sizeof(tag_t))) {
        ptr = ptr - sizeof(tag_t);
        _free_real(ptr);
        pop_alloc(ptr);
    } else {
        _free_real(ptr);
    }
}

/**
 * libc:calloc hook - tag allocations
 */
void *calloc(size_t num, size_t size)
{
    size_t new_size, i;
    uint8_t *ptr;
    struct alloc_info *alloc;

    if (!_calloc_real) {
        /* Ghetto calloc ¯\_(ツ)_/¯ - Since we load before libc, we need to emulate calloc for the loader */
        for (i = 0 ;i < sizeof(_dlsym_tmp_buffer); i++)
            _dlsym_tmp_buffer[i] = 0;

        return _dlsym_tmp_buffer;
    }

    load_symbols();
    check_tagged_allocs("calloc");

    new_size = num * size + sizeof(tag_t) * 2;
    ptr = _calloc_real(new_size, 1);
    if (!ptr)
        return NULL;

    *(uint64_t *)ptr = TAG_VAL;
    *(uint64_t *)(ptr + new_size - sizeof(tag_t)) = TAG_VAL;

    alloc = _malloc_real(sizeof(*alloc));
    if (!alloc)
        FAIL();

    alloc->base = ptr;
    alloc->size = new_size;
    alloc->next = NULL;
    push_alloc(alloc);
    return ptr + sizeof(tag_t);
}

/**
 * libc:realloc hook
 */
void *realloc(void *ptr, size_t new_size)
{
    struct alloc_info *alloc;
    realloc_t realloc_real = NULL;

    load_symbols();
    check_tagged_allocs("realloc");

    LOAD_SYM(realloc_real, realloc_t, "realloc");
    if (is_tagged_allocation(ptr - sizeof(tag_t))) {
        ptr = ptr - sizeof(tag_t);
        pop_alloc(ptr);
    }

    new_size = new_size + sizeof(tag_t) * 2;
    ptr = realloc_real(ptr, new_size);
    if (!ptr)
        return ptr;

    /* Apply the tags */
    *(uint64_t *)ptr = TAG_VAL;
    *(uint64_t *)(ptr + new_size - sizeof(tag_t)) = TAG_VAL;

    /* Cache the allocation info */
    alloc = _malloc_real(sizeof(*alloc));
    if (!alloc)
        FAIL();

    alloc->base = ptr;
    alloc->size = new_size;
    alloc->next = NULL;
    push_alloc(alloc);
    return ptr + sizeof(tag_t);
}

/**
 * libc:malloc hook - tag allocations
 */
void *malloc(size_t size)
{
    size_t new_size;
    uint8_t *ptr;
    struct alloc_info *alloc;

    load_symbols();
    check_tagged_allocs("malloc");

    new_size = size + sizeof(tag_t) * 2;
    ptr = _malloc_real(new_size);
    if (!ptr)
        return NULL;

    /* Apply the tags */
    *(uint64_t *)ptr = TAG_VAL;
    *(uint64_t *)(ptr + new_size - sizeof(tag_t)) = TAG_VAL;

    /* Cache the allocation info */
    alloc = _malloc_real(sizeof(*alloc));
    if (!alloc)
        FAIL();

    alloc->base = ptr;
    alloc->size = new_size;
    alloc->next = NULL;
    push_alloc(alloc);

    /* Return as if base is after the tag */
    return ptr + sizeof(tag_t);
}
