.globl _hook_library
.globl _hook_library_size

_hook_library:
#ifdef DEBUG
    .incbin "./build/debug/libich.so"
#else
    .incbin "./build/release/libich.so"
#endif

_hook_library_size:
   .int _hook_library_size - _hook_library
