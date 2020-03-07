Import('env')

# Build the LD_PRELOAD'd library

lib_env_env = env.Clone()
lib_env_env.AppendUnique(
    LIBS = ["dl", "pthread"],
    CPPDEFINES = "_GNU_SOURCE",
)

lib_env = lib_env_env.SharedLibrary(
    'ich.so',
    source=['src/lib/libc_hooks.c',],
)

# Build the harness
harness_env = env.Clone()
harness_env.AppendUnique(
    CPPDEFINES = [
        "_GNU_SOURCE",
    ]
);

incbin_o = env.Object('src/incbin.S')
env.Depends(incbin_o, lib_env)

sources = [
    'src/main.c',
    'src/utils.c',
    incbin_o,
]

ich = harness_env.Program(
    'ich',
    source = sources,
)

Return('ich')
