# CompilerFlags.cmake - Compiler configuration for solana-c

# Detect compiler
if(CMAKE_C_COMPILER_ID MATCHES "GNU")
    set(COMPILER_GCC TRUE)
elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(COMPILER_CLANG TRUE)
else()
    message(WARNING "Unknown compiler: ${CMAKE_C_COMPILER_ID}")
endif()

# Base warning flags
set(SOL_WARNING_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Werror=implicit-function-declaration
    -Werror=incompatible-pointer-types
    -Werror=int-conversion
    -Werror=return-type
    -Wformat=2
    -Wformat-security
    -Wnull-dereference
    -Wstack-protector
    -Wstrict-aliasing=2
    -Wundef
    -Wuninitialized
    -Wunused
    -Wvla
    -Wwrite-strings
    -Wcast-align
    -Wcast-qual
    -Wdouble-promotion
    -Wfloat-equal
    -Wpointer-arith
    -Wshadow
    -Wswitch-enum
)

# GCC-specific warnings
if(COMPILER_GCC)
    list(APPEND SOL_WARNING_FLAGS
        -Wlogical-op
        -Wduplicated-cond
        -Wduplicated-branches
        -Wrestrict
    )
endif()

# Clang-specific warnings
if(COMPILER_CLANG)
    list(APPEND SOL_WARNING_FLAGS
        -Wcomma
        -Wloop-analysis
        -Wstring-conversion
        -Wimplicit-fallthrough
    )
endif()

# Security hardening flags
set(SOL_SECURITY_FLAGS
    -fstack-protector-strong
    -fno-delete-null-pointer-checks
    -fno-strict-overflow
)

# Performance flags for release
set(SOL_PERF_FLAGS
    -fno-omit-frame-pointer  # Keep frame pointers for profiling
    -ffunction-sections
    -fdata-sections
)

# x86_64 optimization flags
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(SOL_ARCH_FLAGS
        -march=x86-64-v3      # AVX2, BMI1/2, FMA - good baseline for servers
        -mtune=native
    )
else()
    set(SOL_ARCH_FLAGS "")
endif()

# Expand list to a space-separated string for CMAKE_C_FLAGS_*.
string(JOIN " " SOL_ARCH_FLAGS_STR ${SOL_ARCH_FLAGS})

# Apply flags to all targets
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_compile_definitions(_GNU_SOURCE)
endif()

add_compile_options(${SOL_WARNING_FLAGS})
add_compile_options(${SOL_SECURITY_FLAGS})
add_compile_options(${SOL_PERF_FLAGS})

# Build type specific flags
set(CMAKE_C_FLAGS_DEBUG "-O0 -g3 -DSOL_DEBUG=1")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG ${SOL_ARCH_FLAGS_STR}")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG ${SOL_ARCH_FLAGS_STR}")
set(CMAKE_C_FLAGS_MINSIZEREL "-Os -DNDEBUG")

# Sanitizer builds
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_MSAN "Enable MemorySanitizer" OFF)

if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
    message(STATUS "AddressSanitizer enabled")
endif()

if(ENABLE_UBSAN)
    add_compile_options(-fsanitize=undefined -fno-sanitize-recover=all)
    add_link_options(-fsanitize=undefined)
    message(STATUS "UndefinedBehaviorSanitizer enabled")
endif()

if(ENABLE_TSAN)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
    message(STATUS "ThreadSanitizer enabled")
endif()

if(ENABLE_MSAN)
    add_compile_options(-fsanitize=memory -fno-omit-frame-pointer)
    add_link_options(-fsanitize=memory)
    message(STATUS "MemorySanitizer enabled")
endif()

# Link-time optimization for release builds
include(CheckIPOSupported)
check_ipo_supported(RESULT LTO_SUPPORTED OUTPUT LTO_ERROR)
if(LTO_SUPPORTED)
    option(ENABLE_LTO "Enable Link-Time Optimization" ON)
    if(ENABLE_LTO AND CMAKE_BUILD_TYPE MATCHES "Release|RelWithDebInfo")
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
        message(STATUS "LTO enabled")
    endif()
else()
    message(STATUS "LTO not supported: ${LTO_ERROR}")
endif()

# Linker flags
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_link_options(
        -Wl,--gc-sections      # Remove unused sections
        -Wl,--as-needed        # Only link needed libraries
        -Wl,-z,relro           # Read-only relocations
        -Wl,-z,now             # Full RELRO
        -Wl,-z,noexecstack     # Non-executable stack
    )
endif()
