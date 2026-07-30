cmake_minimum_required(VERSION 3.16)
project(aes_assignment3 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_library(aeslab STATIC
    src/aes_core.c
    src/aes_ttable.c
    src/aes_shuffle.c
    src/aes_hw.c
    src/aes_dispatch.c
    src/ghash.c
    src/aes_modes.c
)
target_include_directories(aeslab PUBLIC include PRIVATE src)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(aeslab PRIVATE -O3 -Wall -Wextra -Wpedantic)
endif()

add_executable(aes_tests app/test_main.c)
target_link_libraries(aes_tests PRIVATE aeslab)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(aes_tests PRIVATE -O2 -Wall -Wextra -Wpedantic)
endif()

add_executable(aes_bench app/benchmark.c)
target_link_libraries(aes_bench PRIVATE aeslab)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(aes_bench PRIVATE -O3 -Wall -Wextra -Wpedantic)
endif()

enable_testing()
add_test(NAME aes_correctness COMMAND aes_tests)
