cmake_minimum_required(VERSION 3.10)

project(FHEConv)

set(CMAKE_CXX_STANDARD 17)

find_package(SEAL 4.1 REQUIRED)

add_executable(FHEConv
    main.cpp
)

target_link_libraries(FHEConv
    SEAL::seal
)
