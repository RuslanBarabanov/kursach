cmake_minimum_required(VERSION 3.10)
project(ServerApp)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CRYPTOPP REQUIRED libcrypto++)

find_package(Boost REQUIRED COMPONENTS program_options)

add_executable(server
    main.cpp
    server.cpp
)

target_include_directories(server PRIVATE ${CRYPTOPP_INCLUDE_DIRS})
target_link_libraries(server ${CRYPTOPP_LIBRARIES} ${Boost_LIBRARIES} pthread)
